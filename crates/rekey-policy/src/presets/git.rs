//! The `github-git` smart-HTTP preset: fixed origin, owner and `repo.git`,
//! info/refs and upload-pack as reads, receive-pack as a write.
use rekey_domain::action::{FixedMethod, HeaderName, HttpsOrigin};
use rekey_domain::connection::{MethodSelector, Preset, ReadSemantics, RuleEffect};
use serde_json::json;

use super::{generic_preset, operation, rule};
use crate::PolicyError;

pub(super) fn github_git_preset() -> Result<Preset, PolicyError> {
    let mut preset = generic_preset(
        HttpsOrigin::parse("https://github.com").map_err(|_| PolicyError::Invalid)?,
        "authorization",
        "Basic ",
    )?;
    preset.name = "github-git".into();
    // Git selects protocol v2 with this header; without it the upstream falls
    // back to v0 and advertises every ref instead of the requested prefixes.
    preset
        .allowed_headers
        .insert(HeaderName::new("git-protocol").map_err(|_| PolicyError::Invalid)?);
    let slug =
        json!({"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$","maxLength":100});
    let args = json!({"owner":slug,"repo":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}\\.git$","maxLength":100}});
    preset.operations = vec![
        operation(
            "git.info_refs",
            FixedMethod::Get,
            "/{owner}/{repo}/info/refs",
            args.clone(),
            &["owner", "repo"],
            None,
        ),
        operation(
            "git.upload_pack",
            FixedMethod::Post,
            "/{owner}/{repo}/git-upload-pack",
            args.clone(),
            &["owner", "repo"],
            Some(ReadSemantics::Fixed),
        ),
        operation(
            "git.receive_pack",
            FixedMethod::Post,
            "/{owner}/{repo}/git-receive-pack",
            args,
            &["owner", "repo"],
            None,
        ),
    ];
    preset.rules = preset
        .operations
        .iter()
        .enumerate()
        .map(|(i, op)| {
            rule(
                "github-git",
                i,
                MethodSelector::Methods(vec![op.method]),
                &op.path,
                if op.name == "git.receive_pack" {
                    RuleEffect::Approve
                } else {
                    RuleEffect::Allow
                },
            )
        })
        .collect();
    preset.query_allowlist = Some(["service".to_owned()].into_iter().collect());
    Ok(preset)
}

pub(crate) fn validate_git_connection(
    connection: &rekey_domain::connection::Connection,
) -> Result<(), PolicyError> {
    if connection.preset != "github-git" {
        return Ok(());
    }
    let preset = github_git_preset()?;
    if connection.origin != preset.origin
        || connection.auth != preset.auth.into()
        || connection.operations != preset.operations
        || ["owner", "repo"].iter().any(|key| {
            connection.bindings.get(*key).is_none_or(|values| {
                values.is_empty()
                    || values
                        .iter()
                        .any(|value| value == "*" || *key == "repo" && !value.ends_with(".git"))
            })
        })
    {
        return Err(PolicyError::Invalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn git_protocol_is_the_only_header_beyond_the_generic_pair() {
        let preset = super::github_git_preset().unwrap();
        let names: Vec<_> = preset.allowed_headers.iter().map(|n| n.as_str()).collect();
        assert_eq!(names, ["accept", "content-type", "git-protocol"]);
        assert!(preset.fixed_headers.is_empty());
    }
}
