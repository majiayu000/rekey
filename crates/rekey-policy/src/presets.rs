//! Provider declarations inherited from the binary or an authenticated package.
use std::collections::{BTreeMap, BTreeSet};

use crate::PolicyError;
use rekey_domain::action::{
    FixedMethod, HeaderCredentialUse, HeaderName, HeaderPrefix, HttpsOrigin,
};
use rekey_domain::connection::{
    ConnectionRule, MethodClass, MethodSelector, Preset, PresetOperation, ReadSemantics, RuleEffect,
};
use rekey_domain::ids::PolicyRuleId;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn rule(
    preset: &str,
    index: usize,
    methods: MethodSelector,
    path: &str,
    effect: RuleEffect,
) -> ConnectionRule {
    let mut hash = Sha256::new();
    hash.update(b"RKPRES RULE\0\x01");
    hash.update(preset.as_bytes());
    hash.update((index as u64).to_be_bytes());
    let hash = hash.finalize();
    let mut id = [0; 16];
    id.copy_from_slice(&hash[..16]);
    ConnectionRule {
        id: PolicyRuleId::from_random_bytes(id),
        methods,
        path: path.to_owned(),
        effect,
    }
}
fn operation(
    name: &str,
    method: FixedMethod,
    path: &str,
    properties: Value,
    required: &[&str],
    read_semantics: Option<ReadSemantics>,
) -> PresetOperation {
    PresetOperation {
        name: name.to_owned(),
        description: format!(
            "{} {}. This tool never returns secrets.",
            method.as_str(),
            path
        ),
        method,
        path: path.to_owned(),
        parameters: json!({"type":"object","properties":properties,"required":required,"additionalProperties":false}),
        read_semantics,
    }
}
fn names(values: &[&str]) -> Result<BTreeSet<HeaderName>, PolicyError> {
    values
        .iter()
        .map(|v| HeaderName::new(v).map_err(|_| PolicyError::Invalid))
        .collect()
}

pub fn builtin_preset(name: &str) -> Result<Preset, PolicyError> {
    if name == "github-git" {
        return github_git_preset();
    }
    if oauth_provider(name).is_some() {
        return oauth_preset(name);
    }
    let (origin, header, prefix) = match name {
        "anthropic" => ("https://api.anthropic.com", "x-api-key", ""),
        "glm" => ("https://open.bigmodel.cn", "x-api-key", ""),
        "openai" => ("https://api.openai.com", "authorization", "Bearer "),
        "glm-responses" => ("https://open.bigmodel.cn", "authorization", "Bearer "),
        "github-pat" => ("https://api.github.com", "authorization", "Bearer "),
        _ => return Err(PolicyError::NotConfigured),
    };
    let mut preset = generic_preset(
        HttpsOrigin::parse(origin).map_err(|_| PolicyError::Invalid)?,
        header,
        prefix,
    )?;
    preset.name = name.to_owned();
    preset.rules = vec![
        rule(
            name,
            0,
            MethodSelector::Class(MethodClass::Read),
            "/**",
            RuleEffect::Allow,
        ),
        rule(
            name,
            1,
            MethodSelector::Class(MethodClass::Write),
            "/**",
            RuleEffect::Approve,
        ),
    ];
    let slug =
        json!({"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$","maxLength":100});
    let n = json!({"type":"integer","minimum":1,"maximum":9007199254740991u64});
    match name {
        "github-pat" => {
            preset
                .allowed_headers
                .remove(&HeaderName::new("accept").map_err(|_| PolicyError::Invalid)?);
            preset.fixed_headers.insert(
                HeaderName::new("accept").map_err(|_| PolicyError::Invalid)?,
                "application/vnd.github+json".into(),
            );
            preset.fixed_headers.insert(
                HeaderName::new("x-github-api-version").map_err(|_| PolicyError::Invalid)?,
                "2022-11-28".into(),
            );
            preset.rules.push(rule(
                name,
                2,
                MethodSelector::Methods(vec![FixedMethod::Delete]),
                "/repos/*/*",
                RuleEffect::Deny,
            ));
            preset.rules.push(rule(
                name,
                3,
                MethodSelector::Class(MethodClass::Write),
                "/orgs/**",
                RuleEffect::Deny,
            ));
            preset.rules.push(rule(
                name,
                4,
                MethodSelector::Class(MethodClass::Write),
                "/user/orgs/**",
                RuleEffect::Deny,
            ));
            preset.operations = vec![
                operation(
                    "github.get_issue",
                    FixedMethod::Get,
                    "/repos/{owner}/{repo}/issues/{number}",
                    json!({"owner":slug,"repo":slug,"number":n}),
                    &["owner", "repo", "number"],
                    None,
                ),
                operation(
                    "github.list_issues",
                    FixedMethod::Get,
                    "/repos/{owner}/{repo}/issues",
                    json!({"owner":slug,"repo":slug}),
                    &["owner", "repo"],
                    None,
                ),
                operation(
                    "github.create_issue",
                    FixedMethod::Post,
                    "/repos/{owner}/{repo}/issues",
                    json!({"owner":slug,"repo":slug,"title":{"type":"string","minLength":1,"maxLength":256},"body":{"type":"string"},"labels":{"type":"array","items":{"type":"string"}}}),
                    &["owner", "repo", "title"],
                    None,
                ),
                operation(
                    "github.create_comment",
                    FixedMethod::Post,
                    "/repos/{owner}/{repo}/issues/{number}/comments",
                    json!({"owner":slug,"repo":slug,"number":n,"body":{"type":"string","minLength":1}}),
                    &["owner", "repo", "number", "body"],
                    None,
                ),
                operation(
                    "github.merge_pull",
                    FixedMethod::Put,
                    "/repos/{owner}/{repo}/pulls/{number}/merge",
                    json!({"owner":slug,"repo":slug,"number":n,"merge_method":{"type":"string","enum":["merge","squash","rebase"]}}),
                    &["owner", "repo", "number"],
                    None,
                ),
                operation(
                    "github.graphql",
                    FixedMethod::Post,
                    "/graphql",
                    json!({"query":{"type":"string"},"variables":{"type":"object"},"operationName":{"type":"string"}}),
                    &["query"],
                    Some(ReadSemantics::GraphqlQuery),
                ),
            ];
            preset.query_allowlist = Some(
                [
                    "state",
                    "labels",
                    "sort",
                    "direction",
                    "since",
                    "per_page",
                    "page",
                ]
                .map(str::to_owned)
                .into_iter()
                .collect(),
            );
        }
        "anthropic" | "glm" => {
            preset.fixed_headers.insert(
                HeaderName::new("anthropic-version").map_err(|_| PolicyError::Invalid)?,
                "2023-06-01".into(),
            );
            preset.query_allowlist = Some(["beta".into()].into_iter().collect());
            let base = if name == "glm" {
                "/api/anthropic/v1"
            } else {
                "/v1"
            };
            let properties = json!({"model":{"type":"string"},"messages":{"type":"array"},"max_tokens":{"type":"integer","minimum":1},"stream":{"type":"boolean"},"system":{"type":"string"},"tools":{"type":"array"},"temperature":{"type":"number"}});
            preset.operations = vec![operation(
                &format!("{name}.messages"),
                FixedMethod::Post,
                &format!("{base}/messages"),
                properties.clone(),
                &[],
                Some(ReadSemantics::Fixed),
            )];
            if name == "anthropic" {
                preset.operations.push(operation(
                    "anthropic.count_tokens",
                    FixedMethod::Post,
                    "/v1/messages/count_tokens",
                    properties,
                    &[],
                    Some(ReadSemantics::Fixed),
                ));
                preset.operations.push(operation(
                    "anthropic.models",
                    FixedMethod::Get,
                    "/v1/models",
                    json!({}),
                    &[],
                    None,
                ));
            }
        }
        "openai" => {
            let properties = json!({"model":{"type":"string"},"messages":{"type":"array"},"input":{},"max_tokens":{"type":"integer","minimum":1},"max_completion_tokens":{"type":"integer","minimum":1},"max_output_tokens":{"type":"integer","minimum":1},"stream":{"type":"boolean"},"tools":{"type":"array"},"temperature":{"type":"number"},"instructions":{"type":"string"},"n":{"type":"integer"}});
            preset.operations = vec![
                operation(
                    "openai.responses",
                    FixedMethod::Post,
                    "/v1/responses",
                    properties.clone(),
                    &[],
                    Some(ReadSemantics::Fixed),
                ),
                operation(
                    "openai.chat",
                    FixedMethod::Post,
                    "/v1/chat/completions",
                    properties.clone(),
                    &[],
                    Some(ReadSemantics::Fixed),
                ),
                operation(
                    "openai.embeddings",
                    FixedMethod::Post,
                    "/v1/embeddings",
                    properties,
                    &[],
                    Some(ReadSemantics::Fixed),
                ),
                operation(
                    "openai.models",
                    FixedMethod::Get,
                    "/v1/models",
                    json!({}),
                    &[],
                    None,
                ),
            ];
        }
        "glm-responses" => {
            preset.operations = vec![operation(
                "glm.responses",
                FixedMethod::Post,
                "/api/v1/responses",
                json!({"model":{"type":"string"},"input":{},"max_output_tokens":{"type":"integer","minimum":1},"stream":{"type":"boolean"},"tools":{"type":"array"},"instructions":{"type":"string"}}),
                &[],
                Some(ReadSemantics::Fixed),
            )];
        }
        _ => {}
    }
    Ok(preset)
}

fn github_git_preset() -> Result<Preset, PolicyError> {
    let mut preset = generic_preset(
        HttpsOrigin::parse("https://github.com").map_err(|_| PolicyError::Invalid)?,
        "authorization",
        "Basic ",
    )?;
    preset.name = "github-git".into();
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

pub fn oauth_provider(preset: &str) -> Option<rekey_domain::connection::OAuthProvider> {
    use rekey_domain::connection::OAuthProvider;
    match preset {
        "google-drive" | "google-gmail" | "google-calendar" => Some(OAuthProvider::Google),
        "github-oauth" => Some(OAuthProvider::GitHub),
        "slack" => Some(OAuthProvider::Slack),
        "notion" => Some(OAuthProvider::Notion),
        _ => None,
    }
}

/// Exact operation requirements, not a generic HTTP read/write scope guess.
/// Notion returns Developer Portal capability names, never OAuth scope params.
pub fn oauth_required_scopes(
    preset: &str,
    operation: &str,
) -> Result<BTreeSet<String>, PolicyError> {
    let scopes: &[&str] = match (preset, operation) {
        ("google-drive", "drive.list_files" | "drive.get_file") => {
            &["https://www.googleapis.com/auth/drive.readonly"]
        }
        ("google-drive", "drive.create_file" | "drive.update_file") => {
            &["https://www.googleapis.com/auth/drive.file"]
        }
        ("google-gmail", "gmail.list_messages" | "gmail.get_message") => {
            &["https://www.googleapis.com/auth/gmail.readonly"]
        }
        ("google-gmail", "gmail.send_message") => &["https://www.googleapis.com/auth/gmail.send"],
        ("google-calendar", "calendar.list_events" | "calendar.get_event") => {
            &["https://www.googleapis.com/auth/calendar.events.owned.readonly"]
        }
        ("google-calendar", "calendar.create_event" | "calendar.update_event") => {
            &["https://www.googleapis.com/auth/calendar.events.owned"]
        }
        // OAuth App repo is also write-capable upstream. Local rules provide
        // the read-only ceiling; it is not a private-repository read-only token.
        (
            "github-oauth",
            "github.get_issue"
            | "github.list_issues"
            | "github.create_issue"
            | "github.create_comment"
            | "github.merge_pull",
        ) => &["repo"],
        ("slack", "slack.list_channels") => &["channels:read"],
        ("slack", "slack.history") => &["channels:history"],
        ("slack", "slack.post_message") => &["chat:write"],
        ("notion", "notion.search" | "notion.get_page" | "notion.get_children") => {
            &["read_content"]
        }
        ("notion", "notion.create_page") => &["insert_content"],
        ("notion", "notion.update_page") => &["update_content"],
        _ => return Err(PolicyError::NotConfigured),
    };
    Ok(scopes.iter().map(|s| (*s).to_owned()).collect())
}

fn oauth_preset(name: &str) -> Result<Preset, PolicyError> {
    if name == "github-oauth" {
        let mut preset = builtin_preset("github-pat")?;
        preset.name = name.into();
        preset.operations.retain(|op| op.name != "github.graphql");
        annotate_oauth_operations(&mut preset)?;
        return Ok(preset);
    }
    let origin = match name {
        "google-drive" | "google-calendar" => "https://www.googleapis.com",
        "google-gmail" => "https://gmail.googleapis.com",
        "slack" => "https://slack.com",
        "notion" => "https://api.notion.com",
        _ => return Err(PolicyError::NotConfigured),
    };
    let mut preset = generic_preset(
        HttpsOrigin::parse(origin).map_err(|_| PolicyError::Invalid)?,
        "authorization",
        "Bearer ",
    )?;
    preset.name = name.into();
    let slug =
        json!({"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$","maxLength":100});
    preset.operations = match name {
        "google-drive" => vec![
            operation(
                "drive.list_files",
                FixedMethod::Get,
                "/drive/v3/files",
                json!({}),
                &[],
                None,
            ),
            operation(
                "drive.get_file",
                FixedMethod::Get,
                "/drive/v3/files/{file_id}",
                json!({"file_id":slug}),
                &["file_id"],
                None,
            ),
            operation(
                "drive.create_file",
                FixedMethod::Post,
                "/drive/v3/files",
                json!({"name":{"type":"string"},"mimeType":{"type":"string"},"parents":{"type":"array","items":{"type":"string"}}}),
                &["name"],
                None,
            ),
            operation(
                "drive.update_file",
                FixedMethod::Patch,
                "/drive/v3/files/{file_id}",
                json!({"file_id":slug,"name":{"type":"string"},"description":{"type":"string"}}),
                &["file_id"],
                None,
            ),
        ],
        "google-gmail" => vec![
            operation(
                "gmail.list_messages",
                FixedMethod::Get,
                "/gmail/v1/users/me/messages",
                json!({}),
                &[],
                None,
            ),
            operation(
                "gmail.get_message",
                FixedMethod::Get,
                "/gmail/v1/users/me/messages/{message_id}",
                json!({"message_id":slug}),
                &["message_id"],
                None,
            ),
            operation(
                "gmail.send_message",
                FixedMethod::Post,
                "/gmail/v1/users/me/messages/send",
                json!({"raw":{"type":"string"},"threadId":{"type":"string"}}),
                &["raw"],
                None,
            ),
        ],
        // The primary keyword avoids percent/email calendar IDs; only the
        // authenticated user's owned calendar is included in this preset.
        "google-calendar" => vec![
            operation(
                "calendar.list_events",
                FixedMethod::Get,
                "/calendar/v3/calendars/primary/events",
                json!({}),
                &[],
                None,
            ),
            operation(
                "calendar.get_event",
                FixedMethod::Get,
                "/calendar/v3/calendars/primary/events/{event_id}",
                json!({"event_id":slug}),
                &["event_id"],
                None,
            ),
            operation(
                "calendar.create_event",
                FixedMethod::Post,
                "/calendar/v3/calendars/primary/events",
                json!({"summary":{"type":"string"},"start":{"type":"object"},"end":{"type":"object"},"description":{"type":"string"}}),
                &["start", "end"],
                None,
            ),
            operation(
                "calendar.update_event",
                FixedMethod::Patch,
                "/calendar/v3/calendars/primary/events/{event_id}",
                json!({"event_id":slug,"summary":{"type":"string"},"start":{"type":"object"},"end":{"type":"object"},"description":{"type":"string"}}),
                &["event_id"],
                None,
            ),
        ],
        "slack" => vec![
            operation(
                "slack.list_channels",
                FixedMethod::Get,
                "/api/conversations.list",
                json!({}),
                &[],
                None,
            ),
            operation(
                "slack.history",
                FixedMethod::Get,
                "/api/conversations.history",
                json!({}),
                &[],
                None,
            ),
            operation(
                "slack.post_message",
                FixedMethod::Post,
                "/api/chat.postMessage",
                json!({"channel":slug,"text":{"type":"string"},"thread_ts":{"type":"string"}}),
                &["channel", "text"],
                None,
            ),
        ],
        "notion" => vec![
            operation(
                "notion.search",
                FixedMethod::Post,
                "/v1/search",
                json!({"query":{"type":"string"},"filter":{"type":"object"},"sort":{"type":"object"},"page_size":{"type":"integer","minimum":1,"maximum":100},"start_cursor":{"type":"string"}}),
                &[],
                Some(ReadSemantics::Fixed),
            ),
            operation(
                "notion.get_page",
                FixedMethod::Get,
                "/v1/pages/{page_id}",
                json!({"page_id":slug}),
                &["page_id"],
                None,
            ),
            operation(
                "notion.get_children",
                FixedMethod::Get,
                "/v1/blocks/{block_id}/children",
                json!({"block_id":slug}),
                &["block_id"],
                None,
            ),
            operation(
                "notion.create_page",
                FixedMethod::Post,
                "/v1/pages",
                json!({"parent":{"type":"object"},"properties":{"type":"object"},"children":{"type":"array"}}),
                &["parent", "properties"],
                None,
            ),
            operation(
                "notion.update_page",
                FixedMethod::Patch,
                "/v1/pages/{page_id}",
                json!({"page_id":slug,"properties":{"type":"object"},"archived":{"type":"boolean"}}),
                &["page_id", "properties"],
                None,
            ),
        ],
        _ => unreachable!(),
    };
    // Finite operation paths provide default authorization; placeholder rule
    // segments are wildcards, while operation parameters retain slug validation.
    preset.rules = preset
        .operations
        .iter()
        .enumerate()
        .map(|(i, op)| {
            let path = format!(
                "/{}",
                op.path[1..]
                    .split('/')
                    .map(|s| if s.starts_with('{') { "*" } else { s })
                    .collect::<Vec<_>>()
                    .join("/")
            );
            rule(
                name,
                i,
                MethodSelector::Methods(vec![op.method]),
                &path,
                if matches!(op.method, FixedMethod::Get | FixedMethod::Head)
                    || op.read_semantics.is_some()
                {
                    RuleEffect::Allow
                } else {
                    RuleEffect::Approve
                },
            )
        })
        .collect();
    let query: &[&str] = match name {
        "google-drive" => &["q", "pageSize", "pageToken", "fields", "alt", "orderBy"],
        "google-gmail" => &["q", "maxResults", "pageToken", "format"],
        "google-calendar" => &[
            "timeMin",
            "timeMax",
            "maxResults",
            "pageToken",
            "singleEvents",
            "orderBy",
        ],
        "slack" => &[
            "channel",
            "cursor",
            "limit",
            "oldest",
            "latest",
            "inclusive",
            "types",
        ],
        "notion" => &["page_size", "start_cursor"],
        _ => &[],
    };
    preset.query_allowlist = Some(query.iter().map(|s| (*s).to_owned()).collect());
    if name == "notion" {
        preset.fixed_headers.insert(
            HeaderName::new("notion-version").map_err(|_| PolicyError::Invalid)?,
            "2026-03-11".into(),
        );
    }
    annotate_oauth_operations(&mut preset)?;
    Ok(preset)
}

fn annotate_oauth_operations(preset: &mut Preset) -> Result<(), PolicyError> {
    for operation in &mut preset.operations {
        // Public schema annotation lets clients display the same compile-time
        // scope contract without maintaining a second permission mapping.
        operation.parameters["x-rekey-oauth-scopes"] =
            serde_json::json!(oauth_required_scopes(&preset.name, &operation.name)?);
    }
    Ok(())
}

pub(crate) fn validate_oauth_connection(
    connection: &rekey_domain::connection::Connection,
) -> Result<(), PolicyError> {
    let Some(binding) = &connection.oauth else {
        return if oauth_provider(&connection.preset).is_some() {
            Err(PolicyError::Invalid)
        } else {
            Ok(())
        };
    };
    if oauth_provider(&connection.preset) != Some(binding.provider) {
        return Err(PolicyError::Invalid);
    }
    let preset = builtin_preset(&connection.preset)?;
    if connection.origin != preset.origin
        || connection.auth != preset.auth.into()
        || connection
            .operations
            .iter()
            .any(|op| !preset.operations.contains(op))
    {
        return Err(PolicyError::Invalid);
    }
    let mut allowed = BTreeSet::new();
    for op in &preset.operations {
        allowed.extend(oauth_required_scopes(&connection.preset, &op.name)?);
    }
    if connection.preset == "github-oauth" {
        allowed.insert("offline_access".into());
    }
    if !binding.scopes.is_subset(&allowed) {
        return Err(PolicyError::Invalid);
    }
    Ok(())
}

/// Arbitrary API connections begin with approval for both classes.
pub fn generic_preset(
    origin: HttpsOrigin,
    header: &str,
    prefix: &str,
) -> Result<Preset, PolicyError> {
    let name = if header == "authorization" {
        "generic-bearer"
    } else {
        "generic-header"
    };
    Ok(Preset {
        name: name.to_owned(),
        origin,
        auth: HeaderCredentialUse::new(
            HeaderName::new(header).map_err(|_| PolicyError::Invalid)?,
            HeaderPrefix::new(prefix).map_err(|_| PolicyError::Invalid)?,
        )
        .map_err(|_| PolicyError::Invalid)?,
        rules: vec![
            rule(
                name,
                0,
                MethodSelector::Class(MethodClass::Read),
                "/**",
                RuleEffect::Approve,
            ),
            rule(
                name,
                1,
                MethodSelector::Class(MethodClass::Write),
                "/**",
                RuleEffect::Approve,
            ),
        ],
        allowed_headers: names(&["content-type", "accept"])?,
        fixed_headers: BTreeMap::new(),
        allowed_response_headers: names(&["content-type", "x-request-id", "retry-after"])?,
        query_allowlist: None,
        operations: Vec::new(),
    })
}

/// RKTEMPLATE packages now carry one Preset; signatures bind every rule and
/// operation parameter declaration. No external schema/resource retrieval.
pub fn parse_and_verify_preset_package(
    bytes: &[u8],
    trust: &crate::ValidatedPolicyTrust,
) -> Result<Preset, PolicyError> {
    use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
    use data_encoding::BASE64URL_NOPAD;
    use rekey_domain::authorization::PolicyTrustAlgorithm;
    use rekey_domain::ids::{CredentialId, PolicySignerId};
    use serde::Deserialize;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Package {
        format_version: u32,
        signer_id: PolicySignerId,
        preset: Preset,
        signature: String,
    }
    if bytes.len() > crate::SNAPSHOT_MAX_BYTES {
        return Err(PolicyError::TooLarge);
    }
    let mut value = crate::json::parse_unique_json(bytes)?;
    let package: Package =
        serde_json::from_value(value.clone()).map_err(|_| PolicyError::Malformed)?;
    if package.format_version != 2 {
        return Err(PolicyError::UnsupportedFormat);
    }
    if package.signer_id != trust.signer_id()
        || trust.key().algorithm() != PolicyTrustAlgorithm::Ed25519
    {
        return Err(PolicyError::InvalidSignature);
    }
    let signature = BASE64URL_NOPAD
        .decode(package.signature.as_bytes())
        .map_err(|_| PolicyError::InvalidSignature)?;
    if signature.len() != 64 || BASE64URL_NOPAD.encode(&signature) != package.signature {
        return Err(PolicyError::InvalidSignature);
    }
    value
        .as_object_mut()
        .ok_or(PolicyError::Malformed)?
        .remove("signature");
    let mut message = crate::templates::TEMPLATE_SIGN_PREFIX.to_vec();
    message.extend(serde_jcs::to_vec(&value).map_err(|_| PolicyError::Malformed)?);
    UnparsedPublicKey::new(&ED25519, trust.public_key())
        .verify(&message, &signature)
        .map_err(|_| PolicyError::InvalidSignature)?;
    let connection = package.preset.connection(
        "validation".into(),
        CredentialId::from_random_bytes([1; 16]),
    );
    // LLM model selections belong to the user's Connection, outside the package.
    let mut validation = connection;
    if matches!(
        validation.preset.as_str(),
        "anthropic" | "glm" | "openai" | "glm-responses"
    ) {
        validation.llm = Some(rekey_domain::connection::ConnectionLlmLimits {
            models: ["model".into()].into_iter().collect(),
            max_tokens: 1,
            max_requests_per_day: 1,
            max_output_tokens_per_day: 1,
        });
    }
    validation.validate().map_err(|_| PolicyError::Invalid)?;
    for operation in &package.preset.operations {
        crate::reject_remote_refs(&operation.parameters)?;
        jsonschema::options()
            .build(&operation.parameters)
            .map_err(|_| PolicyError::Invalid)?;
    }
    Ok(package.preset)
}
