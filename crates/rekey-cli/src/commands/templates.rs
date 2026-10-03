use rekey_domain::ipc::ProofKind;
use std::path::Path;

use rekey_domain::ipc::{self, admin_msg};
use zeroize::Zeroizing;

use super::{admin, print_json, read_regular_file_bounded, read_step_up, stdin_lines};
use crate::client::CliError;

fn package_bytes(path: Option<&Path>) -> Result<Zeroizing<Vec<u8>>, CliError> {
    match path {
        Some(path) => read_regular_file_bounded(
            path,
            ipc::ADMIN_SECRET_FIELD_MAX_BYTES as usize,
            "template package",
        ),
        None => Ok(Zeroizing::new(Vec::new())),
    }
}

pub fn template_catalog(
    state_dir: &Path,
    builtin: Option<ipc::TemplateSource>,
    file: Option<&Path>,
    stdin_request: bool,
    package: Option<&Path>,
) -> Result<(), CliError> {
    let input = match (builtin, file, stdin_request) {
        (Some(source), None, false) => ipc::TemplateCatalogMeta { source },
        (None, Some(file), false) => {
            let bytes = read_regular_file_bounded(
                file,
                ipc::METADATA_MAX_BYTES as usize,
                "template request",
            )?;
            serde_json::from_slice(&bytes)
                .map_err(|_| CliError::local("USAGE", "invalid template catalog request"))?
        }
        (None, None, true) => serde_json::from_slice(&stdin_lines(1)?[0])
            .map_err(|_| CliError::local("USAGE", "invalid template catalog request"))?,
        _ => {
            return Err(CliError::local(
                "USAGE",
                "choose a built-in template, a request file or a stdin request",
            ));
        }
    };
    let metadata = serde_json::to_vec(&input)
        .map_err(|_| CliError::local("USAGE", "cannot encode template request"))?;
    let package = package_bytes(package)?;
    let (metadata, _) = admin(state_dir)?.call(admin_msg::TEMPLATE_CATALOG, &metadata, &package)?;
    print_json::<ipc::TemplateCatalogResponse>(&metadata)
}

pub fn template_install(
    state_dir: &Path,
    file: Option<&Path>,
    stdin_request: bool,
    package: Option<&Path>,
    kind: ProofKind,
    password_stdin: bool,
) -> Result<(), CliError> {
    let (metadata, stdin_proof) = match (file, stdin_request) {
        (Some(file), false) => (
            read_regular_file_bounded(
                file,
                ipc::METADATA_MAX_BYTES as usize,
                "template install request",
            )?,
            None,
        ),
        (None, true) if password_stdin => {
            let mut lines = stdin_lines(2)?.into_iter();
            let proof = lines.next().expect("exact line count validated");
            let metadata = lines.next().expect("exact line count validated");
            (metadata, Some(proof))
        }
        _ => {
            return Err(CliError::local(
                "USAGE",
                "choose a request file or --stdin-request --password-stdin",
            ));
        }
    };
    serde_json::from_slice::<ipc::TemplateInstallMeta>(&metadata)
        .map_err(|_| CliError::local("USAGE", "invalid template install request"))?;
    let package = package_bytes(package)?;
    let proof = match stdin_proof {
        Some(proof) => proof,
        None => read_step_up(kind, password_stdin)?,
    };
    let mut body = Zeroizing::new(Vec::new());
    ipc::encode_proof_and_secret_body(kind, &proof, &package, &mut body);
    let (metadata, _) = admin(state_dir)?.call(admin_msg::TEMPLATE_INSTALL, &metadata, &body)?;
    print_json::<ipc::TemplateInstallResponse>(&metadata)
}
