//! One-use Profile control connection. EOF and OS owner death are independent.
use tokio::io::AsyncReadExt;

use super::*;
use crate::ipc::owner::PeerProcess;

pub(super) async fn handle_control(
    stream: UnixStream,
    frame: IncomingFrame,
    ctx: Arc<BrokerCtx>,
    mut shutdown: watch::Receiver<bool>,
) {
    let request_id = frame.header.request_id;
    let mut owner = match PeerProcess::from_peer(&stream) {
        Ok(owner) if owner.uid() == crate::ipc::peer::current_uid() => owner,
        Ok(_) => return,
        Err(error) => {
            let error = if error.kind() == std::io::ErrorKind::Unsupported {
                BrokerError::UnsupportedPlatform
            } else {
                BrokerError::Io(error)
            };
            let mut stream = stream;
            let _ = write_admin_error(
                &mut stream,
                admin_msg::PROFILE_SESSION_CREATE,
                request_id,
                &error,
            )
            .await;
            return;
        }
    };
    let (mut reader, mut writer) = stream.into_split();
    let mut unexpected = [0u8; 1];
    let create = async {
        let deadline = admin_mutation_deadline();
        #[cfg(feature = "lab")]
        let (frame, admission) = prepare_admin_frame(&frame, &ctx, deadline).await?;
        #[cfg(not(feature = "lab"))]
        if frame.body.starts_with(b"RKAU") {
            return Err(BrokerError::Frame(ipc::FrameError::InvalidField));
        }
        let request: ipc::ProfileNameMeta = meta(&frame)?;
        ctx.profile_create_until(
            &request.profile,
            &frame.body,
            #[cfg(feature = "lab")]
            admission.as_ref(),
            deadline,
        )
        .await
    };
    let created = tokio::select! {
        biased;
        _ = owner.wait_exit() => return,
        _ = reader.read(&mut unexpected) => return,
        _ = shutdown.changed() => return,
        created = create => created,
    };
    let (body, guard) = match created {
        Ok(created) => created,
        Err(error) => {
            let message = error.to_string();
            tokio::select! {
                biased;
                _ = owner.wait_exit() => {},
                _ = reader.read(&mut unexpected) => {},
                _ = shutdown.changed() => {},
                _ = write_error(&mut writer, Channel::Admin, request_id, error.code(), &message, error.retryable()) => {},
            }
            return;
        }
    };
    let session_id = guard.session_id();
    let wrote = tokio::select! {
        biased;
        _ = owner.wait_exit() => false,
        _ = reader.read(&mut unexpected) => false,
        _ = shutdown.changed() => false,
        _ = ctx.sessions.wait_revoked(session_id) => false,
        result = write_ok(&mut writer, Channel::Admin, request_id, b"{}", &body) => result.is_ok(),
    };
    drop(body);
    if wrote {
        tokio::select! {
            biased;
            _ = owner.wait_exit() => {},
            _ = reader.read(&mut unexpected) => {},
            _ = shutdown.changed() => {},
            _ = ctx.sessions.wait_revoked(session_id) => {},
        }
    }
    // Never wait for audit/coordinator before closing admission for this token.
    drop(guard);
    drop(writer);
    drop(reader);
    if let Err(error) = authority_until(
        admin_mutation_deadline(),
        ctx.authority
            .commit_audit(crate::runtime::profile::session_audit(
                rekey_vault::model::event_type::SESSION_REVOKED,
                session_id,
            )),
    )
    .await
    {
        tracing::debug!(event = "profile.revoke_audit_failed", code = error.code());
        ctx.request_fault();
    }
}
