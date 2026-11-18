use super::*;

fn query() -> AuditQuery {
    AuditQuery {
        request_id: None,
        session_id: None,
        action_id: None,
        credential_id: None,
        outcome: None,
        since_ms: None,
        until_ms: None,
        snapshot_max_sequence: None,
        before_sequence: None,
        limit: 2,
    }
}

fn record(sequence: u64) -> AuditRecord {
    AuditRecord {
        record_type: AUDIT_SCHEMA_V2.to_owned(),
        sequence,
        event_id: format!("{sequence:032x}"),
        request_id: None,
        session_id: None,
        action_id: None,
        action_version: None,
        credential_id: None,
        credential_version: None,
        principal_id: None,
        policy_version: None,
        policy_digest_hex: None,
        policy_rule_id: None,
        approval_request_id: None,
        approval_id: None,
        approver_id: None,
        usage: None,
        request_context: None,
        event_type: "test.event".to_owned(),
        outcome: "success".to_owned(),
        reason_code: "test".to_owned(),
        upstream_status: None,
        latency_ms: None,
        created_at_ms: sequence as i64,
    }
}

#[test]
fn connection_activity_pages_require_action_evidence_only_for_execution() {
    let mut event = record(1);
    event.request_context = Some(
        crate::connection::ConnectionRequestAuditContext {
            connection: "example".into(),
            caller: "unknown".into(),
            method_class: crate::connection::MethodClass::Read,
            normalized_path: "/".into(),
            rule_id: None,
        }
        .into(),
    );
    for event_type in [
        "access_request.created",
        "scan.performed",
        "oauth.authorized",
        "execution.started",
        "execution.finished",
        "call.dry_run",
    ] {
        event.event_type = event_type.into();
        let page = AuditPage {
            schema: AUDIT_SCHEMA_V2.into(),
            snapshot_max_sequence: 1,
            events: vec![event.clone()],
            next_before_sequence: None,
        };
        let parsed: AuditPage =
            serde_json::from_slice(&serde_json::to_vec(&page).unwrap()).unwrap();
        let needs_action = event_type.starts_with("execution.") || event_type == "call.dry_run";
        assert_eq!(
            parsed.validate_for(&query()).is_err(),
            needs_action,
            "{event_type}"
        );
        if needs_action {
            let mut evidenced = parsed;
            evidenced.events[0].action_id = Some(ActionId::new_random());
            evidenced.events[0].action_version = Some(1);
            assert!(evidenced.validate_for(&query()).is_ok());
        }
    }
}

#[test]
fn derived_activity_requires_real_expiry_and_valid_signed_target() {
    let mut event = record(1);
    event.event_type = "credential.derived_issued".into();
    let context = DerivedRequestAuditContext {
        connection: "eks-dev".into(),
        caller: "codex".into(),
        target: crate::connection::DerivedCredentialTarget::KubernetesEks {
            cluster_id: "test-cluster".into(),
            region: "us-east-1".into(),
        },
        expires_at_ms: Some(900001),
    };
    event.request_context = Some(context.clone().into());
    let page = AuditPage {
        schema: AUDIT_SCHEMA_V2.into(),
        snapshot_max_sequence: 1,
        events: vec![event],
        next_before_sequence: None,
    };
    let mut parsed: AuditPage =
        serde_json::from_slice(&serde_json::to_vec(&page).unwrap()).unwrap();
    parsed.validate_for(&query()).unwrap();
    for expiry in [None, Some(0), Some(1)] {
        let mut bad = context.clone();
        bad.expires_at_ms = expiry;
        parsed.events[0].request_context = Some(bad.into());
        assert!(parsed.validate_for(&query()).is_err());
    }
    let mut pending = context;
    pending.expires_at_ms = None;
    parsed.events[0].event_type = "credential.derived_pending".into();
    parsed.events[0].request_context = Some(pending.clone().into());
    parsed.validate_for(&query()).unwrap();
    parsed.events[0].event_type = "execution.started".into();
    assert!(parsed.validate_for(&query()).is_err());
    pending.target = crate::connection::DerivedCredentialTarget::KubernetesEks {
        cluster_id: "../other".into(),
        region: "us-east-1".into(),
    };
    assert!(RequestAuditContext::from(pending).validate().is_err());
}

fn local_page(event_type: &str, approved: bool) -> AuditPage {
    let mut event = record(1);
    event.event_type = event_type.into();
    event.reason_code = "local-presence".into();
    let request = RequestId::new_random();
    event.request_id = Some(request);
    event.session_id = Some(SessionId::from_random_bytes(*request.as_bytes()));
    event.action_id = Some(ActionId::new_random());
    event.action_version = Some(1);
    event.principal_id = Some(PrincipalId::new_random());
    event.policy_version = Some(1);
    event.policy_digest_hex = Some("01".repeat(32));
    event.policy_rule_id = Some(PolicyRuleId::new_random());
    event.approval_request_id = Some(ApprovalRequestId::new_random());
    event.approval_id = approved.then(ApprovalId::new_random);
    AuditPage {
        schema: AUDIT_SCHEMA_V2.into(),
        snapshot_max_sequence: 1,
        events: vec![event],
        next_before_sequence: None,
    }
}

#[test]
fn local_presence_approved_audit_page_is_valid() {
    local_page("approval.approved", true)
        .validate_for(&query())
        .unwrap();
}

#[test]
fn local_presence_accepted_audit_page_is_valid() {
    local_page("approval.accepted", true)
        .validate_for(&query())
        .unwrap();
}

#[test]
fn local_presence_requested_and_window_audit_pages_preserve_native_evidence() {
    local_page("approval.requested", false)
        .validate_for(&query())
        .unwrap();
    assert!(
        local_page("approval.requested", true)
            .validate_for(&query())
            .is_err()
    );
    let mut window = local_page("approval.accepted", true);
    window.events[0].reason_code = "local-presence-window".into();
    window.validate_for(&query()).unwrap();
    for event_type in [
        "approval.requested",
        "approval.approved",
        "approval.rejected",
        "execution.finished",
    ] {
        let mut invalid = window.clone();
        invalid.events[0].event_type = event_type.into();
        assert!(invalid.validate_for(&query()).is_err(), "{event_type}");
    }
    let mut granted = local_page("approval.window_granted", true);
    granted.events[0].reason_code = "seconds-60".into();
    granted.validate_for(&query()).unwrap();
    for reason in [
        "local-presence",
        "local-presence-window",
        "seconds-0",
        "seconds-28801",
        "seconds-forever",
    ] {
        let mut invalid = granted.clone();
        invalid.events[0].reason_code = reason.into();
        assert!(invalid.validate_for(&query()).is_err(), "{reason}");
    }
    let requested = local_page("approval.requested", false);
    for valid in [requested, window, granted] {
        assert_native_evidence_is_required(&valid);
    }
}

/// Each local decision keeps its request, rule and approval identifiers.
fn assert_native_evidence_is_required(valid: &AuditPage) {
    for change in 0..9 {
        let mut invalid = valid.clone();
        let event = &mut invalid.events[0];
        match change {
            0 => event.request_id = None,
            1 => event.session_id = None,
            2 => event.action_id = None,
            3 => event.action_version = None,
            4 => event.approval_request_id = None,
            5 => event.policy_rule_id = None,
            6 => event.approver_id = Some(ApproverId::new_random()),
            7 => event.outcome = "failure".into(),
            8 => {
                event.approval_id = if event.approval_id.is_some() {
                    None
                } else {
                    Some(ApprovalId::new_random())
                }
            }
            _ => unreachable!(),
        }
        assert!(invalid.validate_for(&query()).is_err(), "{change}");
    }
}

/// Basic mode approves or rejects with the vault password. The Authority
/// writes those decisions with reason `local-password`; `rekey audit list`
/// must accept them with the same evidence as a presence decision.
#[test]
fn local_password_decisions_from_basic_mode_are_valid() {
    let password = |event_type: &str, approved: bool| {
        let mut page = local_page(event_type, approved);
        page.events[0].reason_code = "local-password".into();
        page
    };
    for valid in [
        password("approval.approved", true),
        password("approval.rejected", false),
    ] {
        valid.validate_for(&query()).unwrap();
        assert_native_evidence_is_required(&valid);
    }
    // Only decisions carry the password reason; requests, accepted retries
    // and window grants keep their own reasons.
    for (event_type, approved) in [
        ("approval.requested", false),
        ("approval.accepted", true),
        ("approval.window_granted", true),
        ("execution.finished", false),
    ] {
        let invalid = password(event_type, approved);
        assert!(invalid.validate_for(&query()).is_err(), "{event_type}");
    }
}

#[test]
fn local_audit_shapes_do_not_relax_external_approvers_or_other_events() {
    local_page("approval.rejected", false)
        .validate_for(&query())
        .unwrap();
    for (kind, approved) in [
        ("approval.approved", false),
        ("approval.accepted", false),
        ("approval.rejected", true),
        ("execution.finished", true),
    ] {
        assert!(local_page(kind, approved).validate_for(&query()).is_err());
    }
    let valid = local_page("approval.accepted", true);
    for change in 0..6 {
        let mut page = valid.clone();
        let event = &mut page.events[0];
        match change {
            0 => event.reason_code = "accepted".into(),
            1 => event.approver_id = Some(ApproverId::new_random()),
            2 => event.outcome = "failure".into(),
            3 => event.approval_request_id = None,
            4 => event.session_id = None,
            5 => event.policy_rule_id = None,
            _ => unreachable!(),
        }
        assert!(page.validate_for(&query()).is_err());
    }
    let mut external = valid;
    external.events[0].reason_code = "accepted".into();
    external.events[0].approver_id = Some(ApproverId::new_random());
    external.validate_for(&query()).unwrap();
}

#[test]
fn profile_audit_context_roundtrip_rejects_unknown_fields_and_invalid_dimensions() {
    let context = ProfileRequestAuditContext {
        profile_name: "writer".into(),
        policy_sha256: "ab".repeat(32),
        instance_slug: "provider".into(),
        capability: "messages".into(),
        model: Some("allowed".into()),
    };
    let value = serde_json::to_value(&context).unwrap();
    let decoded: ProfileRequestAuditContext = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(decoded, context);
    decoded.validate().unwrap();
    let mut extra = value;
    extra["prompt"] = serde_json::json!("not metadata");
    assert!(serde_json::from_value::<ProfileRequestAuditContext>(extra).is_err());
    for field in 0..5 {
        let mut bad = context.clone();
        match field {
            0 => bad.profile_name = "../writer".into(),
            1 => bad.policy_sha256 = "AB".repeat(32),
            2 => bad.instance_slug = "_hidden".into(),
            3 => bad.capability = "../target".into(),
            4 => bad.model = Some("allowed\n".into()),
            _ => unreachable!(),
        }
        assert!(bad.validate().is_err());
    }
}

#[test]
fn query_rejects_invalid_bounds() {
    let mut value = query();
    value.limit = 0;
    assert!(value.validate().is_err());
    value.limit = 1;
    value.since_ms = Some(2);
    value.until_ms = Some(1);
    assert!(value.validate().is_err());
    value.since_ms = None;
    value.until_ms = None;
    value.before_sequence = Some(0);
    assert!(value.validate().is_err());
    value.before_sequence = Some(2);
    value.snapshot_max_sequence = Some(1);
    assert!(value.validate().is_err());
}

#[test]
fn page_rejects_order_cursor_and_filter_violations() {
    let value = query();
    let valid = AuditPage {
        schema: AUDIT_SCHEMA_V2.to_owned(),
        snapshot_max_sequence: 3,
        events: vec![record(3), record(2)],
        next_before_sequence: Some(2),
    };
    assert!(valid.validate_for(&value).is_ok());

    let mut bad = valid.clone();
    bad.events.swap(0, 1);
    assert!(bad.validate_for(&value).is_err());

    let mut filtered = value;
    filtered.outcome = Some("denied".to_owned());
    assert!(valid.validate_for(&filtered).is_err());
    let empty_scan_window = AuditPage {
        schema: AUDIT_SCHEMA_V2.to_owned(),
        snapshot_max_sequence: 3,
        events: Vec::new(),
        next_before_sequence: Some(2),
    };
    assert!(empty_scan_window.validate_for(&filtered).is_ok());

    let mut malformed = valid;
    malformed.events[0].event_id = "ABC".to_owned();
    assert!(malformed.validate_for(&query()).is_err());
}

#[test]
fn approval_events_require_complete_authorization_evidence() {
    for event_type in [
        "approval.requested",
        "approval.accepted",
        "approval.rejected",
    ] {
        let mut event = record(1);
        event.event_type = event_type.to_owned();
        event.approval_request_id = Some(ApprovalRequestId::new_random());
        if event_type == "approval.accepted" {
            event.approval_id = Some(ApprovalId::new_random());
            event.approver_id = Some(ApproverId::new_random());
        }
        let page = AuditPage {
            schema: AUDIT_SCHEMA_V2.to_owned(),
            snapshot_max_sequence: 1,
            events: vec![event],
            next_before_sequence: None,
        };
        assert!(page.validate_for(&query()).is_err());
    }
}

#[test]
fn rejected_approval_identifiers_are_complete_or_absent() {
    let mut event = record(1);
    event.event_type = "approval.rejected".to_owned();
    event.principal_id = Some(PrincipalId::new_random());
    event.policy_version = Some(1);
    event.policy_digest_hex = Some("00".repeat(32));
    event.policy_rule_id = Some(PolicyRuleId::new_random());
    event.approval_request_id = Some(ApprovalRequestId::new_random());
    let mut page = AuditPage {
        schema: AUDIT_SCHEMA_V2.to_owned(),
        snapshot_max_sequence: 1,
        events: vec![event],
        next_before_sequence: None,
    };
    assert!(page.validate_for(&query()).is_err());
    page.events[0].approval_id = Some(ApprovalId::new_random());
    page.events[0].approver_id = Some(ApproverId::new_random());
    assert!(page.validate_for(&query()).is_ok());
}
