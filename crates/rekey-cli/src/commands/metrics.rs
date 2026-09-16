use super::*;
use std::fmt::Write as _;

pub fn metrics(state_dir: &Path, prometheus: bool) -> Result<(), CliError> {
    let (metadata, body) = admin(state_dir)?.call(admin_msg::METRICS, b"{}", &[])?;
    if !body.is_empty() {
        return Err(CliError::local(
            "INVALID_FRAME",
            "unexpected metrics response body",
        ));
    }
    if !prometheus {
        return print_json::<ipc::MetricsResponse>(&metadata);
    }
    let snapshot: ipc::MetricsResponse = serde_json::from_slice(&metadata)
        .map_err(|_| CliError::local("INVALID_FRAME", "invalid metrics snapshot"))?;
    std::io::stdout()
        .write_all(render(&snapshot).as_bytes())
        .map_err(|error| CliError::local("OUTPUT_FAILED", format!("cannot write metrics: {error}")))
}

fn render(snapshot: &ipc::MetricsResponse) -> String {
    let mut text = String::new();
    let channels = [("admin", &snapshot.admin), ("agent", &snapshot.agent)];
    // Names and labels come only from this fixed schema, never from the broker.
    for (name, help, kind, admin, agent, backup) in [
        (
            "requests_total",
            "Complete requests entering dispatch.",
            "counter",
            snapshot.admin.dispatch.requests_total,
            snapshot.agent.dispatch.requests_total,
            snapshot.backup.requests_total,
        ),
        (
            "finished_total",
            "Dispatches finished including cancellation.",
            "counter",
            snapshot.admin.dispatch.finished_total,
            snapshot.agent.dispatch.finished_total,
            snapshot.backup.finished_total,
        ),
        (
            "errors_total",
            "Dispatches returning an error.",
            "counter",
            snapshot.admin.dispatch.errors_total,
            snapshot.agent.dispatch.errors_total,
            snapshot.backup.errors_total,
        ),
        (
            "cancelled_total",
            "Dispatches cancelled before returning.",
            "counter",
            snapshot.admin.dispatch.cancelled_total,
            snapshot.agent.dispatch.cancelled_total,
            snapshot.backup.cancelled_total,
        ),
        (
            "requests_in_flight",
            "Dispatches currently in flight.",
            "gauge",
            snapshot.admin.dispatch.requests_in_flight,
            snapshot.agent.dispatch.requests_in_flight,
            snapshot.backup.requests_in_flight,
        ),
    ] {
        writeln!(
            text,
            "# HELP rekey_{name} {help}\n# TYPE rekey_{name} {kind}"
        )
        .unwrap();
        writeln!(
            text,
            "rekey_{name}{{channel=\"admin\"}} {admin}\nrekey_{name}{{channel=\"agent\"}} {agent}"
        )
        .unwrap();
        writeln!(text, "# HELP rekey_backup_{name} Backup {help}\n# TYPE rekey_backup_{name} {kind}\nrekey_backup_{name} {backup}").unwrap();
    }
    for (name, help, admin, agent) in [
        (
            "peer_rejections_total",
            "Connections rejected by peer identity.",
            snapshot.admin.peer_rejections_total,
            snapshot.agent.peer_rejections_total,
        ),
        (
            "capacity_rejections_total",
            "Connections rejected for exhausted request capacity.",
            snapshot.admin.capacity_rejections_total,
            snapshot.agent.capacity_rejections_total,
        ),
        (
            "frame_read_failures_total",
            "Failed frame reads excluding EOF.",
            snapshot.admin.frame_read_failures_total,
            snapshot.agent.frame_read_failures_total,
        ),
    ] {
        writeln!(text, "# HELP rekey_{name} {help}\n# TYPE rekey_{name} counter\nrekey_{name}{{channel=\"admin\"}} {admin}\nrekey_{name}{{channel=\"agent\"}} {agent}").unwrap();
    }
    writeln!(text, "# HELP rekey_dispatch_duration_seconds Dispatch duration including cancellation, excluding response writes.\n# TYPE rekey_dispatch_duration_seconds summary").unwrap();
    for (channel, metrics) in channels {
        duration(
            &mut text,
            "rekey_dispatch_duration_seconds",
            &format!("{{channel=\"{channel}\"}}"),
            &metrics.dispatch,
        );
    }
    writeln!(text, "# HELP rekey_backup_duration_seconds Backup dispatch duration including cancellation.\n# TYPE rekey_backup_duration_seconds summary").unwrap();
    duration(
        &mut text,
        "rekey_backup_duration_seconds",
        "",
        &snapshot.backup,
    );
    for (name, help, kind, value) in [
        (
            "fault_signals_total",
            "Fault shutdown signals, not confirmed fault transitions.",
            "counter",
            snapshot.fault_signals_total,
        ),
        (
            "capabilities_active",
            "Unrevoked unexpired unexhausted capabilities.",
            "gauge",
            u64::from(snapshot.capabilities_active),
        ),
        (
            "executions_in_flight",
            "Capability execution permits currently held.",
            "gauge",
            u64::from(snapshot.executions_in_flight),
        ),
    ] {
        writeln!(
            text,
            "# HELP rekey_{name} {help}\n# TYPE rekey_{name} {kind}\nrekey_{name} {value}"
        )
        .unwrap();
    }
    text
}

fn duration(text: &mut String, name: &str, labels: &str, metrics: &ipc::DispatchMetrics) {
    let micros = metrics.duration_micros_total;
    writeln!(
        text,
        "{name}_count{labels} {}\n{name}_sum{labels} {}.{:06}",
        metrics.finished_total,
        micros / 1_000_000,
        micros % 1_000_000
    )
    .unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prometheus_uses_fixed_names_labels_and_integer_duration_conversion() {
        let mut snapshot = ipc::MetricsResponse::default();
        snapshot.agent.dispatch.requests_total = 7;
        snapshot.agent.dispatch.finished_total = 6;
        snapshot.agent.dispatch.duration_micros_total = 1_000_001;
        let text = render(&snapshot);
        assert!(text.contains("rekey_requests_total{channel=\"agent\"} 7\n"));
        assert!(text.contains("rekey_dispatch_duration_seconds_count{channel=\"agent\"} 6\n"));
        assert!(text.contains("rekey_dispatch_duration_seconds_sum{channel=\"agent\"} 1.000001\n"));
        assert!(text.contains("# TYPE rekey_fault_signals_total counter\n"));
        assert!(text.contains("# TYPE rekey_capabilities_active gauge\n"));
        let samples: Vec<_> = text.lines().filter(|line| !line.starts_with('#')).collect();
        assert_eq!(samples.len(), 30);
        for line in samples {
            assert!(
                line.split_whitespace()
                    .last()
                    .unwrap()
                    .parse::<f64>()
                    .unwrap()
                    .is_finite()
            );
        }
    }
}
