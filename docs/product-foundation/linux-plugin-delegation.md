# Linux reference-plugin delegation

This fixed deployment example supports the selected cgroup-v2 backend. It has not been installed or tested on this macOS host. Native plugins fail closed unless the required delegation and kernel interfaces are present.

Use a dedicated existing nonroot `rekey` account and privately initialized `/var/lib/rekey` state. The registered Linux GNU artifact requires its documented bwrap/user-namespace/loader prerequisites. Administrator-managed trusted files and directories must contain `/opt/rekey/bin/rekeyd` and the plugin artifact. The service starts locked; unlock remains an existing Admin operation.

```ini
[Unit]
Description=Rekey Credential Authority with delegated plugin containment
After=local-fs.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=rekey
ExecStart=/opt/rekey/bin/rekeyd serve --state-dir /var/lib/rekey
Delegate=memory
UMask=0077
NoNewPrivileges=true
KillMode=control-group
KillSignal=SIGTERM
TimeoutStopSec=130s
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Only this Broker initially occupies its delegated domain. Do not add auxiliary ExecStartPost/ExecReload/ExecStop commands or DelegateSubgroup to this example. The implementation moves the Broker into its own control leaf before enabling memory for payload leaves. Do not point it at the global cgroup root or manually move other services into its subtree. Keep the cgroup filesystem writable to the delegated account; ProtectControlGroups and a read-only cgroup mount defeat the backend prerequisites.

`Delegate=memory` requests delegation; it does not prove controller availability. Verify the actual kernel, systemd and bwrap versions, unified cgroup-v2 membership, directory ownership, delegated memory controller and cgroup.kill support on the target GNU Linux VM. A generated unit or successful service startup alone does not prove descendant cleanup, charged-memory enforcement or the reference artifact's strict protocol.

Run the actual kernel acceptance cases from [the containment contract](../superpowers/specs/2026-10-01-linux-plugin-cgroup.md): real artifact success, memory/OOM evidence, kill/drain on success and failure, interrupted guardian/startup, parent death and repeated cancellation. Record the real outcomes and leaf population; missing facilities remain failures or unexecuted gates.

Source guidance: [systemd delegation](https://systemd.io/CGROUP_DELEGATION/) explains exclusive subtree ownership, User ownership and controller requests; [kernel cgroup-v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html) defines the enforcement interfaces. This file supplies a reviewable example only and does not deploy, create users or alter host delegation.

## CI delegation

The Linux security gate gives each plugin test executable a separate transient
systemd service under the runner UID/GID with `Delegate=memory`. Cargo itself
stays outside that delegated root. The P6 example uses the same Cargo runner
entry explicitly, since the shell starts that example directly. Cancellation
terminates and reaps the privileged client process group before stopping the
named service; target failure status is preserved. The AppArmor rule and all
production cgroup guards remain required.

Generated-shell checks cover routing, arguments, stdin, exit status and two
late-start cancellation windows with synthetic systemd clients. Those checks do
not establish actual root-UID, delegated-controller, OOM or kernel acceptance;
the required hosted Linux gate must still execute.
