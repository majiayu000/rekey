# P-10: Linux GNU delegated cgroup-v2 plugin containment

Status: selected implementation contract before source edits; actual kernel acceptance pending. This replaces the Linux AS-only and enumerated descendant cleanup portions of the existing GitHub reference-plugin spec. The registered GNU artifact and existing fixed protocols/effect boundary remain unchanged. macOS remains on its documented weaker backend; this increment does not close its physical-memory/startup gap.

## Minimal implementation

Add only one private `github_issue_plugin/linux_cgroup.rs` module. Change the existing Linux launch/guardian/tree and their tests plus the existing cross-platform call site. No dependencies, Domain/IPC/format changes, configurable limits, path/env switches, alternate runner or compatibility fallback. Root owns this specification, baselines and one fixed systemd delegation example. Registered Linux artifacts require the new containment; missing prerequisites fail closed.

The parent locates its current cgroup2 delegated domain using `/proc/self/cgroup` and mountinfo, binds the directory by no-follow FDs, rejects the global root and requires a dedicated nonroot UID-owned subtree whose only process is this Broker. Initialization is serialized before `pre_exec`. Create a control leaf, move the whole Broker there, enable delegated memory at the owned root; cache its pinned identity for subsequent actions. Never modify an arbitrary system cgroup, infer a parent from a later control membership or repair an unowned delegation.

Each execution has one unique payload leaf, configured and read back as `memory.max=67108864`, `memory.swap.max=0`, `memory.oom.group=1`. Pre-open membership, kill and events FDs. Only bwrap and its descendants enter payload; Broker and the existing execed guardian remain in control. Preserve CPU1/2s, AS64MiB, CORE0, NOFILE128, namespaces, fixed loader/rootfs, seccomp and 256KiB IO. All manager FDs are closed/CLOEXEC before payload execution, and cgroup interfaces are not mounted into its rootfs.

## Startup, cancellation and original deadline

Prepare the containment guard before spawn. Existing private guardian protocol receives pinned payload kill/events and parent/launcher identity. Before bwrap may fork/exec, guardian must be armed and alive and launcher must have joined payload. A temporary parent-death signal and identity recheck protects the launcher before guardian arming; it cannot replace the guardian after descendants may exist. `setsid` failure must not produce a successful ACK. Monitor ACK lifetime/EOF, not just one byte from an exited guardian.

Middle waitpid, exec ACK, membership and final gate share the original monotonic execution deadline; use bounded poll and WNOHANG, recomputing remaining budget after EINTR. No blocking indefinite startup handshake. Missing/invalid ACK, guardian death, parent death, cancellation or deadline triggers `cgroup.kill`, not a snapshot of PIDs. Guardian survives Broker SIGKILL and owns the same kill responsibility. No new watchdog platform.

Normal success also kills/drains the payload and confirms `populated=0` before releasing plugin success. Failed/expired cleanup cannot return cached success; leave nonempty kernel leaf to the guardian rather than claiming deletion. Drop triggers kill/guardian closure without indefinite wait. Preserve typed Io/Denied errors and existing native-plugin-rejected/GitHub failure paths; admitted remote effects, audit faults, indeterminate and lease cleanup responsibility remain unchanged. No automatic retry.

## Evidence and limits

The kernel memory limit controls cgroup charged memory/OOM, can temporarily overshoot, and is not a strict sum-of-RSS bound. Moving an already-created process does not transfer all past charge. The trusted fork/pre_exec and shared-cache prior charges remain outside the claim. A birth-time CLONE_INTO_CGROUP shim is not selected; do not claim it. Guardian termination is bounded by OS scheduling and interruptible kernel behavior, not synchronous parent/child death.

Pure host tests cover exact mount/cgroup identity parsing, ambiguity/escape, missing controller/readback, ACK failure/EOF, original deadline and cleanup prohibiting success. Temporary files do not prove cgroup kernel semantics. Linux-target compile is a separate gate from actual Linux runtime; tests requiring delegation/bwrap must explicitly fail or remain unexecuted, never skip into PASS.

Actual kernel acceptance requires a dedicated nonroot GNU Linux VM with cgroup-v2 memory delegation/cgroup.kill and bwrap/userns. Record kernel/systemd/bwrap/arch and positive real artifact/Broker protocols. Test aggregate charge using safe bounded multiple trusted startup allocations with an unlimited successful control, OOM/group events/populated drain; payload seccomp fork remains denied. Inject parent/launcher death at fork, guardian exec/ACK, membership, bwrap initialization/raw_clone and READY phases, observe leaf emptiness/reaping/zero late effects. Missing delegation, read-only/wrong owner, bad limit readback, guardian failure, repeated cancellation, elapsed deadline and cleanup error must reject without exchange. User deferred real environments; these gates remain open until actually run.

References: https://docs.kernel.org/admin-guide/cgroup-v2.html and https://systemd.io/CGROUP_DELEGATION/ . No host delegation is installed or changed by implementing source.
