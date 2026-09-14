# APR-09 local approval inbox

This slice adds one G1 notification entry: a local Admin CLI inbox of unused
in-memory approval challenges. It is not a GUI, push-notification service,
hosted inbox, personnel directory, or Agent-callable approval socket.
Existing `rekey-approval-sign` review/sign and Broker grant verification remain
the only authorization path.

Topology matches APR-08: same-user personal CLI. The operator polls
`rekey approval pending` from a trusted terminal, fetches the origin-signed
envelope with `rekey approval get`, then reviews/signs/executes as today.

## Inbox contract

SessionRegistry already stores inner `rekey.approval.challenge.v1` objects at
prepare time. This slice adds:

- `consumed` on a stored challenge, set when grant reservation succeeds
- Admin `APPROVAL_PENDING` (29): unused, non-expired challenges as summaries
- Admin `APPROVAL_GET` (30): one pending challenge re-signed as
  `rekey.approval.challenge.envelope.v1`

Pending and get require unlocked Running. They are reads: no step-up, no audit
row, no new Unix socket. Agent cannot call them. Lock, session revoke, and
restart still clear every challenge.

Pending response:

```json
{
  "record_type": "rekey.approval.pending.v1",
  "challenges": [
    {
      "approval_request_id": "UUID",
      "session_id": "UUID",
      "principal_id": "UUID",
      "action_id": "UUID",
      "action_version": 1,
      "created_at_ms": 0,
      "max_expires_at_ms": 0,
      "mode": "one-time",
      "quorum": 1,
      "max_uses": 1,
      "parameter_sha256": "64 lowercase hex"
    }
  ]
}
```

At most 128 summaries; overflow fails closed. Summaries include `parameter_sha256`
so an operator can match the exact request, and omit request bodies, capability
tokens, origin private material, and grant files. Get of an unknown,
expired, or already reserved challenge returns `approval-challenge-unknown`.

## Operator flow

1. Agent or operator prepares the exact request (`rekey approval prepare`).
2. Operator lists `rekey approval pending` and copies an `approval_request_id`.
3. `rekey approval get UUID` prints the origin-signed envelope.
4. Wrap the envelope with the original body into `approval-request.json`.
5. Review/sign with `rekey-approval-sign --origin-key` and execute within 60s.

The inbox authenticates Broker challenge bytes the same way prepare does. It
does not authenticate Action/policy/trust files or operator intent.
Auto-approve remains forbidden. After a successful reservation the item leaves
the inbox even if a time-window grant still has remaining uses.

## Non-goals

- GUI, notifications center, email, chat, or webhooks
- Hosted remote approval SaaS or APR-10 directory
- Agent-callable approval/sign, auto-approve, durable approval tables
- Changing grant verification, origin-key derivation, or vault format
