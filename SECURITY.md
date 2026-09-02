# Security policy

## Supported version

Only `2.0.0-alpha.1` is supported until superseded by a later prerelease. The
project provides best-effort fixes and makes no SLA or response-time promise.

## Report a vulnerability privately

Use GitHub Security Advisories for this repository: open the **Security** tab,
choose **Advisories**, then **Report a vulnerability**. Do not include secrets,
private keys, recovery keys, customer data, or exploit details in a public
issue. If GitHub private reporting is unavailable, open a public issue that
contains only a request for a private contact channel.

Include affected version/commit, platform, security boundary, minimal
reproduction, impact, and whether credentials or remote effects may be
involved. Maintainers will acknowledge when available, triage severity, and
coordinate a fix and disclosure. There is no bug bounty or guaranteed embargo.

## Scope

Read `docs/alpha-scope.md` and the threat model before reporting an intended
G1 limitation as a vulnerability. Host root/kernel compromise, same-user
process inspection, and direct Agent egress outside the bounded G2 reference
are not claimed protections. Secret exposure through a documented supported
boundary, authentication bypass, unsafe remote effect, cryptographic misuse,
or durable audit/integrity failure is in scope.

Never test against systems, repositories, credentials, or users you do not own
or have explicit permission to assess.
