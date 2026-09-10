# WID-10 GitHub Actions OIDC interoperability

Use a disposable private GitHub Actions repository with id-token:write and
contents:read. The initial workflow verified the published alpha.2 Linux archive,
which rejected GitHub's standard RS256 `x5t` header. The successful workflow
instead built base `358b3a5` with the bounded `x5t` metadata fix and its tests.
The harness requests real GitHub OIDC JWTs in memory, obtains the
issuer public JWKS over HTTPS, and puts a single selected RS256 public key in
a signed static Rekey policy. The configured issuer, subject and audiences are
exact; the broker does not fetch keys or perform discovery.

Create a disposable authority and synthetic upstream header credential. Mint
a workload session via explicit token stdin, execute a fixed anonymous GitHub
read, reject replay and wrong audience, then wait for a distinct unused genuine
JWT to expire and reject it without modifying claims or the clock. Expiry waits
are bounded to 15 minutes. No JWT, password, capability or private signer key
is uploaded to artifacts; only public key metadata, hashes, statuses and audit
summaries. Remove temporary local state at job exit and delete the test repo
after retrieving evidence. This does not implement WID-09 or OAuth exchange.

Reference: https://docs.github.com/en/actions/reference/security/oidc

## Recorded static-key acceptance

GitHub Actions run `34458227976` completed successfully on 2026-09-10.
`outputs/rekey-wid10-20260910/static-receipt/` records its status, runner commit,
binary hashes and public receipt. Real JWT mint and fixed read returned success
and HTTP 200; replay, wrong audience and a distinct naturally expired unused JWT
all returned CLI exit 4. No JWT was saved; job-local state and secrets were removed.
This is source acceptance, not evidence that released alpha.2 supports these JWTs.
The disposable repository subsequently passed the separate WID-09 online JWKS
acceptance and was deleted. `outputs/rekey-wid09-20260910/online/cleanup.json`
records zero active runs before deletion and API 404 afterward.
