# Onboarding review

Reviewed by native thread `/root/onboarding_review` (read-only).

- Fixed: executing a binary or CRLF response no longer decodes or normalizes the response body. Capability remains stdin-only; HTTP failures point to operator repair without automatic retry.
- Verified locally: hidden TTY credential enrollment and rotation; all required step-up prompts; existing Action selection; existing signed-policy rejection; real wrapper denial before activation, invalid-schema denial after activation, and session revocation.
- Public checks are tracked separately. A mocked upstream success is not public GitHub/Vault evidence.
- Temporary GitHub harness uses null schema for bodyless repository listing. Its same-key profile rotation does not claim provider key rotation or webhook delivery coverage.
