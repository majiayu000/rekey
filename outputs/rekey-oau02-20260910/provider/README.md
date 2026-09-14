Provider-only loopback probe, Keycloak 26.7.3. This is not Broker or production
public-address transport acceptance. Only `rekey-oau02-provider-20260910` was
created. Its container and volumes were removed and the private realm import
was deleted; receipt.json records absence and a successful secret scan. The
public image remains cached.

The original run exited 1 because its expiry negative assertion expected
`invalid_token`; Keycloak returned HTTP 400 `invalid_request` for a subject
expired by 2 seconds. That is the actual refusal evidence. The archived script
now expects this correct error; the receipt is preserved unchanged and no
successful rerun is claimed. Exchange -> active -> direct revoke -> inactive
completed with 19.9247 seconds remaining before issued-token expiry.

Online introspection proves provider state. Offline JWT-only resources can
continue accepting the token until exp. No tokens, client secrets, realm
imports, private CA material or administrator credentials are archived.
