# Tenant CA Rotation Playbook

Operator procedure for rotating a tenant's certificate authority or bundle-signing key.
Client-cert renewal is **not** covered here — that is automatic (90-day certs, agents renew
at 14 days remaining via `POST /agent/v1/renew`).

Tenant CAs are issued with a 10-year lifetime, so rotation is an exceptional event, not
maintenance. The triggers that justify it:

- **Key compromise** (or suspected compromise) of the tenant CA private key.
- **Master-key rotation** that requires re-encrypting or re-issuing tenant secrets.
- **Cryptographic deprecation** of the CA's algorithm.

## How trust is wired (what rotation must preserve)

- Each tenant has one CA (`tenant_secrets.ca_cert_pem` + `ca_key_encrypted`, AEAD under
  `MASTER_KEY`). It signs host client certs only.
- The mTLS listener's trust store holds **every** tenant CA and resolves the tenant from
  the leaf's *issuer* — never from the leaf's own claims. Reload it with
  `trust_store.rebuild().await` (`crates/server/src/mtls.rs`). `notify_change()` also
  exists but is fire-and-forget: it can land *after* the response that told a client to
  start using the new material, which is the `UnknownCA` failure mode enrollment used to
  have. Anywhere ordering matters, await the rebuild.
- Agents pin the material they got at enrollment and refresh **all** of it (client cert,
  `ca_pem`, `mtls_server_cert_pem`, `bundle_signing_pub_pem`) from each
  `POST /agent/v1/renew` response (`crates/server/src/agent_api.rs`, `renew`).

That renew response is the distribution channel: anything placed in `tenant_secrets`
reaches every live agent within one renewal cycle once you force early renewal.

## Procedure A — planned rotation (old key NOT compromised)

The old CA remains trusted during the transition, so nothing breaks mid-flight.

1. **Generate the new CA** for the tenant (same path as tenant creation:
   `crates/server/src/tenant_setup.rs`). Encrypt the key with the master key.
2. **Add, don't replace**: insert the new CA as an *additional* trusted issuer for the
   tenant. The trust store must contain old + new simultaneously. (The
   `tenant_secrets` table is one-row-per-tenant today — rotation therefore needs a
   sibling row or table for the retiring CA; keep the old cert PEM trusted until step 5.)
3. **Switch signing**: new enrollments and renewals now sign with the new CA. Set
   `ca_cert_pem`/`ca_key_encrypted` to the new pair, then `trust_store.rebuild().await`.
   Await it before any renewal is served, or an agent can be handed a certificate signed
   by a CA the listener does not yet trust.
4. **Force early renewal**: agents renew when within 14 days of expiry. To converge
   faster, revoke nothing — instead shorten the fleet's remaining cert lifetime by
   re-issuing... in practice: wait for the natural renewal window, or lower
   `client_cert_lifetime_days` temporarily so renewals issue short certs and cycle
   quickly. Track progress: `SELECT COUNT(*) FROM host_certs WHERE expires_at > ? AND
   tenant_id = ?` grouped by issuing CA serial prefix.
5. **Retire the old CA** once every active host cert chains to the new CA: remove the
   old cert from the trust store and delete the old encrypted key. Audit-log the event.

## Procedure B — compromise response (old key IS burned)

Speed over continuity — agents signed by the old CA must be cut off.

1. Generate + install the new CA (steps 1 and 3 above), **immediately remove the old CA
   from the trust store**, and `rebuild().await`. All agents with old certs now fail the
   mTLS handshake.
2. Revoke outstanding certs: `UPDATE host_certs SET revoked_at = now WHERE tenant_id = ?
   AND revoked_at IS NULL` (belt-and-braces; the issuer removal already blocks them).
3. Re-enroll the fleet: agents cannot renew (renew requires a valid mTLS session), so
   each host needs a fresh bootstrap token — "Add host" per host, or re-issue tokens for
   the existing host rows via a maintenance script. This is manual by design: a
   compromise should have a human in the loop.
4. Audit-log the rotation with the incident reference.

## Bundle-signing key rotation

The bundle-signing key is deliberately independent of the CA (a CA compromise doesn't
forge bundles, and rotating one doesn't invalidate the other).

1. Generate a new Ed25519 pair; store in `tenant_secrets`
   (`bundle_signing_pub_pem` / `bundle_signing_key_encrypted`).
2. **Re-sign every stored bundle** for the tenant (`bundles.signature` is a signature
   over the zip's sha256): walk `bundles`, recompute signatures with the new key.
3. Agents pick up the new public key from their next `renew` response. Until an agent
   has renewed, its pinned old pubkey will reject newly-signed bundles — so either
   (a) force early renewal first, then re-sign, accepting a window where *new uploads*
   are unverifiable by *stale agents*, or (b) accept that stale agents defer bundle
   updates until their next renewal. For v1 fleets (30-day max staleness) option (b) is
   fine.

## Out of scope for v1

- Automated rotation tooling (this playbook is the manual procedure).
- CRL/OCSP — revocation is the `host_certs.revoked_at` check on every request.
- The server's own mTLS listener cert rotation. It is self-signed and persisted at
  `$MTLS_STATE_DIR/mtls-server.{crt,key}` (default `data/`); to rotate it, delete both
  files and restart. **Warning:** agents pin this cert and dial the mTLS port with it as
  their only trust root, so rotating it cuts off every enrolled agent — renewal cannot
  help (it runs over the now-broken mTLS channel); the fleet must re-enroll with fresh
  bootstrap tokens. Changing `MTLS_HOST` triggers the same regeneration automatically.
  A graceful rotation (serve old + new during an overlap window) is future work.
