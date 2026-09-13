-- Enforce the slug grammar in the schema, as a backstop to the application check.
--
-- The slug becomes a tenant's CA subject DN. Signup used to only trim and lowercase it
-- while the strict validator lived in the platform console, so a self-service tenant could
-- be named `ac me` and end up canonicalising onto an existing `acme` in the mTLS issuer
-- map. Both paths now validate, and this makes a third path that forgets to a hard error
-- rather than a quiet collision.
--
-- Triggers rather than a CHECK constraint: adding a CHECK to an existing SQLite table means
-- rebuilding it, and `tenants` is referenced by eleven others. A trigger gets the same
-- refusal with no rebuild and nothing to orphan.
--
-- GLOB is case-sensitive, so `[^a-z0-9-]` also rejects uppercase. A trailing `-` inside the
-- class is a literal.

CREATE TRIGGER tenants_slug_shape_insert
BEFORE INSERT ON tenants
WHEN NEW.slug = ''
  OR length(NEW.slug) > 63
  OR NEW.slug GLOB '*[^a-z0-9-]*'
  OR NEW.slug GLOB '-*'
  OR NEW.slug GLOB '*-'
BEGIN
  SELECT RAISE(ABORT, 'slug must be 1-63 characters of a-z, 0-9 and dashes, not starting or ending with a dash');
END;

CREATE TRIGGER tenants_slug_shape_update
BEFORE UPDATE OF slug ON tenants
WHEN NEW.slug = ''
  OR length(NEW.slug) > 63
  OR NEW.slug GLOB '*[^a-z0-9-]*'
  OR NEW.slug GLOB '-*'
  OR NEW.slug GLOB '*-'
BEGIN
  SELECT RAISE(ABORT, 'slug must be 1-63 characters of a-z, 0-9 and dashes, not starting or ending with a dash');
END;
