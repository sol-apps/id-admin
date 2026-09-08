/*
 * lib/guard.js — who may operate the grants service.
 *
 * Normally: whoever holds an ADMIN grant on `id-admin` itself, which makes this
 * screen governed by the same mechanism it governs. There is no separate operator
 * list and no environment variable naming a superuser.
 *
 * A PocketBase token only proves which local record logged in.  It does not prove
 * that the grant which produced that login still exists.  Every request therefore
 * resolves that record's OIDC link to the canonical Keycloak subject and checks the
 * CURRENT id-admin grant in this database.  Revoking an Access administrator takes
 * effect here immediately, even while their old PocketBase token remains valid.
 *
 * The one exception is the provisioning token, and it exists to solve exactly one
 * problem: the first admin grant. Nobody can use this screen until someone has an
 * admin grant on it, and nobody can create that grant through this screen. The token
 * lives in the id-admin instance's env file, root-only, on the prod box — so
 * "presents the token" means "is already root on the machine", which is not an
 * escalation. It is accepted for the two ends of the grant lifecycle — creating a grant and
 * revoking one — and for registering an app, and for nothing else: offboarding,
 * reconcile-repair and reading the audit trail all still require a human admin.
 *
 * Revoke accepts it for the same reason grant does, and refusing it there was an
 * inconsistency rather than a boundary: a caller who can hand out access through this
 * door can already take it away by hand, and greenlight-proof needs to put the demo
 * realm back exactly the way it found it.
 */
module.exports = {
  // Constant-time-ish comparison of the provisioning token, in one place. It was
  // written out twice, which is two chances for one of them to become an ordinary
  // string compare during a tidy-up.
  provisioningOk(e) {
    const token = $os.getenv("PROVISION_TOKEN");
    if (!token) return false;
    const given = e.request.header.get("X-Provision-Token") || "";
    if (given.length !== token.length) return false;
    let same = true;
    for (let i = 0; i < token.length; i++) {
      if (given.charCodeAt(i) !== token.charCodeAt(i)) same = false;
    }
    return same;
  },

  // Returns the canonical Keycloak subject to record as actor, or null if the caller
  // may not do this.  Email and PocketBase record ids are display/local data only.
  actor(e, allowToken) {
    if (allowToken && this.provisioningOk(e)) return "provisioning";
    if (!e.auth) return null;
    const identity = require(__hooks + "/lib/identity.js");
    return identity.currentAdmin(e.app, e.auth);
  },

  requireAdmin(e) {
    return this.actor(e, false);
  },

  // Provisioning ONLY — an admin grant is not enough.
  //
  // Used by the app-registration route, because the row it writes is not ordinary
  // data: it names a Keycloak client uuid and two role ids, and the grants service
  // later assigns exactly those ids. A row naming the realm-management client and one
  // of its roles turns "grant Bob access to an app" into "give Bob manage-users on the
  // realm" — verified against a live realm, which accepted manage-users (a role the
  // service account itself holds) and refused realm-admin (one it does not).
  //
  // So registration is restricted to whoever holds the provisioning token, which means
  // root on the prod box, who already holds the Keycloak admin credential and gains
  // nothing from the detour. An id-admin admin is trusted with access, not with the
  // realm's own administration.
  requireProvisioning(e) {
    return this.provisioningOk(e) ? "provisioning" : null;
  },
};
