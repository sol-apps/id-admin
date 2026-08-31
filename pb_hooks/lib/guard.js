/*
 * lib/guard.js — who may operate the grants service.
 *
 * Normally: whoever holds an ADMIN grant on `id-admin` itself, which makes this
 * screen governed by the same mechanism it governs. There is no separate operator
 * list and no environment variable naming a superuser.
 *
 * `role` is server-set from the identity provider's claim on every login
 * (pb_hooks/identity.pb.js) and cannot be set by any request, so reading it here is
 * reading the grant, not reading the browser.
 *
 * The one exception is the provisioning token, and it exists to solve exactly one
 * problem: the first admin grant. Nobody can use this screen until someone has an
 * admin grant on it, and nobody can create that grant through this screen. The token
 * lives in the id-admin instance's env file, root-only, on the prod box — so
 * "presents the token" means "is already root on the machine", which is not an
 * escalation. It is accepted for creating a grant and for registering an app, and for
 * nothing else: offboarding, reconcile-repair and reading the audit trail all still
 * require a human admin.
 */
module.exports = {
  // Returns the actor string to record, or null if the caller may not do this.
  actor(e, allowToken) {
    if (allowToken) {
      const token = $os.getenv("PROVISION_TOKEN");
      const given = e.request.header.get("X-Provision-Token") || "";
      if (token && given.length === token.length) {
        let same = true;
        for (let i = 0; i < token.length; i++) {
          if (given.charCodeAt(i) !== token.charCodeAt(i)) same = false;
        }
        if (same) return "provisioning";
      }
    }
    const auth = e.auth;
    if (!auth) return null;
    if (auth.collection().name !== "users") return null;
    if (auth.get("role") !== "admin") return null;
    return auth.get("email") || auth.id;
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
    const token = $os.getenv("PROVISION_TOKEN");
    if (!token) return null;
    const given = e.request.header.get("X-Provision-Token") || "";
    if (given.length !== token.length) return null;
    let same = true;
    for (let i = 0; i < token.length; i++) {
      if (given.charCodeAt(i) !== token.charCodeAt(i)) same = false;
    }
    return same ? "provisioning" : null;
  },
};
