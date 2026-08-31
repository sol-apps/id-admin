/*
 * lib/kc.js — the Keycloak admin API, as much of it as the grants service is allowed
 * to touch.
 *
 * Reached over LOOPBACK (KC_INTERNAL_URL), never through Caddy: the public vhost
 * answers 404 to /admin/*, so the credential that mints identity is never behind
 * anything as thin as a password form. Same box, same reason the PocketBase superuser
 * tools run on prod rather than from a laptop.
 *
 * The service account behind this holds exactly two realm-management roles,
 * view-users and manage-users. It cannot read a client secret, enumerate clients or
 * create anything — verified, not assumed. Everything below is written to work inside
 * that, which is why role assignment takes ids from the `apps` table rather than
 * looking a client up by name.
 */
module.exports = {
  cfg() {
    const c = {
      base: ($os.getenv("KC_INTERNAL_URL") || "http://127.0.0.1:8180").replace(/\/+$/, ""),
      realm: $os.getenv("KC_REALM") || "greenlight",
      clientId: $os.getenv("KC_SVC_CLIENT_ID") || "id-admin-svc",
      secret: $os.getenv("KC_SVC_CLIENT_SECRET"),
    };
    if (!c.secret) {
      throw new Error("KC_SVC_CLIENT_SECRET is not set — the grants service cannot reach the realm");
    }
    return c;
  },

  token(c) {
    const res = $http.send({
      url: c.base + "/realms/" + c.realm + "/protocol/openid-connect/token",
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "grant_type=client_credentials&client_id=" + encodeURIComponent(c.clientId) +
            "&client_secret=" + encodeURIComponent(c.secret),
      timeout: 15,
    });
    if (res.statusCode !== 200) {
      throw new Error("keycloak refused the service account: HTTP " + res.statusCode);
    }
    return res.json.access_token;
  },

  admin(c, tok, method, path, body) {
    const req = {
      url: c.base + "/admin/realms/" + c.realm + path,
      method: method,
      headers: { authorization: "Bearer " + tok },
      timeout: 20,
    };
    if (body !== undefined) {
      req.headers["content-type"] = "application/json";
      req.body = JSON.stringify(body);
    }
    const res = $http.send(req);
    if (res.statusCode >= 400) {
      // The status travels with the error. Callers used to swallow every failure from
      // a role removal on the theory that "the person did not hold it anyway" — and
      // that theory is false: Keycloak answers 204 to removing a role the user does
      // not hold (probed, not assumed). A 4xx or 5xx here is always a real failure,
      // and swallowing it made revoke report success it had not achieved.
      const err = new Error("keycloak " + method + " " + path + " -> HTTP " + res.statusCode);
      err.statusCode = res.statusCode;
      throw err;
    }
    return res.json;
  },

  // ── the operations the grants service actually performs ───────────────────

  // Paged, because a capped read here is not a truncated list — it is a silent hole
  // in the reconcile check. Anyone past the cap is never compared against the grant
  // table, so an unbacked role mapping on person 501 is invisible to the one tool
  // built to find exactly that. Better to be slow than to be quietly partial.
  people(c, tok) {
    const out = [];
    const page = 200;
    let first = 0;
    for (;;) {
      const users = this.admin(c, tok, "GET",
        "/users?briefRepresentation=true&first=" + first + "&max=" + page) || [];
      for (let i = 0; i < users.length; i++) {
        const u = users[i];
        out.push({
          subject: u.id,
          username: u.username,
          email: u.email || "",
          name: ((u.firstName || "") + " " + (u.lastName || "")).trim() || u.username,
          enabled: u.enabled !== false,
        });
      }
      if (users.length < page) break;
      first += page;
      // A realm this large has outgrown a reconcile that walks every person against
      // every app inside one HTTP request (see lib/reconcile.js). Stop and say so
      // rather than time out halfway and report a partial answer as a clean one.
      if (first >= 5000) {
        throw new Error("more than 5000 realm users — reconcile needs to move to a " +
                        "background job before it can be trusted at this size");
      }
    }
    return out;
  },

  rolesHeld(c, tok, subject, clientUuid) {
    const held = this.admin(c, tok, "GET",
      "/users/" + subject + "/role-mappings/clients/" + clientUuid) || [];
    const names = [];
    for (let i = 0; i < held.length; i++) names.push(held[i].name);
    return names;
  },

  // A grant is TWO role assignments, not one: restricted-access is what lets the
  // person authenticate to the client at all, and app-admin is what makes them an
  // admin once inside. Role "user" means the first without the second.
  applyGrant(c, tok, subject, appRow, role) {
    const add = [{ id: appRow.get("role_restricted_id"), name: "restricted-access" }];
    const drop = [];
    const adminRole = { id: appRow.get("role_admin_id"), name: "app-admin" };
    if (role === "admin") add.push(adminRole); else drop.push(adminRole);

    const path = "/users/" + subject + "/role-mappings/clients/" + appRow.get("client_uuid");
    this.admin(c, tok, "POST", path, add);
    if (drop.length) {
      // Nothing is caught here. Removing a role the person does not hold already
      // succeeds (204), so the only way this throws is a failure that matters — and
      // the demotion path is the invisible direction of drift: if dropping app-admin
      // fails quietly, the table says "user", the realm keeps minting app-admin into
      // the claim, and the person stays an admin of that app with nothing on screen
      // to say so.
      this.admin(c, tok, "DELETE", path, drop);
    }
  },

  revokeGrant(c, tok, subject, appRow) {
    const path = "/users/" + subject + "/role-mappings/clients/" + appRow.get("client_uuid");
    const both = [
      { id: appRow.get("role_restricted_id"), name: "restricted-access" },
      { id: appRow.get("role_admin_id"), name: "app-admin" },
    ];
    // Not caught, for the same reason: a failure here means the person still holds
    // restricted-access and can still enter the app, which is precisely what the
    // caller is about to tell someone did not happen.
    this.admin(c, tok, "DELETE", path, both);
  },

  // Blunt on purpose, and the bluntness was measured rather than assumed: a Keycloak
  // user session spans every client that person has entered, so there is no such
  // thing as logging them out of one app. Revoking a grant does not need this — the
  // restriction is re-evaluated at the next authorization request either way — but
  // offboarding does.
  logout(c, tok, subject) {
    this.admin(c, tok, "POST", "/users/" + subject + "/logout", {});
  },

  setEnabled(c, tok, subject, enabled) {
    this.admin(c, tok, "PUT", "/users/" + subject, { enabled: !!enabled });
  },
};
