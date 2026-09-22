/// <reference path="../pb_data/types.d.ts" />
/*
 * identity.pb.js — the app's half of the platform identity layer.
 *
 * Delivered by the template and PROTECTED BY CI: a generated app may not edit this
 * file. An app that could rewrite its own role mapping is an app that decides its own
 * permissions, and the whole point of the grant table is that it does not.
 *
 * Four jobs:
 *   1. converge the reviewed public/Keycloak policy from the runtime env, on every boot;
 *   2. set users.role from the identity provider's roles claim, on every login;
 *   3. refuse local session renewal, so every renewal re-enters through the IdP.
 *   4. stop authenticated realtime delivery when the token that authorised it expires.
 *
 * None of them reads anything the browser sent.
 */

// ── 1. provider configuration, from the env, every boot ─────────────────────
//
// Not a migration: a migration runs once, so it would miss an app provisioned before
// the IdP existed and could not express a rotated client secret. This converges on
// every start, which makes `provision-app <slug>` the repair for both.
onBootstrap((e) => {
  e.next();

  const issuer = $os.getenv("OIDC_ISSUER");
  const clientId = $os.getenv("OIDC_CLIENT_ID");
  const clientSecret = $os.getenv("OIDC_CLIENT_SECRET");
  const mode = $os.getenv("GREENLIGHT_IDENTITY_MODE");
  let access = $os.getenv("GREENLIGHT_ACCESS_MODE");

  if (mode === "local") {
    // pb-dev opts into this explicitly. Access policy is a production decision and
    // local mode is never a back door to public production.
    console.log("[identity] explicit local mode — production access convergence skipped");
    return;
  }
  if (mode !== "production") {
    throw new Error("GREENLIGHT_IDENTITY_MODE must be explicitly 'local' or 'production'");
  }
  const users = e.app.findCollectionByNameOrId("users");

  // Compatibility is deliberately protected-only. Existing governed apps predate
  // GREENLIGHT_ACCESS_MODE; their complete OIDC triple continues to mean Keycloak.
  // Missing configuration can never select public access.
  if (!access && issuer && clientId && clientSecret) access = "keycloak";
  if (access !== "keycloak" && access !== "public") {
    throw new Error("GREENLIGHT_ACCESS_MODE must be explicitly 'keycloak' or 'public'");
  }

  // Password accounts are never a fallback in either mode. Public means anonymous
  // operations declared by the reviewed app migrations, not self-registration.
  const authWasOpen = users.authRule !== null || users.oauth2.enabled ||
    users.passwordAuth.enabled;
  users.passwordAuth.enabled = false;
  users.deleteRule = null;
  users.authToken.duration = 1800;

  if (access === "public") {
    if (issuer || clientId || clientSecret) {
      throw new Error("public access must not retain OIDC credentials");
    }
    // PocketBase auth tokens are stateless. Closing the login methods alone does not
    // invalidate a token issued while this app was protected, so rotate the shared
    // users-token secret exactly when an auth-capable configuration becomes public.
    if (authWasOpen) users.authToken.secret = $security.randomString(50);
    users.authRule = null;
    users.oauth2.enabled = false;
    users.oauth2.providers = [];
    users.createRule = null;
    users.listRule = null;
    users.viewRule = null;
    users.updateRule = null;
    e.app.save(users);
    console.log("[identity] public access configured — users and OAuth remain closed");
    return;
  }

  if (!issuer || !clientId || !clientSecret) {
    throw new Error("keycloak access requires complete OIDC_ISSUER, OIDC_CLIENT_ID and OIDC_CLIENT_SECRET");
  }
  users.authRule = "";
  users.oauth2.enabled = true;
  users.oauth2.mappedFields = { id: "", name: "name", username: "", avatarURL: "" };
  users.oauth2.providers = [{
    name: "oidc",
    displayName: "Greenlight",
    clientId: clientId,
    clientSecret: clientSecret,
    authURL: issuer + "/protocol/openid-connect/auth",
    tokenURL: issuer + "/protocol/openid-connect/token",
    userInfoURL: issuer + "/protocol/openid-connect/userinfo",
    pkce: true,
  }];

  users.createRule = "@request.context = 'oauth2'";
  users.listRule = "id = @request.auth.id";
  users.viewRule = "id = @request.auth.id";
  users.updateRule = "id = @request.auth.id && @request.body.role:isset = false";

  e.app.save(users);
  console.log("[identity] OIDC provider configured for " + clientId + " at " + issuer);
});

// ── 2. role mapping, from the claim, every login ────────────────────────────
onRecordAuthWithOAuth2Request((e) => {
  const claim = "greenlight_roles";
  const raw = (e.oAuth2User && e.oAuth2User.rawUser) || {};
  const roles = raw[claim];

  // Defence in depth. The issuer has already refused anyone without the
  // restricted-access role, so an absent claim does not mean "ungranted" — it means
  // this app's client is misconfigured (mapper removed, scope changed). Failing the
  // login is the honest response: the alternative is quietly treating a
  // misconfiguration as "ordinary user", which is a permission decision made by
  // accident.
  const list = [];
  if (roles) {
    for (let i = 0; i < roles.length; i++) {
      list.push("" + roles[i]);
    }
  }
  if (!roles || !list.length) {
    console.log("[identity] refusing login: no " + claim + " claim in the userinfo payload");
    throw new BadRequestError("identity is not configured for this app");
  }

  const role = list.indexOf("app-admin") !== -1 ? "admin" : "user";
  const incomingSubject = "" + ((e.oAuth2User && e.oAuth2User.id) || "");
  if (!incomingSubject) {
    throw new BadRequestError("identity provider returned no canonical subject");
  }

  // PocketBase may select an existing record by verified email before it checks the
  // external-auth link. Never let a new subject inherit or modify that record. A
  // password-account migration therefore needs an explicit linking policy; the
  // default is refusal, not email-based account linking.
  if (e.record && !e.isNewRecord) {
    const links = e.app.findAllExternalAuthsByRecord(e.record);
    let linkedSubject = null;
    for (let i = 0; i < links.length; i++) {
      if (links[i] && links[i].provider() === "oidc") {
        linkedSubject = "" + (links[i].providerId() || "");
        break;
      }
    }
    if (!linkedSubject || linkedSubject !== incomingSubject) {
      throw new BadRequestError("this local account is linked to a different identity subject");
    }
  }

  if (!e.record || e.isNewRecord) {
    // First login: PocketBase creates the record and provider link inside e.next().
    e.createData = e.createData || {};
    e.createData["role"] = role;
  } else {
    // e.next() serialises and sends the OAuth response. Persist an existing record's
    // role before crossing that response boundary so the returned record and token
    // cannot carry the previous permission. A failed save therefore refuses login.
    // The subject-link check above makes this safe from recycled-email linking.
    e.record.set("role", role);
    e.app.save(e.record);
  }

  // For a new identity, createData is committed as part of PocketBase's own provider
  // link transaction. For an existing identity, the role is already durable. In both
  // cases the successful response contains exactly the permission just validated.
  e.next();
}, "users");

// Read-only UX metadata. It cannot select or mutate policy: the value comes only from
// the provisioner-owned environment and is useful to the shared browser seam.
routerAdd("GET", "/api/greenlight/access", (e) => {
  const identityMode = $os.getenv("GREENLIGHT_IDENTITY_MODE");
  let access = $os.getenv("GREENLIGHT_ACCESS_MODE");
  if (identityMode === "local") return e.json(200, { mode: "local" });
  if (!access && $os.getenv("OIDC_ISSUER") && $os.getenv("OIDC_CLIENT_ID") &&
      $os.getenv("OIDC_CLIENT_SECRET")) access = "keycloak";
  if (access !== "keycloak" && access !== "public") {
    return e.json(503, { error: "production access policy is not configured" });
  }
  return e.json(200, { mode: access });
});

// ── 3. renewal is not a local operation ─────────────────────────────────────
//
// PocketBase's auth-refresh endpoint issues a fresh token to anyone presenting a
// valid one, without reference to the issuer. Left enabled it quietly defeats the
// thirty-minute token lifetime set in pb_migrations/1756540000_identity.js: a tab
// that refreshes every twenty minutes keeps its session alive indefinitely, at the
// role its FIRST login wrote, on a grant that may have been revoked hours earlier —
// because nothing anywhere in that path asks the identity provider anything.
//
// A short lifetime is therefore only worth something if this door is shut. It is
// shut here rather than by removing the route, so the refusal is explicit and shows
// up in the app's logs instead of as a 404 someone reads as a bug.
//
// The cost is one popup against a live SSO cookie (pb-auth.js), and the popup is the
// whole point: it is the only moment the restriction gets re-evaluated.
onRecordAuthRefreshRequest((e) => {
  console.log("[identity] refusing local token renewal for " +
              ((e.record && e.record.id) || "unknown") + " — renewal goes through the IdP");
  throw new BadRequestError("sessions are renewed by signing in again, not locally");
}, "users");

// ── 4. realtime is part of the same session boundary ───────────────────────
// PocketBase stores the authenticated record on a realtime client. Without this
// guard it can continue authorising deliveries after the JWT that created the
// subscription has expired. Remember that JWT's expiry when the subscription is
// authorised, then enforce it before every outgoing message. Browser-side cleanup is
// helpful UX, but the server is the security boundary.
onRealtimeSubscribeRequest((e) => {
  if (e.auth && e.auth.collection().name === "users") {
    const headers = e.requestInfo().headers;
    const header = (typeof headers.get === "function"
      ? (headers.get("authorization") || headers.get("Authorization"))
      : (headers.authorization || headers.Authorization)) || "";
    const token = header.replace(/^Bearer\s+/i, "");
    if (!token) throw new BadRequestError("authenticated realtime subscription has no token");
    const claims = $security.parseUnverifiedJWT(token);
    const expires = Number((typeof claims.get === "function" && claims.get("exp")) ||
                           claims.exp || 0);
    if (!expires) throw new BadRequestError("authenticated realtime token has no expiry");
    e.client.set("greenlight_auth_expires", expires);
  }
  e.next();
});

onRealtimeMessageSend((e) => {
  const expires = Number(e.client.get("greenlight_auth_expires") || 0);
  if (expires && Math.floor(Date.now() / 1000) >= expires) {
    console.log("[identity] discarding realtime client after its auth token expired");
    e.client.discard();
    return;
  }
  e.next();
});
