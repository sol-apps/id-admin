/// <reference path="../pb_data/types.d.ts" />
/*
 * identity.pb.js — the app's half of the platform identity layer.
 *
 * Delivered by the template and PROTECTED BY CI: a generated app may not edit this
 * file. An app that could rewrite its own role mapping is an app that decides its own
 * permissions, and the whole point of the grant table is that it does not.
 *
 * Three jobs:
 *   1. configure the OIDC provider from the runtime env, on every boot;
 *   2. set users.role from the identity provider's roles claim, on every login;
 *   3. refuse local session renewal, so every renewal re-enters through the IdP.
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

  if (!issuer || !clientId || !clientSecret) {
    // Local pb-dev has no Keycloak. Password auth stays available there and only
    // there — on prod the env is always present, because provision-app writes it
    // before the instance is ever started.
    console.log("[identity] no OIDC_* in the environment — local mode, password auth left enabled");
    return;
  }

  const users = e.app.findCollectionByNameOrId("users");
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

  // With the IdP in front, a password on the local record is a second way in that no
  // grant governs — so there isn't one.
  users.passwordAuth.enabled = false;

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

  // Server-set, on EVERY login, from the claim — never from the request body, and
  // never left at whatever it was last time. Revoking someone's app-admin grant
  // therefore takes effect at their next sign-in without anyone editing a record.
  if (e.record) {
    e.record.set("role", role);
    e.app.save(e.record);
  } else {
    // First login for this person in this app: the record does not exist yet, so the
    // role goes in with the data PocketBase is about to create it from.
    e.createData = e.createData || {};
    e.createData["role"] = role;
  }

  e.next();
}, "users");

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
