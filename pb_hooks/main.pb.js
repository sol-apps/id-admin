/// <reference path="../pb_data/types.d.ts" />
/*
 * main.pb.js — the grants service.
 *
 * Every route here is one of two things: a provisioning callback authenticated by a
 * shared token, or an admin action authenticated by an admin grant on THIS app. There
 * is no third kind, and in particular there is no route that grants access to anyone
 * without a human having asked for it — nothing in this file auto-approves, and if a
 * future flow wants requestable access, the request queues for a human, the same
 * shape as the merge gate.
 *
 * The grant table is the source of truth. Keycloak is a cache of it. Every mutation
 * writes the table, writes an audit row, then pushes the change to the realm — in
 * that order, so a realm push that fails leaves a recorded intent that reconcile can
 * repair, rather than a silent divergence nobody can see.
 */

// ── provisioning: register an app ──────────────────────────────────────────
// Called by provision-app on the same box when an app's OIDC client is created. It
// carries the client uuid and role ids that this service cannot look up for itself.
routerAdd("POST", "/api/id-admin/apps", (e) => {
  const g = require(__hooks + "/lib/guard.js");
  // Provisioning only, deliberately — see requireProvisioning in lib/guard.js for
  // what an arbitrary row here is worth to an attacker.
  if (!g.requireProvisioning(e)) {
    return e.json(403, { message: "provisioning token required" });
  }

  const body = e.requestInfo().body || {};
  const slug = "" + (body.slug || "");
  const roles = body.roles || {};
  const restricted = roles["restricted-access"] || {};
  const appAdmin = roles["app-admin"] || {};
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(slug) || slug.length > 28) {
    return e.json(400, { message: "bad slug" });
  }
  // Shape-check the identifiers too. This does not make a hostile row safe — only
  // restricting the route to provisioning does that — but it stops a malformed one
  // being stored and then failing much later, inside a grant, as an opaque 502.
  if (!uuid.test("" + body.client_uuid) || !uuid.test("" + restricted.id) ||
      !uuid.test("" + appAdmin.id)) {
    return e.json(400, { message: "client_uuid and both role ids must be uuids" });
  }
  // Keycloak's own clients are never apps. Registering one would point the grants
  // service at the realm's administration surface.
  const reserved = ["realm-management", "account", "account-console", "admin-cli",
                    "broker", "security-admin-console"];
  if (reserved.indexOf(slug) !== -1) {
    return e.json(400, { message: "that slug is a Keycloak built-in, not an app" });
  }

  let row;
  try {
    row = e.app.findFirstRecordByFilter("apps", "slug = {:s}", { s: slug });
  } catch (err) {
    row = new Record(e.app.findCollectionByNameOrId("apps"));
  }
  row.set("slug", slug);
  row.set("client_uuid", "" + body.client_uuid);
  row.set("role_restricted_id", "" + restricted.id);
  row.set("role_admin_id", "" + appAdmin.id);
  e.app.save(row);

  const audit = new Record(e.app.findCollectionByNameOrId("audit"));
  audit.set("actor", "provisioning");
  audit.set("action", "app.register");
  audit.set("slug", slug);
  audit.set("detail", "client " + body.client_uuid);
  e.app.save(audit);

  return e.json(200, { ok: true, slug: slug });
});

// ── provisioning: forget an app ────────────────────────────────────────────
// The counterpart to registration, called by deprovision-app. Its grants must go with
// it: a slug can be reused, and grants left pointing at a dead app would be inherited
// by whatever takes that slug next — access nobody granted, that reconcile cannot see
// because the table and the realm would agree with each other and both be wrong.
routerAdd("DELETE", "/api/id-admin/apps/{slug}", (e) => {
  const g = require(__hooks + "/lib/guard.js");
  if (!g.requireProvisioning(e)) {
    return e.json(403, { message: "provisioning token required" });
  }
  const slug = e.request.pathValue("slug");
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(slug || "")) {
    return e.json(400, { message: "bad slug" });
  }

  const grants = e.app.findAllRecords("grants", $dbx.exp("slug = {:s}", { s: slug }));
  for (let i = 0; i < grants.length; i++) {
    e.app.delete(grants[i]);
  }
  let hadApp = false;
  try {
    e.app.delete(e.app.findFirstRecordByFilter("apps", "slug = {:s}", { s: slug }));
    hadApp = true;
  } catch (err) { /* never registered, or already gone */ }

  const audit = new Record(e.app.findCollectionByNameOrId("audit"));
  audit.set("actor", "provisioning");
  audit.set("action", "app.deregister");
  audit.set("slug", slug);
  audit.set("detail", "removed " + grants.length + " grant(s)" +
                      (hadApp ? " and the app registration" : " (app was not registered)"));
  e.app.save(audit);

  return e.json(200, { ok: true, slug: slug, grants_removed: grants.length });
});

// ── admin surface ──────────────────────────────────────────────────────────

routerAdd("GET", "/api/id-admin/state", (e) => {
  const g = require(__hooks + "/lib/guard.js");
  const kc = require(__hooks + "/lib/kc.js");
  const who = g.requireAdmin(e);
  if (!who) return e.json(403, { message: "admin on id-admin required" });

  const apps = e.app.findAllRecords("apps");
  const grants = e.app.findAllRecords("grants");
  const appList = [];
  for (let i = 0; i < apps.length; i++) appList.push({ slug: apps[i].get("slug") });
  const grantList = [];
  for (let i = 0; i < grants.length; i++) {
    grantList.push({
      id: grants[i].id,
      subject: grants[i].get("subject"),
      slug: grants[i].get("slug"),
      role: grants[i].get("role"),
      person: grants[i].get("person"),
      granted_by: grants[i].get("granted_by"),
      created: "" + grants[i].get("created"),
    });
  }

  let people = [];
  let peopleError = null;
  try {
    const c = kc.cfg();
    people = kc.people(c, kc.token(c));
  } catch (err) {
    // The screen is still useful without the directory — it can show and revoke what
    // is already granted. Saying so beats an empty page that looks like "no one".
    peopleError = "" + err;
  }

  return e.json(200, { apps: appList, grants: grantList, people: people, peopleError: peopleError });
});

routerAdd("POST", "/api/id-admin/grants", (e) => {
  const g = require(__hooks + "/lib/guard.js");
  const kc = require(__hooks + "/lib/kc.js");
  // allowToken: this is the route that creates the FIRST admin grant, from the prod
  // box, before anyone can sign in here. See lib/guard.js.
  const who = g.actor(e, true);
  if (!who) return e.json(403, { message: "admin on id-admin required" });

  const body = e.requestInfo().body || {};
  const subject = "" + (body.subject || "");
  const slug = "" + (body.slug || "");
  const role = "" + (body.role || "user");
  if (!subject || !slug) return e.json(400, { message: "subject and slug are required" });
  if (role !== "user" && role !== "admin") return e.json(400, { message: "role must be user or admin" });

  let appRow;
  try {
    appRow = e.app.findFirstRecordByFilter("apps", "slug = {:s}", { s: slug });
  } catch (err) {
    return e.json(404, { message: "no such app: " + slug + " (has it been provisioned?)" });
  }

  let row;
  let action = "grant.create";
  try {
    row = e.app.findFirstRecordByFilter("grants", "subject = {:s} && slug = {:g}",
                                        { s: subject, g: slug });
    action = "grant.change";
  } catch (err) {
    row = new Record(e.app.findCollectionByNameOrId("grants"));
    row.set("subject", subject);
    row.set("slug", slug);
  }
  row.set("role", role);
  row.set("granted_by", who);
  if (body.person) row.set("person", "" + body.person);
  e.app.save(row);

  const audit = new Record(e.app.findCollectionByNameOrId("audit"));
  audit.set("actor", who);
  audit.set("action", action);
  audit.set("subject", subject);
  audit.set("slug", slug);
  audit.set("role", role);
  e.app.save(audit);

  try {
    const c = kc.cfg();
    kc.applyGrant(c, kc.token(c), subject, appRow, role);
  } catch (err) {
    return e.json(502, {
      message: "grant recorded but NOT applied to the identity provider: " + err,
      recorded: true,
    });
  }
  return e.json(200, { ok: true, id: row.id, role: role });
});

routerAdd("POST", "/api/id-admin/revoke", (e) => {
  const g = require(__hooks + "/lib/guard.js");
  const kc = require(__hooks + "/lib/kc.js");
  const who = g.requireAdmin(e);
  if (!who) return e.json(403, { message: "admin on id-admin required" });

  const body = e.requestInfo().body || {};
  const subject = "" + (body.subject || "");
  const slug = "" + (body.slug || "");
  if (!subject || !slug) return e.json(400, { message: "subject and slug are required" });

  let appRow;
  try {
    appRow = e.app.findFirstRecordByFilter("apps", "slug = {:s}", { s: slug });
  } catch (err) {
    return e.json(404, { message: "no such app: " + slug });
  }
  try {
    const row = e.app.findFirstRecordByFilter("grants", "subject = {:s} && slug = {:g}",
                                              { s: subject, g: slug });
    e.app.delete(row);
  } catch (err) { /* already absent — still push the realm side below */ }

  // The audit row goes in BEFORE the realm push, like POST /grants and offboard.
  // Writing it afterwards put the one case that matters most — a revoke that did not
  // take — on the far side of an early return: the table said no grant, the realm
  // kept granting, and the audit trail said nothing at all. The row records INTENT
  // here and is updated with the outcome below, so every attempt leaves a trace
  // whichever way the push goes.
  const audit = new Record(e.app.findCollectionByNameOrId("audit"));
  audit.set("actor", who);
  audit.set("action", "grant.revoke");
  audit.set("subject", subject);
  audit.set("slug", slug);
  audit.set("detail", "revoke requested");
  e.app.save(audit);

  let sessionsEnded = false;
  let sessionNote = "";
  try {
    const c = kc.cfg();
    const tok = kc.token(c);
    kc.revokeGrant(c, tok, subject, appRow);
    // Then end their identity-provider sessions (AUTH-LAYER §3). This is BLUNT: a
    // Keycloak session spans every client the person has entered, and there is no
    // per-client logout (probed — §7.5 anticipates exactly this and accepts it), so
    // revoking one app signs them out of all of them. They can walk straight back
    // into the apps they still hold; what they cannot do is keep riding an existing
    // SSO cookie into the one just taken away.
    //
    // It runs AFTER the role removal, so a failed revoke never costs someone their
    // sessions for nothing.
    try {
      kc.logout(c, tok, subject);
      sessionsEnded = true;
    } catch (err) {
      // Not fatal: re-entry is already denied by the role removal, which is the
      // property that matters. But it is not silently fine either — say so, so that
      // "sessions dead" is never claimed when it did not happen.
      sessionNote = "; sessions NOT ended: " + err;
    }
  } catch (err) {
    // The grant row is already gone and the realm still grants. Say so in the trail
    // rather than leaving a row that reads like an ordinary successful revoke.
    audit.set("detail", "FAILED: grant row removed but the identity provider still " +
                        "grants this app — reconcile will report it as MISSING: " + err);
    e.app.save(audit);
    return e.json(502, { message: "grant removed but the identity provider still has it: " + err });
  }

  audit.set("detail", (sessionsEnded ? "sessions ended" : "sessions NOT ended") + sessionNote);
  e.app.save(audit);

  return e.json(200, { ok: true, sessions_ended: sessionsEnded, note: sessionNote });
});

// ── offboard: one action, everything for one person ────────────────────────
routerAdd("POST", "/api/id-admin/offboard", (e) => {
  const g = require(__hooks + "/lib/guard.js");
  const kc = require(__hooks + "/lib/kc.js");
  const who = g.requireAdmin(e);
  if (!who) return e.json(403, { message: "admin on id-admin required" });

  const body = e.requestInfo().body || {};
  const subject = "" + (body.subject || "");
  if (!subject) return e.json(400, { message: "subject is required" });

  const rows = e.app.findAllRecords("grants", $dbx.exp("subject = {:s}", { s: subject }));
  const c = kc.cfg();
  const tok = kc.token(c);

  // Disable FIRST, then end the sessions, then unpick the grants.
  //
  // The order is the whole containment story. Disabling is the single act that stops
  // this person authenticating anywhere, so it goes first and is allowed to throw:
  // an offboard that cannot disable the account has not offboarded anyone, and must
  // say so before it starts deleting the records that show what they had. Ending
  // sessions before disabling would leave a window in which the still-enabled account
  // simply signs in again.
  kc.setEnabled(c, tok, subject, false);
  kc.logout(c, tok, subject);

  const removed = [];
  const failures = [];
  for (let i = 0; i < rows.length; i++) {
    const slug = rows[i].get("slug");
    let appRow = null;
    try {
      appRow = e.app.findFirstRecordByFilter("apps", "slug = {:s}", { s: slug });
    } catch (err) {
      // The app was deprovisioned; there is no realm client left to revoke on, and
      // the grant row should still go. This is the ONLY thing caught here.
      appRow = null;
    }
    if (appRow) {
      try {
        kc.revokeGrant(c, tok, subject, appRow);
      } catch (err) {
        // Keep the grant row: it is now the only record that this person still holds
        // access in the realm, and reconcile reads the table.
        failures.push(slug + " (" + err + ")");
        continue;
      }
    }
    e.app.delete(rows[i]);
    removed.push(slug);
  }

  const audit = new Record(e.app.findCollectionByNameOrId("audit"));
  audit.set("actor", who);
  audit.set("action", "offboard");
  audit.set("subject", subject);
  audit.set("detail", "account disabled; sessions ended; removed " + removed.length +
                      " grant(s): " + removed.join(", ") +
                      (failures.length ? "; FAILED to revoke: " + failures.join(", ") : ""));
  e.app.save(audit);

  if (failures.length) {
    return e.json(502, {
      message: "the account is disabled and its sessions are ended, but " +
               failures.length + " grant(s) could NOT be removed from the identity " +
               "provider — run reconcile: " + failures.join(", "),
      removed: removed, failed: failures,
    });
  }
  return e.json(200, { ok: true, removed: removed });
});

routerAdd("GET", "/api/id-admin/audit", (e) => {
  const g = require(__hooks + "/lib/guard.js");
  if (!g.requireAdmin(e)) return e.json(403, { message: "admin on id-admin required" });
  // Through the guarded route, like everything else: the collection's own rules are
  // null, so there is exactly one way to read this and one place the check lives.
  const rows = e.app.findRecordsByFilter("audit", "1 = 1", "-at", 300, 0);
  const out = [];
  for (let i = 0; i < rows.length; i++) {
    out.push({
      at: "" + rows[i].get("at"),
      action: rows[i].get("action"),
      actor: rows[i].get("actor"),
      subject: rows[i].get("subject"),
      slug: rows[i].get("slug"),
      role: rows[i].get("role"),
      detail: rows[i].get("detail"),
    });
  }
  return e.json(200, { entries: out });
});

// ── reconcile: the table is right, the realm is a cache ────────────────────
routerAdd("GET", "/api/id-admin/reconcile", (e) => {
  const g = require(__hooks + "/lib/guard.js");
  const rec = require(__hooks + "/lib/reconcile.js");
  // READ-ONLY drift, so the provisioning token is accepted here as well as an admin
  // grant — it lets the auth suite assert "drift = 0" on prod without a human session
  // (§9 asks for exactly that). The token means root on this box, who could read the
  // grants database directly anyway, so this discloses nothing new. REPAIRING is a
  // different matter and stays admin-only, below.
  const who = g.actor(e, true);
  if (!who) return e.json(403, { message: "admin on id-admin required" });
  return e.json(200, rec.run(e.app, false, who));
});

routerAdd("POST", "/api/id-admin/reconcile", (e) => {
  const g = require(__hooks + "/lib/guard.js");
  const rec = require(__hooks + "/lib/reconcile.js");
  const who = g.requireAdmin(e);
  if (!who) return e.json(403, { message: "admin on id-admin required" });
  return e.json(200, rec.run(e.app, true, who));
});
