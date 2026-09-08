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
 * The grant table is the source of truth. Keycloak is a cache of it. Every identity
 * mutation goes through lib/work.js: desired state, audit intent and versioned work
 * commit together, then one retryable path pushes the latest version to the realm.
 */

// A process can stop after claiming work and before recording its outcome.  On the
// next boot make those items retryable; no remote operation here is non-idempotent.
onBootstrap((e) => {
  e.next();
  const work = require(__hooks + "/lib/work.js");
  try {
    const recovered = work.recoverInterrupted(e.app);
    if (recovered) console.log("[identity-work] recovered " + recovered + " interrupted item(s)");
  } catch (err) {
    // On a brand-new database custom migrations run after this bootstrap hook. The
    // collection will exist on the next start; there cannot be interrupted work yet.
    console.log("[identity-work] recovery deferred until the work collection exists");
  }
});

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

  e.app.runInTransaction((tx) => {
    let row;
    try {
      row = tx.findFirstRecordByFilter("apps", "slug = {:s}", { s: slug });
    } catch (err) {
      row = new Record(tx.findCollectionByNameOrId("apps"));
    }
    row.set("slug", slug);
    row.set("client_uuid", "" + body.client_uuid);
    row.set("role_restricted_id", "" + restricted.id);
    row.set("role_admin_id", "" + appAdmin.id);
    tx.save(row);

    const audit = new Record(tx.findCollectionByNameOrId("audit"));
    audit.set("actor", "provisioning");
    audit.set("action", "app.register");
    audit.set("slug", slug);
    audit.set("detail", "client " + body.client_uuid);
    tx.save(audit);
  });

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

  let removed = 0;
  let cancelled = 0;
  let hadApp = false;
  e.app.runInTransaction((tx) => {
    const grants = tx.findAllRecords("grants", $dbx.exp("slug = {:s}", { s: slug }));
    removed = grants.length;
    for (let i = 0; i < grants.length; i++) tx.delete(grants[i]);
    // deprovision-app deletes the Keycloak client before calling here. Discard any
    // old provider intent as part of forgetting the slug, or a pending grant could be
    // retried after the slug is reused and give the new app access nobody granted.
    const workRows = tx.findAllRecords("identity_work", $dbx.exp("slug = {:s}", { s: slug }));
    cancelled = workRows.length;
    for (let i = 0; i < workRows.length; i++) tx.delete(workRows[i]);
    try {
      tx.delete(tx.findFirstRecordByFilter("apps", "slug = {:s}", { s: slug }));
      hadApp = true;
    } catch (err) { /* never registered, or already gone */ }

    const audit = new Record(tx.findCollectionByNameOrId("audit"));
    audit.set("actor", "provisioning");
    audit.set("action", "app.deregister");
    audit.set("slug", slug);
    audit.set("detail", "removed " + removed + " grant(s) and " + cancelled +
                        " provider work item(s)" +
                        (hadApp ? " and the app registration" : " (app was not registered)"));
    tx.save(audit);
  });

  return e.json(200, {
    ok: true,
    slug: slug,
    grants_removed: removed,
    work_cancelled: cancelled,
  });
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
  const work = require(__hooks + "/lib/work.js");
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

  try {
    e.app.findFirstRecordByFilter("apps", "slug = {:s}", { s: slug });
  } catch (err) {
    return e.json(404, { message: "no such app: " + slug + " (has it been provisioned?)" });
  }

  const queued = work.setGrant(e.app, {
    subject: subject,
    slug: slug,
    role: role,
    person: body.person ? ("" + body.person) : "",
    actor: who,
  });
  const synced = work.process(e.app, queued.id);
  if (!synced.ok) {
    return e.json(502, {
      message: "grant recorded but NOT applied to the identity provider: " +
               (synced.error || "provider sync is already running"),
      recorded: true,
      work_id: queued.id,
    });
  }
  if (synced.version !== queued.version) {
    return e.json(409, {
      message: "this grant was superseded by a newer identity change",
      recorded: true,
      work_id: queued.id,
    });
  }
  const row = e.app.findFirstRecordByFilter("grants", "subject = {:s} && slug = {:g}",
                                            { s: subject, g: slug });
  return e.json(200, { ok: true, id: row.id, role: role, work_id: queued.id });
});

routerAdd("POST", "/api/id-admin/revoke", (e) => {
  const g = require(__hooks + "/lib/guard.js");
  const work = require(__hooks + "/lib/work.js");
  // Token allowed here, exactly as it is on POST /grants: the same root-on-the-box
  // caller that can create a grant can withdraw one, and the proof script needs to
  // leave the realm as it found it through the audited path rather than behind it.
  const who = g.actor(e, true);
  if (!who) return e.json(403, { message: "admin on id-admin required" });

  const body = e.requestInfo().body || {};
  const subject = "" + (body.subject || "");
  const slug = "" + (body.slug || "");
  if (!subject || !slug) return e.json(400, { message: "subject and slug are required" });

  try {
    e.app.findFirstRecordByFilter("apps", "slug = {:s}", { s: slug });
  } catch (err) {
    return e.json(404, { message: "no such app: " + slug });
  }
  const queued = work.setGrant(e.app, {
    subject: subject,
    slug: slug,
    role: null,
    actor: who,
    action: "grant.revoke",
    endSessions: true,
  });
  const synced = work.process(e.app, queued.id);
  if (!synced.ok) {
    return e.json(502, {
      message: "revocation recorded but provider cleanup is still pending: " +
               (synced.error || "provider sync is already running"),
      recorded: true,
      work_id: queued.id,
      sessions_ended: false,
    });
  }
  if (synced.version !== queued.version) {
    return e.json(409, {
      message: "this revocation was superseded by a newer identity change",
      recorded: true,
      work_id: queued.id,
      sessions_ended: false,
    });
  }
  return e.json(200, { ok: true, sessions_ended: true, work_id: queued.id });
});

// ── offboard: one action, everything for one person ────────────────────────
routerAdd("POST", "/api/id-admin/offboard", (e) => {
  const g = require(__hooks + "/lib/guard.js");
  const work = require(__hooks + "/lib/work.js");
  const who = g.requireAdmin(e);
  if (!who) return e.json(403, { message: "admin on id-admin required" });

  const body = e.requestInfo().body || {};
  const subject = "" + (body.subject || "");
  if (!subject) return e.json(400, { message: "subject is required" });

  const queued = work.offboard(e.app, { subject: subject, actor: who });
  const results = [work.process(e.app, queued.id)];
  for (let i = 0; i < queued.grantWorkIds.length; i++) {
    results.push(work.process(e.app, queued.grantWorkIds[i]));
  }
  const failures = results.filter((result) => !result.ok);
  if (failures.length) {
    return e.json(502, {
      message: "offboarding intent is recorded but provider cleanup is still pending: " +
               (failures[0].error || "provider sync is already running") +
               "; run reconcile to retry",
      recorded: true,
      work_id: queued.id,
      removed: queued.slugs,
    });
  }
  return e.json(200, { ok: true, removed: queued.slugs, work_id: queued.id });
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
