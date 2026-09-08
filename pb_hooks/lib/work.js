/*
 * lib/work.js — one durable mutation workflow for the grants service.
 *
 * A route first commits desired state, an audit intent and a versioned work item in
 * one local transaction.  It then asks this module to sync that item to Keycloak.
 * Failed remote work remains retryable; a newer version cannot be overwritten by an
 * older in-flight request because only one worker owns a key and it loops to the
 * latest version before releasing it.
 */

function addAudit(app, values) {
  const row = new Record(app.findCollectionByNameOrId("audit"));
  row.set("actor", values.actor);
  row.set("action", values.action);
  if (values.subject) row.set("subject", values.subject);
  if (values.slug) row.set("slug", values.slug);
  if (values.role) row.set("role", values.role);
  if (values.detail) row.set("detail", values.detail);
  app.save(row);
}

function findWork(app, key) {
  try {
    return app.findFirstRecordByFilter("identity_work", "work_key = {:k}", { k: key });
  } catch (err) {
    return null;
  }
}

function putWork(app, values) {
  let row = findWork(app, values.key);
  if (!row) {
    row = new Record(app.findCollectionByNameOrId("identity_work"));
    row.set("work_key", values.key);
    row.set("version", 0);
    row.set("attempts", 0);
  }
  row.set("subject", values.subject);
  row.set("slug", values.slug || "");
  row.set("kind", values.kind);
  row.set("desired_role", values.desiredRole || "");
  row.set("end_sessions", !!values.endSessions);
  row.set("actor", values.actor);
  row.set("version", Number(row.get("version") || 0) + 1);
  // Do not release a running worker.  It will see the new version after its current
  // remote call and immediately converge the latest intent.  Starting a second
  // worker here is the race that versioning exists to prevent.
  if (row.get("status") !== "running") row.set("status", "pending");
  row.set("last_error", "");
  app.save(row);
  return { id: row.id, version: Number(row.get("version")) };
}

function grantKey(subject, slug) {
  return "grant|" + subject + "|" + slug;
}

function offboardKey(subject) {
  return "offboard|" + subject;
}

function hasOffboardIntent(app, subject) {
  return !!findWork(app, offboardKey(subject));
}

function claim(app, id) {
  let out = null;
  app.runInTransaction((tx) => {
    const row = tx.findRecordById("identity_work", id);
    if (row.get("status") === "running") {
      out = { busy: true, id: id };
      return;
    }
    if (row.get("status") === "succeeded") {
      out = { done: true, id: id };
      return;
    }
    row.set("status", "running");
    row.set("attempts", Number(row.get("attempts") || 0) + 1);
    tx.save(row);
    out = {
      id: row.id,
      version: Number(row.get("version")),
      key: row.get("work_key"),
      kind: row.get("kind"),
      subject: row.get("subject"),
      slug: row.get("slug"),
      desiredRole: row.get("desired_role") || null,
      endSessions: !!row.get("end_sessions"),
      actor: row.get("actor"),
    };
  });
  return out;
}

function execute(app, item) {
  const kc = require(__hooks + "/lib/kc.js");
  const c = kc.cfg();
  const tok = kc.token(c);

  if (item.kind === "grant") {
    const appRow = app.findFirstRecordByFilter("apps", "slug = {:s}", { s: item.slug });
    const endSessions = item.endSessions;
    if (item.desiredRole) {
      kc.applyGrant(c, tok, item.subject, appRow, item.desiredRole);
      // A newer grant may supersede a revoke while that revoke's logout is still
      // pending. Access follows the current grant, but the older session-termination
      // obligation must still be completed.
      if (endSessions) {
        try { kc.logout(c, tok, item.subject); }
        catch (err) { if (err.statusCode !== 404) throw err; }
      }
    } else {
      // A 404 on cleanup means the subject or client no longer exists, so the
      // requested access/session is already absent. Every other provider error is a
      // real failure and remains retryable.
      try { kc.revokeGrant(c, tok, item.subject, appRow); }
      catch (err) { if (err.statusCode !== 404) throw err; }
      if (endSessions) {
        try { kc.logout(c, tok, item.subject); }
        catch (err) { if (err.statusCode !== 404) throw err; }
      }
    }
    return item.desiredRole ?
      (endSessions ? "grant applied and prior sessions ended" : "grant applied") :
      (endSessions ? "grant removed and sessions ended" : "grant removed");
  }

  if (item.kind === "offboard") {
    const failures = [];
    try { kc.setEnabled(c, tok, item.subject, false); }
    catch (err) { if (err.statusCode !== 404) failures.push("disable: " + err); }

    try { kc.logout(c, tok, item.subject); }
    catch (err) { if (err.statusCode !== 404) failures.push("logout: " + err); }

    if (failures.length) throw new Error(failures.join("; "));
    return "account disabled and sessions ended";
  }

  throw new Error("unknown identity work kind: " + item.kind);
}

function finish(app, item, error, detail) {
  let retry = false;
  app.runInTransaction((tx) => {
    const row = tx.findRecordById("identity_work", item.id);
    const current = Number(row.get("version"));
    if (current !== item.version) {
      row.set("status", "pending");
      row.set("last_error", "");
      tx.save(row);
      addAudit(tx, {
        actor: item.actor,
        action: "provider.sync.superseded",
        subject: item.subject,
        slug: item.slug,
        role: item.desiredRole,
        detail: "version " + item.version + " completed after version " + current + " was queued",
      });
      retry = true;
      return;
    }

    row.set("status", error ? "failed" : "succeeded");
    row.set("last_error", error ? ("" + error).slice(0, 2000) : "");
    tx.save(row);
    addAudit(tx, {
      actor: item.actor,
      action: error ? "provider.sync.failed" : "provider.sync.succeeded",
      subject: item.subject,
      slug: item.slug,
      role: item.desiredRole,
      detail: error ? ("" + error).slice(0, 2000) : detail,
    });
  });
  return retry;
}

module.exports = {
  setGrant(app, values) {
    let queued = null;
    app.runInTransaction((tx) => {
      // Keep the offboard check in the same transaction as desired state. Checking
      // before opening it leaves a race where offboard commits, then this request
      // recreates the grant immediately afterwards.
      if (values.role && hasOffboardIntent(tx, values.subject)) {
        throw new BadRequestError("this identity has been offboarded and cannot receive a grant");
      }

      let row = null;
      try {
        row = tx.findFirstRecordByFilter(
          "grants",
          "subject = {:s} && slug = {:g}",
          { s: values.subject, g: values.slug },
        );
      } catch (err) { /* absent */ }

      let action = values.action || (row ? "grant.change" : "grant.create");
      if (values.role) {
        if (!row) {
          row = new Record(tx.findCollectionByNameOrId("grants"));
          row.set("subject", values.subject);
          row.set("slug", values.slug);
        }
        row.set("role", values.role);
        row.set("granted_by", values.actor);
        if (values.person) row.set("person", values.person);
        tx.save(row);
      } else if (row) {
        tx.delete(row);
      }

      const currentWork = findWork(tx, grantKey(values.subject, values.slug));
      const preserveLogout = !!(currentWork && currentWork.get("status") !== "succeeded" &&
        currentWork.get("end_sessions"));

      addAudit(tx, {
        actor: values.actor,
        action: action,
        subject: values.subject,
        slug: values.slug,
        role: values.role,
        detail: "desired state committed; provider sync queued",
      });
      queued = putWork(tx, {
        key: grantKey(values.subject, values.slug),
        kind: "grant",
        subject: values.subject,
        slug: values.slug,
        desiredRole: values.role,
        endSessions: !!values.endSessions || preserveLogout,
        actor: values.actor,
      });
    });
    return queued;
  },

  syncGrant(app, values) {
    let queued = null;
    app.runInTransaction((tx) => {
      // Reconcile's provider/table snapshot may already be stale. Desired state is
      // resolved again under the same transaction that
      // versions the work item, so reconciliation can never turn historical state
      // into a newer grant after revoke or offboard has committed.
      let desiredRole = null;
      if (!hasOffboardIntent(tx, values.subject)) {
        try {
          desiredRole = tx.findFirstRecordByFilter(
            "grants",
            "subject = {:s} && slug = {:g}",
            { s: values.subject, g: values.slug },
          ).get("role") || null;
        } catch (err) { /* no current grant */ }
      }

      // Do not erase a revoke's still-unfinished logout when reconciliation versions
      // the same person/app key. If access was granted again, apply that current grant
      // and then end the older sessions.
      const currentWork = findWork(tx, grantKey(values.subject, values.slug));
      const preserveLogout = !!(currentWork && currentWork.get("status") !== "succeeded" &&
        currentWork.get("end_sessions"));
      addAudit(tx, {
        actor: values.actor,
        action: "reconcile.sync.intent",
        subject: values.subject,
        slug: values.slug,
        role: desiredRole,
        detail: "provider drift found; current desired state resolved and sync queued",
      });
      queued = putWork(tx, {
        key: grantKey(values.subject, values.slug),
        kind: "grant",
        subject: values.subject,
        slug: values.slug,
        desiredRole: desiredRole,
        endSessions: preserveLogout,
        actor: values.actor,
      });
    });
    return queued;
  },

  offboard(app, values) {
    let queued = null;
    app.runInTransaction((tx) => {
      const rows = tx.findAllRecords("grants", $dbx.exp("subject = {:s}", { s: values.subject }));
      const slugs = [];
      const grantWorkIds = [];
      for (let i = 0; i < rows.length; i++) {
        slugs.push(rows[i].get("slug"));
        tx.delete(rows[i]);
      }
      // Revoke every registered app, not only rows that happened to exist locally.
      // This also removes pre-existing realm drift while the person is being
      // offboarded, rather than leaving it for a later reconciliation run.
      const apps = tx.findAllRecords("apps");
      for (let i = 0; i < apps.length; i++) {
        const slug = apps[i].get("slug");
        // Version the same per-subject/app key used by grants. If an older grant is
        // already in flight its worker will see this newer revoke before releasing
        // the key, so it cannot finish last and restore access after offboarding.
        grantWorkIds.push(putWork(tx, {
          key: grantKey(values.subject, slug),
          kind: "grant",
          subject: values.subject,
          slug: slug,
          desiredRole: null,
          endSessions: false,
          actor: values.actor,
        }).id);
      }
      addAudit(tx, {
        actor: values.actor,
        action: "offboard",
        subject: values.subject,
        detail: "offboarding intent committed; " + slugs.length + " local grant(s) removed and " +
                apps.length + " registered app(s) queued for provider cleanup",
      });
      queued = putWork(tx, {
        key: offboardKey(values.subject),
        kind: "offboard",
        subject: values.subject,
        endSessions: false,
        actor: values.actor,
      });
      queued.slugs = slugs;
      queued.grantWorkIds = grantWorkIds;
    });
    return queued;
  },

  process(app, id) {
    // In ordinary use this loops at most twice: once for the claimed version and once
    // for a newer intent that arrived while the provider call was in flight.
    for (let i = 0; i < 20; i++) {
      const item = claim(app, id);
      if (item.busy) return { ok: false, pending: true, id: id };
      if (item.done) return { ok: true, id: id, alreadyDone: true };
      let error = null;
      let detail = "";
      try { detail = execute(app, item); }
      catch (err) { error = err; }
      if (finish(app, item, error, detail)) continue;
      return {
        ok: !error,
        id: id,
        version: item.version,
        kind: item.kind,
        desiredRole: item.desiredRole,
        error: error ? ("" + error) : null,
        detail: detail,
      };
    }
    return { ok: false, id: id, error: "provider sync changed too often; retry through reconcile" };
  },

  unfinished(app) {
    const rows = app.findRecordsByFilter(
      "identity_work",
      "status != 'succeeded' && status != 'running'",
      "+created",
      500,
      0,
    );
    // Retrying an offboard always disables/logs out before its per-app revokes.
    rows.sort((a, b) => {
      if (a.get("kind") === b.get("kind")) return 0;
      return a.get("kind") === "offboard" ? -1 : 1;
    });
    return rows;
  },

  outstanding(app) {
    return app.findRecordsByFilter(
      "identity_work",
      "status != 'succeeded'",
      "+created",
      500,
      0,
    );
  },

  recoverInterrupted(app) {
    const rows = app.findAllRecords("identity_work", $dbx.exp("status = 'running'"));
    for (let i = 0; i < rows.length; i++) {
      rows[i].set("status", "failed");
      rows[i].set("last_error", "server stopped while provider sync was running; safe to retry");
      app.save(rows[i]);
    }
    return rows.length;
  },

  removeOrphan(app, grant, actor) {
    app.runInTransaction((tx) => {
      const row = tx.findRecordById("grants", grant.id);
      tx.delete(row);
      const providerWork = findWork(tx, grantKey(grant.get("subject"), grant.get("slug")));
      if (providerWork) tx.delete(providerWork);
      addAudit(tx, {
        actor: actor,
        action: "reconcile.orphan.remove",
        subject: grant.get("subject"),
        slug: grant.get("slug"),
        role: grant.get("role"),
        detail: "grant removed because the canonical subject no longer exists",
      });
    });
  },

  removeAbsentSubject(app, subject, actor) {
    app.runInTransaction((tx) => {
      const grants = tx.findAllRecords("grants", $dbx.exp("subject = {:s}", { s: subject }));
      const rows = tx.findAllRecords("identity_work", $dbx.exp("subject = {:s}", { s: subject }));
      for (let i = 0; i < grants.length; i++) tx.delete(grants[i]);
      for (let i = 0; i < rows.length; i++) tx.delete(rows[i]);
      addAudit(tx, {
        actor: actor,
        action: "reconcile.absent-subject.remove",
        subject: subject,
        detail: "removed " + grants.length + " grant(s) and " + rows.length +
                " provider work item(s) for an identity absent from the realm",
      });
    });
  },
};
