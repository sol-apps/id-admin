/*
 * lib/reconcile.js — compare desired grants with EFFECTIVE provider access.
 *
 * Direct mappings are still read in one call per person. Each registered app also
 * gets an effective-role read so access inherited through a group or composite is a
 * visible, unresolved finding instead of a false clean result. Greenlight prohibits
 * inherited governed-app roles; removing their source is an operator action because
 * this service cannot safely guess which group/composite to edit.
 */

function roleFrom(names) {
  const access = names.indexOf("restricted-access") !== -1;
  const admin = names.indexOf("app-admin") !== -1;
  if (admin && !access) return "app-admin-only";
  return access ? (admin ? "admin" : "user") : null;
}

function inspect(app, kc, c, tok) {
  const apps = app.findAllRecords("apps");
  const grants = app.findAllRecords("grants");
  const people = kc.people(c, tok);
  const want = {};
  for (let i = 0; i < grants.length; i++) {
    want[grants[i].get("subject") + "|" + grants[i].get("slug")] = grants[i].get("role");
  }

  const byUuid = {};
  for (let i = 0; i < apps.length; i++) byUuid[apps[i].get("client_uuid")] = apps[i];

  const drift = [];
  for (let p = 0; p < people.length; p++) {
    const subject = people[p].subject;
    let direct;
    try {
      direct = kc.allRolesHeld(c, tok, subject);
    } catch (err) {
      drift.push({
        kind: "unreadable", slug: "(all)", subject: subject,
        person: people[p].name, table: null, realm: null, repairable: false,
        detail: "" + err,
      });
      continue;
    }

    for (let a = 0; a < apps.length; a++) {
      const appRow = apps[a];
      const slug = appRow.get("slug");
      const directNames = (direct[appRow.get("client_uuid")] || { roles: [] }).roles;
      let effectiveNames;
      try {
        effectiveNames = kc.effectiveRolesHeld(c, tok, subject, appRow);
      } catch (err) {
        drift.push({
          kind: "unreadable", slug: slug, subject: subject,
          person: people[p].name, table: want[subject + "|" + slug] || null,
          realm: null, repairable: false, detail: "" + err,
        });
        continue;
      }

      const directRole = roleFrom(directNames);
      const effectiveRole = roleFrom(effectiveNames);
      const tableRole = want[subject + "|" + slug] || null;
      const inheritedAccess = effectiveNames.indexOf("restricted-access") !== -1 &&
                              directNames.indexOf("restricted-access") === -1;
      const inheritedAdmin = effectiveNames.indexOf("app-admin") !== -1 &&
                             directNames.indexOf("app-admin") === -1;

      if (inheritedAccess || inheritedAdmin) {
        drift.push({
          kind: "inherited", slug: slug, subject: subject, person: people[p].name,
          table: tableRole, realm: effectiveRole, direct: directRole, repairable: false,
          detail: "governed app role inherited through a group or composite; remove it at its source",
        });
        continue;
      }
      if (effectiveRole === tableRole) continue;

      drift.push({
        slug: slug, subject: subject, person: people[p].name,
        table: tableRole, realm: effectiveRole, direct: directRole, repairable: true,
        kind: tableRole === null ? "extra" :
              (effectiveRole === null ? "missing" : "role-mismatch"),
      });
    }

    // Unknown clients are visible only when the mapping is direct. The service
    // account intentionally cannot enumerate clients, because view-clients also
    // exposes every app secret. Registered apps above cover inherited access where
    // the platform has declared the client to be governed.
    for (const uuid in direct) {
      if (!Object.prototype.hasOwnProperty.call(direct, uuid) || byUuid[uuid]) continue;
      if (direct[uuid].roles.indexOf("restricted-access") === -1 &&
          direct[uuid].roles.indexOf("app-admin") === -1) continue;
      drift.push({
        kind: "unregistered", slug: direct[uuid].clientId, subject: subject,
        person: people[p].name, table: null, realm: roleFrom(direct[uuid].roles),
        repairable: false,
        detail: "this client grants direct access and is not registered with the grants service",
      });
    }
  }

  const known = {};
  for (let i = 0; i < people.length; i++) known[people[i].subject] = true;
  for (let i = 0; i < grants.length; i++) {
    const subject = grants[i].get("subject");
    if (known[subject]) continue;
    drift.push({
      kind: "orphan", slug: grants[i].get("slug"), subject: subject,
      person: "(no such person in the realm)", table: grants[i].get("role"),
      realm: null, repairable: true, grantId: grants[i].id,
    });
  }

  return { apps: apps, grants: grants, people: people, drift: drift };
}

function auditSummary(app, actor, attempted, succeeded, failed, unresolved) {
  const audit = new Record(app.findCollectionByNameOrId("audit"));
  audit.set("actor", actor);
  audit.set("action", "reconcile.repair");
  audit.set("detail", "attempted " + attempted + "; succeeded " + succeeded +
                      "; failed " + failed + "; unresolved " + unresolved);
  app.save(audit);
}

function workSummary(rows) {
  const out = [];
  for (let i = 0; i < rows.length; i++) {
    out.push({
      kind: rows[i].get("kind"),
      subject: rows[i].get("subject"),
      slug: rows[i].get("slug"),
      status: rows[i].get("status"),
      error: rows[i].get("last_error") || null,
    });
  }
  return out;
}

module.exports = {
  run(app, repair, actor) {
    const kc = require(__hooks + "/lib/kc.js");
    const work = require(__hooks + "/lib/work.js");
    const c = kc.cfg();
    const tok = kc.token(c);
    const before = inspect(app, kc, c, tok);

    if (!repair) {
      const openWork = work.outstanding(app);
      return {
        apps: before.apps.length,
        people: before.people.length,
        grants: before.grants.length,
        drift: before.drift,
        clean: before.drift.length === 0 && openWork.length === 0,
        attempted: 0,
        succeeded: 0,
        failed: 0,
        unresolved: before.drift.length + openWork.length,
        drift_unresolved: before.drift.length,
        work_unresolved: openWork.length,
        work: workSummary(openWork),
      };
    }

    let attempted = 0;
    let succeeded = 0;
    let failed = 0;
    const outcomes = [];
    const processed = {};
    const knownSubjects = {};
    const absentSubjects = {};
    for (let i = 0; i < before.people.length; i++) {
      knownSubjects[before.people[i].subject] = true;
    }

    // Retry durable work first. This is what lets reconciliation finish an
    // offboarding whose disable, logout or one role removal previously failed.
    const pending = work.unfinished(app);
    for (let i = 0; i < pending.length; i++) {
      attempted++;
      processed[pending[i].get("work_key")] = true;
      if (!knownSubjects[pending[i].get("subject")]) {
        const subject = pending[i].get("subject");
        work.removeAbsentSubject(app, subject, actor);
        absentSubjects[subject] = true;
        succeeded++;
        outcomes.push({
          kind: "absent-subject", subject: subject, slug: pending[i].get("slug"),
          attempted: true, repaired: true,
        });
        continue;
      }
      const out = work.process(app, pending[i].id);
      if (out.ok) succeeded++; else failed++;
      outcomes.push({
        kind: "queued", subject: pending[i].get("subject"), slug: pending[i].get("slug"),
        attempted: true, repaired: !!out.ok, error: out.error || null,
      });
    }

    for (let i = 0; i < before.drift.length; i++) {
      const item = before.drift[i];
      if (absentSubjects[item.subject]) continue;
      if (!item.repairable) {
        outcomes.push({
          kind: item.kind, subject: item.subject, slug: item.slug,
          attempted: false, repaired: false, error: item.detail || "operator action required",
        });
        continue;
      }

      if (item.kind === "orphan") {
        attempted++;
        try {
          const grant = app.findRecordById("grants", item.grantId);
          work.removeOrphan(app, grant, actor);
          succeeded++;
          outcomes.push({
            kind: item.kind, subject: item.subject, slug: item.slug,
            attempted: true, repaired: true,
          });
        } catch (err) {
          failed++;
          outcomes.push({
            kind: item.kind, subject: item.subject, slug: item.slug,
            attempted: true, repaired: false, error: "" + err,
          });
        }
        continue;
      }

      const key = "grant|" + item.subject + "|" + item.slug;
      if (processed[key]) continue;
      attempted++;
      const queued = work.syncGrant(app, {
        subject: item.subject,
        slug: item.slug,
        actor: actor,
      });
      const out = work.process(app, queued.id);
      if (out.ok) succeeded++; else failed++;
      outcomes.push({
        kind: item.kind, subject: item.subject, slug: item.slug,
        attempted: true, repaired: !!out.ok, error: out.error || null,
      });
    }

    // Never claim success from attempted writes. Read effective access again and
    // derive clean/unresolved from what the provider now says.
    const after = inspect(app, kc, c, tok);
    const remainingWork = work.outstanding(app);
    const unresolved = after.drift.length + remainingWork.length;
    auditSummary(app, actor, attempted, succeeded, failed, unresolved);
    return {
      apps: after.apps.length,
      people: after.people.length,
      grants: after.grants.length,
      drift: after.drift,
      items: outcomes,
      clean: unresolved === 0 && failed === 0,
      attempted: attempted,
      succeeded: succeeded,
      failed: failed,
      unresolved: unresolved,
      drift_unresolved: after.drift.length,
      work_unresolved: remainingWork.length,
      work: workSummary(remainingWork),
    };
  },
};
