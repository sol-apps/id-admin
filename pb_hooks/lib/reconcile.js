/*
 * lib/reconcile.js — diff the grant table against the realm, and optionally repair it.
 *
 * The table is the source of truth; the realm is a cache of it. Two kinds of drift
 * matter, and they are not symmetrical:
 *
 *   MISSING  a grant exists in the table but not in the realm — someone cannot get
 *            into an app they were granted. Annoying, visible, self-reporting.
 *   EXTRA    a role mapping exists in the realm with no grant behind it — someone can
 *            get into an app nobody granted them. That is the one that matters, and
 *            it is invisible from inside the app, because from the app's side such a
 *            person looks exactly like a legitimate user.
 *
 * So the check enumerates the realm rather than only walking the table: walking the
 * table alone can only ever find MISSING.
 *
 *   ORPHAN   a grant row naming a subject the realm no longer has. Neither of the
 *            above finds it — the apps x people walk never visits a person who does
 *            not exist — so it is looked for separately, after.
 *
 * The cost used to be an O(apps x people) walk of admin calls inside one request,
 * because role mappings were read one client at a time. They are not: a single
 * GET /users/{id}/role-mappings returns every client mapping for a person, WITH the
 * client uuid, and the service account's two roles are enough to call it (probed).
 * So this is one admin call per person, and the apps are matched in memory.
 *
 * That also closes a gap the per-app walk could not see. Asking "does this person hold
 * app X's role" can only ever find drift about apps we already know about; reading
 * everything they hold surfaces a client that grants access and was never registered
 * with the grants service at all.
 */
module.exports = {
  run(app, repair, actor) {
    const kc = require(__hooks + "/lib/kc.js");
    const c = kc.cfg();
    const tok = kc.token(c);

    const apps = app.findAllRecords("apps");
    const grants = app.findAllRecords("grants");
    const people = kc.people(c, tok);

    // table: "subject|slug" -> role
    const want = {};
    for (let i = 0; i < grants.length; i++) {
      want[grants[i].get("subject") + "|" + grants[i].get("slug")] = grants[i].get("role");
    }

    // uuid -> the app row, so a mapping can be matched back without view-clients.
    const byUuid = {};
    for (let a = 0; a < apps.length; a++) byUuid[apps[a].get("client_uuid")] = apps[a];

    const drift = [];
    for (let p = 0; p < people.length; p++) {
      const subject = people[p].subject;
      let held;
      try {
        held = kc.allRolesHeld(c, tok, subject);
      } catch (err) {
        // Unreadable is not "no drift": this person's access could not be established
        // either way, for any app, which the caller must see.
        drift.push({ kind: "unreadable", slug: "(all)", subject: subject,
                     person: people[p].name, table: null, realm: null,
                     detail: "" + err });
        continue;
      }

      for (let a = 0; a < apps.length; a++) {
        const appRow = apps[a];
        const slug = appRow.get("slug");
        const entry = held[appRow.get("client_uuid")] || { roles: [] };
        const hasAccess = entry.roles.indexOf("restricted-access") !== -1;
        const hasAdmin = entry.roles.indexOf("app-admin") !== -1;
        const realmRole = hasAccess ? (hasAdmin ? "admin" : "user") : null;
        const tableRole = want[subject + "|" + slug] || null;
        if (realmRole === tableRole) continue;

        const item = {
          slug: slug, subject: subject, person: people[p].name,
          table: tableRole, realm: realmRole,
          kind: tableRole === null ? "extra" : (realmRole === null ? "missing" : "role-mismatch"),
        };
        if (repair) {
          // repaired reflects what happened, not what was attempted. Reporting a
          // repair that did not occur is worse than reporting the drift: the drift
          // is at least still on screen next time, whereas a false "repaired" closes
          // the one check built to notice that someone can enter an app nobody
          // granted them.
          try {
            if (tableRole === null) {
              kc.revokeGrant(c, tok, subject, appRow);
            } else {
              kc.applyGrant(c, tok, subject, appRow, tableRole);
            }
            item.repaired = true;
          } catch (err) {
            item.repaired = false;
            item.error = "" + err;
          }
        }
        drift.push(item);
      }

      // A client that grants this person access but is not in the apps table at all.
      // Nothing else looks for it: the walk above only asks about apps we know about,
      // so a client created by hand — or one left behind by a deprovision that did not
      // finish — hands out access no grant backs and no check would mention it.
      for (const uuid in held) {
        if (!Object.prototype.hasOwnProperty.call(held, uuid)) continue;
        if (byUuid[uuid]) continue;
        if (held[uuid].roles.indexOf("restricted-access") === -1) continue;
        drift.push({
          kind: "unregistered", slug: held[uuid].clientId, subject: subject,
          person: people[p].name, table: null, realm: "user",
          detail: "this client grants access and is not registered with the grants service",
        });
      }
    }

    // A grant whose subject is no longer in the realm is invisible to the walk above:
    // that walk is apps x PEOPLE, so a row naming someone who has been deleted is
    // never visited by it and reads as "no drift". It is not access — the person is
    // gone — but it is a grant table that disagrees with reality, and it is the shape
    // a slug reuse or a hand-deleted user leaves behind.
    const known = {};
    for (let p = 0; p < people.length; p++) known[people[p].subject] = true;
    for (let i = 0; i < grants.length; i++) {
      const subject = grants[i].get("subject");
      if (known[subject]) continue;
      const item = {
        slug: grants[i].get("slug"), subject: subject,
        person: "(no such person in the realm)",
        table: grants[i].get("role"), realm: null, kind: "orphan",
      };
      if (repair) {
        // The realm side cannot be repaired — there is nobody to assign a role to —
        // so repairing means removing the row that outlived its person.
        try {
          app.delete(grants[i]);
          item.repaired = true;
        } catch (err) {
          item.repaired = false;
          item.error = "" + err;
        }
      }
      drift.push(item);
    }

    let failed = 0;
    for (let i = 0; i < drift.length; i++) {
      if (drift[i].repaired === false) failed++;
    }

    if (repair && drift.length) {
      const audit = new Record(app.findCollectionByNameOrId("audit"));
      audit.set("actor", actor);
      audit.set("action", "reconcile.repair");
      audit.set("detail", "repaired " + (drift.length - failed) + " of " +
                          drift.length + " difference(s)" +
                          (failed ? "; " + failed + " FAILED" : ""));
      app.save(audit);
    }

    return {
      apps: apps.length,
      people: people.length,
      grants: grants.length,
      drift: drift,
      clean: drift.length === 0,
      repaired: !!repair,
      failed: failed,
    };
  },
};
