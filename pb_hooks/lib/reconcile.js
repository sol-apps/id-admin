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
 * The cost of that is an O(apps x people) walk of admin calls inside one request, and
 * it is a DIRECT consequence of the grants service not holding view-clients: with it,
 * one call per app would list that client's role members and this would be O(apps).
 * That trade — no ability to read any app's client secret, in exchange for a reconcile
 * that walks — is deliberate and worth naming rather than discovering at four hundred
 * users. It is fine for a realm of tens and it is not a supportable online operation
 * for a realm of thousands; at that size this becomes a background job that writes its
 * findings to a collection, and lib/kc.js refuses outright past 5000 people rather
 * than returning a partial answer that reads as clean.
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

    const drift = [];
    for (let a = 0; a < apps.length; a++) {
      const appRow = apps[a];
      const slug = appRow.get("slug");
      for (let p = 0; p < people.length; p++) {
        const subject = people[p].subject;
        let held;
        try {
          held = kc.rolesHeld(c, tok, subject, appRow.get("client_uuid"));
        } catch (err) {
          // Unreadable is not "no drift": it means this person's access to this app
          // could not be established either way, which the caller must see.
          drift.push({ kind: "unreadable", slug: slug, subject: subject,
                       person: people[p].name, table: want[subject + "|" + slug] || null,
                       realm: null, detail: "" + err });
          continue;
        }
        const hasAccess = held.indexOf("restricted-access") !== -1;
        const hasAdmin = held.indexOf("app-admin") !== -1;
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
