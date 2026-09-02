/// <reference path="../pb_data/types.d.ts" />
/*
 * The grant table. THIS is the source of truth for who may use which app; the realm
 * is a cache of it, and the reconcile job exists to say so out loud when they differ.
 *
 * Every collection here is superuser-only at the rules level (all rules null). Nothing
 * reaches these records through the generic collections API — the admin screen goes
 * through /api/id-admin/*, which checks that the caller holds admin on this app before
 * it does anything. One place to get the permission check right beats five rule
 * expressions that have to agree with each other.
 */
migrate((app) => {
  // ── apps ──────────────────────────────────────────────────────────────────
  // Written by provisioning (provision-app → POST /api/id-admin/apps), never by a
  // person. It holds the client uuid and role ids that the grants service needs to
  // write a role mapping and deliberately cannot look up for itself: its Keycloak
  // service account holds view-users and manage-users only, because the role that
  // would let it resolve clients (view-clients) would also let it read every app's
  // OIDC client secret.
  const apps = new Collection({
    type: "base",
    name: "apps",
    listRule: null, viewRule: null, createRule: null, updateRule: null, deleteRule: null,
    fields: [
      { type: "text", name: "slug", required: true, max: 28 },
      { type: "text", name: "client_uuid", required: true },
      { type: "text", name: "role_restricted_id", required: true },
      { type: "text", name: "role_admin_id", required: true },
      { type: "autodate", name: "created", onCreate: true },
      { type: "autodate", name: "updated", onCreate: true, onUpdate: true },
    ],
    indexes: ["CREATE UNIQUE INDEX `idx_apps_slug` ON `apps` (`slug`)"],
  });
  app.save(apps);

  // ── grants ────────────────────────────────────────────────────────────────
  const grants = new Collection({
    type: "base",
    name: "grants",
    listRule: null, viewRule: null, createRule: null, updateRule: null, deleteRule: null,
    fields: [
      // The CANONICAL Keycloak user id, never the email. Email is display data that
      // changes; this is the identifier every later thing keys on — the audit trail,
      // and (phase 3) per-user connection tokens. It also survives the realm being
      // pointed at a customer's own directory, which is the whole reason for choosing
      // it now rather than when that happens.
      { type: "text", name: "subject", required: true },
      { type: "text", name: "slug", required: true, max: 28 },
      { type: "select", name: "role", required: true, maxSelect: 1, values: ["user", "admin"] },
      // Display cache so the screen and the audit trail stay readable after someone
      // is deleted from the directory. Never used to identify anyone.
      { type: "text", name: "person", max: 200 },
      { type: "text", name: "granted_by", required: true },
      { type: "autodate", name: "created", onCreate: true },
      { type: "autodate", name: "updated", onCreate: true, onUpdate: true },
    ],
    indexes: ["CREATE UNIQUE INDEX `idx_grants_subject_slug` ON `grants` (`subject`, `slug`)"],
  });
  app.save(grants);

  // ── audit ─────────────────────────────────────────────────────────────────
  // Append-only by construction: nothing in this service updates or deletes an audit
  // row, and the rules refuse everyone anyway. A grant that changed without a row
  // here is a bug, and the reconcile job is what would notice.
  const audit = new Collection({
    type: "base",
    name: "audit",
    listRule: null, viewRule: null, createRule: null, updateRule: null, deleteRule: null,
    fields: [
      { type: "text", name: "actor", required: true },
      { type: "text", name: "action", required: true },
      { type: "text", name: "subject" },
      { type: "text", name: "slug", max: 28 },
      { type: "text", name: "role" },
      { type: "text", name: "detail", max: 2000 },
      { type: "autodate", name: "at", onCreate: true },
    ],
    indexes: [
      "CREATE INDEX `idx_audit_at` ON `audit` (`at`)",
      "CREATE INDEX `idx_audit_subject` ON `audit` (`subject`)",
    ],
  });
  app.save(audit);
}, (app) => {
  for (const name of ["audit", "grants", "apps"]) {
    try { app.delete(app.findCollectionByNameOrId(name)); } catch (err) { /* already gone */ }
  }
});
