/// <reference path="../pb_data/types.d.ts" />
/* Durable, versioned provider work.  The grants table is desired state; this table
 * records what still has to converge in Keycloak after the local transaction commits.
 */
migrate((app) => {
  const work = new Collection({
    type: "base",
    name: "identity_work",
    listRule: null, viewRule: null, createRule: null, updateRule: null, deleteRule: null,
    fields: [
      { type: "text", name: "work_key", required: true, max: 300 },
      { type: "text", name: "subject", required: true, max: 200 },
      { type: "text", name: "slug", max: 28 },
      { type: "select", name: "kind", required: true, maxSelect: 1,
        values: ["grant", "offboard"] },
      { type: "select", name: "desired_role", maxSelect: 1,
        values: ["user", "admin"] },
      { type: "bool", name: "end_sessions" },
      { type: "text", name: "actor", required: true, max: 200 },
      { type: "number", name: "version", required: true, onlyInt: true, min: 1 },
      { type: "select", name: "status", required: true, maxSelect: 1,
        values: ["pending", "running", "succeeded", "failed"] },
      { type: "number", name: "attempts", onlyInt: true, min: 0 },
      { type: "text", name: "last_error", max: 2000 },
      { type: "autodate", name: "created", onCreate: true },
      { type: "autodate", name: "updated", onCreate: true, onUpdate: true },
    ],
    indexes: [
      "CREATE UNIQUE INDEX `idx_identity_work_key` ON `identity_work` (`work_key`)",
      "CREATE INDEX `idx_identity_work_status` ON `identity_work` (`status`)",
    ],
  });
  app.save(work);
}, (app) => {
  try { app.delete(app.findCollectionByNameOrId("identity_work")); }
  catch (err) { /* already gone */ }
});
