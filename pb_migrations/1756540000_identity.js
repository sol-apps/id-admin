/// <reference path="../pb_data/types.d.ts" />
/*
 * Identity schema for a governed app. Delivered by the template, protected by CI —
 * this file is not the generated app's to edit (see .github/lint.py).
 *
 * SCHEMA only. The OIDC provider's credentials are NOT here: they arrive at runtime
 * from the app's env and are applied on every boot by pb_hooks/identity.pb.js. A
 * migration is a one-shot, and configuration that can only ever be applied once is
 * configuration that silently misses the app provisioned before the IdP existed, and
 * cannot express a rotated client secret. Schema shape lives here; credentials live
 * in the env; neither is ever committed to this public repo.
 */
migrate((app) => {
  const users = app.findCollectionByNameOrId("users");

  // Which role this person holds IN THIS APP. Set server-side on every login from
  // the identity provider's roles claim, and settable from nowhere else.
  if (!users.fields.getByName("role")) {
    users.fields.add(new SelectField({
      name: "role",
      values: ["user", "admin"],
      maxSelect: 1,
      required: false,
    }));
  }

  // Accounts exist because a human granted access and the person then signed in.
  //
  // The rule is not `null`. PocketBase checks createRule for the record it
  // auto-creates on a first OAuth2 login too, so `null` locks out the ONE path that
  // is supposed to work (verified: 403 "Only superusers can perform this action").
  // Scoping it to the oauth2 context instead gives exactly the door we want: a record
  // can be created by completing an IdP login — which the IdP only permits to someone
  // who already holds a grant — and by nothing else. A plain POST to
  // /api/collections/users/records is still refused.
  users.createRule = "@request.context = 'oauth2'";
  users.deleteRule = null;
  users.listRule = "id = @request.auth.id";
  users.viewRule = "id = @request.auth.id";

  // A person may edit their own record but may NOT set their own role. Without the
  // isset guard, `PATCH /api/collections/users/records/<self> {"role":"admin"}` is a
  // self-service privilege escalation that needs no bug to exploit — just the API.
  users.updateRule = "id = @request.auth.id && @request.body.role:isset = false";

  // How long this app's own session token outlives the grant that produced it.
  //
  // PocketBase's default for an auth collection is 432000s — FIVE DAYS (verified on a
  // fresh 0.39.5 instance, not inferred). That default silently undoes revocation:
  // the app's token is issued at login and is thereafter independent of both the
  // realm role and the IdP session, so removing someone's grant leaves their open tab
  // making authenticated calls, at whatever role their last login wrote, for the rest
  // of those five days. Revoke ends their ability to RE-ENTER; without this line it
  // does not end their access.
  //
  // Thirty minutes is the bound on that window. It is affordable only because
  // re-entry is cheap: pb-auth.js signs in through a popup against a live SSO cookie,
  // so a renewal is a round-trip to the IdP that costs a click and no page state —
  // and that round-trip is the point, because it is where the restriction is
  // re-evaluated. Renewing WITHOUT it is refused in pb_hooks/identity.pb.js.
  users.authToken.duration = 1800;

  app.save(users);
}, (app) => {
  const users = app.findCollectionByNameOrId("users");
  users.authToken.duration = 432000; // back to PocketBase's own default
  const role = users.fields.getByName("role");
  if (role) {
    users.fields.removeById(role.id);
  }
  app.save(users);
});
