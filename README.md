---
greenlight_app: true
slug: id-admin
title: Access
description: Who may use which app on solhann.net, and the record of every change.
---

# Access

The grants service and its admin screen. A **platform repo**, not a wizard-generated
app: the build agent has no grant on it, and it ships through the same review gate as
everything else.

This is the source of truth for who may use which app. Keycloak is a cache of it.

- **Design:** [AUTH-LAYER.md](../AUTH-LAYER.md) — why the identity provider refuses
  people rather than the apps doing it.
- **Implementation:** [platform/id/](../platform/id/) — the realm, the per-app clients,
  and what was verified against real software rather than assumed.

## What it does

    grants     (subject, slug, role)  unique per person per app — the source of truth
    apps       client uuid + role ids, written by provisioning
    audit      append-only; every grant, revoke, offboard and repair

A grant is two Keycloak role assignments: `restricted-access`, which is what lets that
person authenticate to that app **at all**, and `app-admin`, which makes them an admin
once inside. Role `user` means the first without the second.

Every mutation writes the table, writes an audit row, then pushes to the realm — in
that order, so a failed push leaves a recorded intent that reconcile can repair rather
than a silent divergence nobody can see.

## Who may use it

Whoever holds an **admin grant on `id-admin` itself**, which makes this screen governed
by the same mechanism it governs. There is no operator list and no environment variable
naming a superuser.

The one exception is the provisioning token in this instance's env file, root-only on
the prod box. It exists for the first admin grant — nobody can use this screen until
someone has one, and nobody can create it through this screen. It is accepted for
creating a grant and registering an app, and for nothing else: offboarding, reconcile
and the audit trail all still need a human admin.

## Reconcile

Two kinds of drift, and they are not symmetrical. **Missing** means someone cannot get
into an app they were granted — annoying and self-reporting. **Extra** means someone
can get into an app nobody granted them, which is invisible from inside that app,
because such a person looks exactly like a legitimate user. So the check enumerates the
realm rather than only walking the table: walking the table alone can only find missing.

## Running it locally

`pb-dev` works, with no Keycloak: `pb_hooks/identity.pb.js` leaves password auth
enabled when `OIDC_*` is absent from the environment. The grants routes need
`KC_*` set to reach a realm.
