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
    identity_work  one versioned, retryable provider-sync item per person/app

A grant is two Keycloak role assignments: `restricted-access`, which is what lets that
person authenticate to that app **at all**, and `app-admin`, which makes them an admin
once inside. Role `user` means the first without the second.

Every mutation commits desired state, an audit intent and durable provider work in one
local transaction. One worker per person/app then converges the latest version in the
realm. A failed or interrupted push is therefore both visible and retryable; an older
in-flight grant cannot finish after a newer revoke and restore access. Reconciliation
resolves the current grant/offboard state again inside that transaction rather than
turning its earlier inspection snapshot into a new intent. Pending session termination
is a typed work field and survives later work versions until it succeeds.

## Who may use it

Whoever **currently** holds an admin grant on `id-admin` itself, which makes this screen
governed by the same mechanism it governs. Each request resolves the caller's OIDC
external-auth link to the canonical Keycloak subject and rechecks that grant. A stale
PocketBase token or old local `users.role` value cannot recreate revoked access. There
is no operator list and no environment variable naming a superuser.

The one exception is the provisioning token in this instance's env file, root-only on
the prod box. It exists for the first admin grant — nobody can use this screen until
someone has one, and nobody can create it through this screen. It is accepted for
creating or revoking a grant, registering an app and reading drift for the production
proof. It cannot offboard, repair drift or read the audit trail; those still need a
human admin.

## Reconcile

Two kinds of direct drift, and they are not symmetrical. **Missing** means someone cannot get
into an app they were granted — annoying and self-reporting. **Extra** means someone
can get into an app nobody granted them, which is invisible from inside that app,
because such a person looks exactly like a legitimate user. So the check enumerates the
realm rather than only walking the table: walking the table alone can only find missing.
The check also reads **effective** roles for every governed client. Access inherited
through a group or composite is reported as unresolved and is never called repaired,
because its source needs an operator decision. A repair response reports attempted,
succeeded, failed and still-unresolved counts from a fresh provider read.

## Running it locally

`pb-dev` explicitly sets `GREENLIGHT_IDENTITY_MODE=local`; the fresh local migration
keeps password auth available and the hook skips production OIDC convergence.
Production explicitly sets `GREENLIGHT_IDENTITY_MODE=production` and refuses to start
without the complete OIDC configuration. Missing secrets never select a mode. The
grants routes still need `KC_*` set to reach a realm.
