/// <reference path="../pb_data/types.d.ts" />
/*
 * main.pb.js — server-side hooks for {{SLUG}}. THIS FILE RUNS ON THE SERVER.
 *
 * Runtime is PocketBase 0.39's embedded Goja VM: no npm, no Node APIs, no async.
 * You get PocketBase's own helpers — $app, routerAdd, cronAdd, onRecordCreate,
 * $os.getenv and so on. Docs: https://pocketbase.io/docs/js-overview/
 *
 * Two rules that are enforced by CI, not just style:
 *
 * 1. Handlers run in ISOLATED POOLED VMs. Nothing at the top level of this file is
 *    visible inside a handler — not functions, and not consts either. Shared code
 *    lives in pb_hooks/lib/*.js and is pulled in INSIDE each handler:
 *
 *      routerAdd("GET", "/api/things", (e) => {
 *        const things = require(__hooks + "/lib/things.js");
 *        return e.json(200, things.list(e.app));
 *      });
 *
 * 2. The app may only do what spec.json says it does. Outbound network calls,
 *    scheduled jobs and process access each require a matching declaration in the
 *    spec — see AGENT.md for exactly which. Adding the capability without adding
 *    the declaration fails the build, and so does the reverse of that trade:
 *    quietly widening the spec to match code the reviewer never agreed to.
 *
 * Runtime configuration arrives as environment variables, read with
 * $os.getenv("MY_KEY"). Never commit a secret to this repo — it is public.
 */

// Nothing yet. Delete this comment when the app grows a server side; an app that
// needs no hooks should ship this file empty rather than pretend otherwise.
