# Repo conventions

You are building one governed mini-app in this repository. This file is the local,
checked-in half of your instructions; your system prompt is the other half. Where
they overlap, they agree. Where this file is more specific, follow it.

## What this repo is

A **node-free static frontend plus PocketBase hooks**. No build step, no package
manager, no bundler, no framework. The browser loads the files as written, and
PocketBase 0.39 runs `pb_hooks/` in an embedded Goja VM.

```
index.html            the app (add more .html pages beside it as needed)
pb-auth.js            the identity seam — read it before you write any data code
design-system/        vendored, read-only: tokens, components, behaviours
pb_hooks/main.pb.js   server-side hooks (Goja, not Node)
pb_migrations/        committed schema; empty until the app needs a collection
spec.json             YOU create this — the agreed governance spec
.github/workflows/    CI, read-only
```

## Placeholders

The template ships with `{{SLUG}}`, `{{TITLE}}` and `{{DESCRIPTION}}`
placeholders (generating a repo from a template does not substitute them). Replace
every one before you open the pull request. CI fails if any survive.

## The design system is law

`design-system/` is a vendored snapshot of Greenlight's. Link it, use it, do not
edit it — CI fails on any diff under that directory.

```html
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,500;12..96,600;12..96,700;12..96,800&family=Hanken+Grotesk:wght@400;500;600;700&display=swap">
<link rel="stylesheet" href="design-system/tokens.css">
<link rel="stylesheet" href="design-system/components.css">
<script src="design-system/components.js" defer></script>
```

Use the tokens (`var(--space-4)`, `var(--text-base)`, `var(--surface)`, …) rather
than hard-coded values, and the components (`.panel`, `.card`, `.btn`, `.chip`,
`.dtable`, `.field`, `.input`, `.badge`, `.empty`, `.topbar`) rather than new ones.
Page-specific CSS goes in a `<style>` block on that page. Open
`design-system/styleguide.html` to see everything rendered.

House rules: British English, sentence case, and never `·` middot separators — use
commas or dashes.

## Hooks

Handlers run in **isolated pooled VMs**. Nothing at the top level of a `.pb.js`
file is visible inside a handler — not functions, and not `const` either. Shared
code goes in `pb_hooks/lib/*.js` and is pulled in *inside* each handler:

```js
routerAdd("GET", "/api/thing", (e) => {
  const helper = require(__hooks + "/lib/helper.js");
  return e.json(200, helper.list(e.app));
});
```

Forbidden, and checked by CI:

- any `$os.*` call except `$os.getenv`
- `$http.send` unless `spec.json` declares an outbound scope — a `scopes` entry of
  the form `net:<host>`, e.g. `"net:api.postcodes.io"`
- `cronAdd` unless `spec.json` has `"runtime_shape": "scheduler"`
- `require()` of anything that is not under `__hooks`
- `package.json`, `node_modules`, or committed binaries

The check does not strip comments before it looks, so a commented-out `$os.cmd`
example still fails. Delete it rather than commenting it out.

## Schema

If the app needs collections, they are **committed migrations** in `pb_migrations/`,
the same files a local PocketBase writes under automigrate. Never write code that
assumes someone will create a collection by hand.

## Data

Ship with invented, obviously-fake data unless the spec says otherwise. Promotion
from fake data to real data is a separate governed decision, and not yours.

## spec.json

Create it at the repo root from the spec you agreed with the builder, in the shape
of `spec.json.example`. It is read by the tier classifier, by the human reviewer,
and by CI — which cross-checks the code against what the spec claims. Code that
contradicts its own spec fails the build.

## Delivery

Branch `draft/<slug>-1`, then a pull request into `main`. Never commit to `main`,
never merge, never approve. A human reviews it. That review is the point.

Assume the merge ships. Once a human approves and merges, this app goes live on its
own subdomain with no further step — the merge IS the deploy, and nobody gets a second
look between the two. Open the pull request in the state you would want
deployed, and say plainly in the description anything a reviewer should weigh, because
the description is the last place it can be said.
