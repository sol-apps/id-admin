#!/usr/bin/env python3
"""
greenlight-lint — check a generated app against the spec it declares.

The generated surface is deliberately small: browser JavaScript plus PocketBase's
hook API, no npm, no Node process, no binaries. That makes the interesting failure
mode mechanically checkable rather than a matter of judgement — an app whose code
does more than its spec admits to is caught by grep, and never reaches a human
reviewer pretending to be something it isn't.

Run by .github/workflows/lint.yml on every pull request. Both this file and that
workflow live under .github/, which the same check forbids the generated app from
modifying.
"""

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

REPO = os.getcwd()
FAILURES = []
NOTES = []

TIERS = {"green", "amber", "red"}
RUNTIME_SHAPES = {"static", "datastore", "identity", "scheduler", "endpoint"}
DATA_REACH = {"invented", "own", "reads_sor", "writes_sor", "sends_outward"}
REQUIRED_SPEC_KEYS = [
    "title", "slug", "description", "runtime_shape",
    "data_reach", "blast_radius", "scopes", "tier", "rationale",
]

# Paths the generated app may not touch.
#
# .github/ is the CI that checks it, and design-system/ and vendor/ are the vendored
# snapshots it is supposed to use rather than fork — vendor/ most of all, since the
# PocketBase SDK in it is what performs the OAuth2 code exchange. .claude/ is here for a different reason: it is
# an instruction channel aimed at whoever reviews this pull request. The build agent
# does not read it — its own skills come from Anthropic's Skills API, attached to the
# agent, never from the repository — but a human reviewing the PR with an agentic tool
# would, and the human review is the enforcement point of the entire platform. An app
# that could write instructions into its own review is an app that reviews itself.
PROTECTED_PREFIXES = (".github/", "design-system/", ".claude/", "vendor/")

# The identity layer, delivered by the template and not the generated app's to touch.
#
# These three files are what make the app governed: the migration owns the role field
# and the rule that stops anyone setting their own role, the hook writes that role
# from the identity provider's claim on every login, and pb-auth.js is the only seam
# the app is supposed to reach identity through. An app that could edit them could
# decide its own permissions — and it would do so in a pull request whose diff a
# reviewer is reading for the app's FEATURES, which is exactly where it would pass.
#
# Required as well as protected: deleting them is the same attack as editing them,
# and a deletion is even easier to miss.
PROTECTED_FILES = (
    "pb-auth.js",
    "pb_hooks/identity.pb.js",
    "pb_migrations/1756540000_identity.js",
)
REQUIRED_FILES = PROTECTED_FILES

# Protected does not mean frozen, and the difference matters: a defect found in the
# identity layer — or in the CI, or in vendored code — has to be able to REACH the apps
# already carrying it, and the only route to a shipped app is a reviewed pull request.
# A flat "never touch these" made the review gate the thing that kept a five-day session
# token in place, and would equally have frozen every app's copy of this very file.
#
# So one edit is allowed and exactly one: make the file identical to the template's
# copy. Anything else — including a "small" tweak on top of a convergence — still
# fails. The comparison is against the template at main, fetched here rather than
# vendored, because a vendored copy is one more thing that can drift.
#
# Unreachable means REFUSED, not skipped. A change to these files that cannot be shown
# to be a convergence is precisely the change this check exists to stop.
TEMPLATE_RAW = "https://raw.githubusercontent.com/sol-apps/app-template/main/%s"


def canonical_template(path):
    """The template's own copy of `path`, or None if it could not be read."""
    try:
        with urllib.request.urlopen(TEMPLATE_RAW % path, timeout=20) as resp:
            if resp.getcode() != 200:
                return None
            return resp.read().decode("utf-8")
    except (urllib.error.URLError, OSError, UnicodeDecodeError):
        return None
MAX_FILE_BYTES = 512 * 1024
BINARY_MAGIC = (b"\x7fELF", b"MZ", b"\xca\xfe\xba\xbe", b"PK\x03\x04", b"\x1f\x8b")
BANNED_PATHS = ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml")


def fail(msg):
    FAILURES.append(msg)


def note(msg):
    NOTES.append(msg)


def tracked_files():
    out = subprocess.run(
        ["git", "ls-files"], capture_output=True, text=True, check=True
    ).stdout
    return [p for p in out.splitlines() if p]


def changed_files(base, head):
    if not base or not head:
        return None
    try:
        out = subprocess.run(
            ["git", "diff", "--name-only", f"{base}...{head}"],
            capture_output=True, text=True, check=True,
        ).stdout
        return [p for p in out.splitlines() if p]
    except subprocess.CalledProcessError:
        return None


# --------------------------------------------------------------------- spec

def load_spec():
    path = os.path.join(REPO, "spec.json")
    if not os.path.exists(path):
        fail("spec.json is missing — every generated app declares what it does before it ships")
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            spec = json.load(fh)
    except json.JSONDecodeError as err:
        fail(f"spec.json is not valid JSON: {err}")
        return None
    if not isinstance(spec, dict):
        fail("spec.json must be a JSON object")
        return None

    for key in REQUIRED_SPEC_KEYS:
        if key not in spec:
            fail(f"spec.json is missing the required key '{key}'")

    if spec.get("tier") not in TIERS:
        fail(f"spec.json tier must be one of {sorted(TIERS)}, got {spec.get('tier')!r}")
    if spec.get("runtime_shape") not in RUNTIME_SHAPES:
        fail(f"spec.json runtime_shape must be one of {sorted(RUNTIME_SHAPES)}, got {spec.get('runtime_shape')!r}")
    if spec.get("data_reach") not in DATA_REACH:
        fail(f"spec.json data_reach must be one of {sorted(DATA_REACH)}, got {spec.get('data_reach')!r}")
    if not isinstance(spec.get("scopes"), list):
        fail("spec.json scopes must be an array")
    if not str(spec.get("rationale", "")).strip():
        fail("spec.json rationale must explain why the app landed on its tier")
    return spec


# ------------------------------------------------------------------ repo shape

def check_repo_shape(files):
    for path in files:
        base = os.path.basename(path)
        if base in BANNED_PATHS or path.startswith("node_modules/") or "/node_modules/" in path:
            fail(f"{path}: the template is deliberately node-free — no package manager files")

    for path in files:
        full = os.path.join(REPO, path)
        if not os.path.isfile(full):
            continue
        size = os.path.getsize(full)
        if size > MAX_FILE_BYTES:
            fail(f"{path}: {size // 1024}KB exceeds the {MAX_FILE_BYTES // 1024}KB limit — no vendored blobs")
            continue
        with open(full, "rb") as fh:
            head = fh.read(4)
        if any(head.startswith(magic) for magic in BINARY_MAGIC):
            fail(f"{path}: looks like a binary or archive — generated apps ship source, not artefacts")


# AGENT.md and spec.json.example document the placeholders, so they are the one place
# the literal text is allowed to survive.
PLACEHOLDER_EXEMPT = {"AGENT.md", "spec.json.example", "DESIGN-SYSTEM-VERSION"}


def check_placeholders(files):
    pattern = re.compile(r"\{\{[A-Z_]+\}\}")
    for path in files:
        if path.startswith(".github/") or path in PLACEHOLDER_EXEMPT:
            continue
        full = os.path.join(REPO, path)
        if not os.path.isfile(full):
            continue
        try:
            with open(full, encoding="utf-8") as fh:
                text = fh.read()
        except (UnicodeDecodeError, OSError):
            continue
        found = sorted(set(pattern.findall(text)))
        if found:
            fail(f"{path}: unreplaced template placeholders {', '.join(found)}")


def check_protected(base, head):
    changed = changed_files(base, head)
    if changed is None:
        note("could not diff against the base commit — skipped the protected-path check")
        return
    for path in changed:
        protected_prefix = path.startswith(PROTECTED_PREFIXES)
        if not protected_prefix and path not in PROTECTED_FILES:
            continue
        if protected_prefix:
            why = (f"{path}: CI, the design system and vendored code are not the generated "
                   f"app's to change")
        else:
            why = (f"{path}: the identity layer is not the generated app's to change — it is "
                   f"what makes this app's access decisions someone else's to make")
        full = os.path.join(REPO, path)
        here = None
        if os.path.isfile(full):
            try:
                with open(full, encoding="utf-8") as fh:
                    here = fh.read()
            except (UnicodeDecodeError, OSError):
                here = None
        canon = canonical_template(path)
        if canon is None:
            fail(
                f"{path}: this path is protected and the template's copy could not be read "
                f"to check the change against — either it does not exist there, or the "
                f"template was unreachable. Refusing rather than skipping: an unverifiable "
                f"diff to a protected path is the whole risk."
            )
        elif here == canon:
            note(f"{path}: converged to the template — allowed")
        else:
            fail(why + ". The only permitted edit is making it identical to the "
                       "template's copy, and this diff leaves it different.")


def note_users_reach(files):
    """Point the reviewer at anything else that can touch the users collection.

    The protected-file rule is defence in depth, not a boundary: it stops the identity
    SEAM being edited, and stops nothing else. Any other hook or migration in the app
    can still read or write the users collection — legitimately, most of the time — and
    a reviewer scanning a feature diff has no way to know which files those are. So the
    lint says so out loud rather than implying, by its silence, that the seam being
    intact means the users collection is untouched.
    """
    hits = []
    pattern = re.compile(r"""["']users["']|\busers\b\s*\)""")
    for path in files:
        if path in PROTECTED_FILES or not (
                path.startswith("pb_hooks/") or path.startswith("pb_migrations/")):
            continue
        if not path.endswith(".js"):
            continue
        full = os.path.join(REPO, path)
        if not os.path.isfile(full):
            continue
        try:
            with open(full, encoding="utf-8") as fh:
                text = fh.read()
        except (UnicodeDecodeError, OSError):
            continue
        if "users" in text and pattern.search(text):
            hits.append(path)
    if hits:
        note("these files also reach the users collection, where role lives — worth a "
             "look in review: " + ", ".join(sorted(hits)))


def check_identity_present(files):
    tracked = set(files)
    for path in REQUIRED_FILES:
        if path not in tracked:
            fail(
                f"{path} is missing — every generated app ships the platform identity "
                f"layer. An app without it has no grants, no roles and no sign-in."
            )


# ----------------------------------------------------------------- hook rules

# Comments and string literals are not stripped before these run. A false positive on
# a commented-out example is the right trade: the rule is easy to satisfy honestly, and
# a lint that can be talked out of a finding by a comment is not a control.
HOOK_RULES = [
    (
        re.compile(r"\$os\.(?!getenv\b)\w+"),
        "$os.* is forbidden in hooks (only $os.getenv is allowed) — no shelling out, no filesystem access",
        lambda spec: True,
    ),
    (
        re.compile(r"\bcronAdd\s*\("),
        "cronAdd requires \"runtime_shape\": \"scheduler\" in spec.json — an app that runs unattended has to say so",
        lambda spec: spec.get("runtime_shape") != "scheduler",
    ),
    (
        re.compile(r"\$http\.send\s*\("),
        "$http.send requires an outbound scope in spec.json (a \"net:<host>\" entry in scopes) — undeclared egress is the whole point of the check",
        lambda spec: not any(
            str(s).startswith("net:") for s in (spec.get("scopes") or [])
        ),
    ),
]

REQUIRE_CALL = re.compile(r"""\brequire\s*\(\s*(?!__hooks\b)(.+?)\)""")


def check_hooks(spec, files):
    hook_files = [p for p in files if p.startswith("pb_hooks/") and p.endswith(".js")]
    if not hook_files:
        return
    for path in hook_files:
        full = os.path.join(REPO, path)
        if not os.path.isfile(full):
            continue
        with open(full, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
        for lineno, line in enumerate(lines, 1):
            for pattern, message, applies in HOOK_RULES:
                if pattern.search(line) and applies(spec or {}):
                    fail(f"{path}:{lineno}: {message}")
            m = REQUIRE_CALL.search(line)
            if m:
                fail(
                    f"{path}:{lineno}: require() may only load files under __hooks "
                    f"(got {m.group(1).strip()}) — there is no module ecosystem here"
                )


# ----------------------------------------------------------------------- main

def main():
    base = sys.argv[1] if len(sys.argv) > 1 else ""
    head = sys.argv[2] if len(sys.argv) > 2 else ""

    files = tracked_files()
    spec = load_spec()
    check_repo_shape(files)
    check_placeholders(files)
    check_protected(base, head)
    check_identity_present(files)
    check_hooks(spec, files)
    note_users_reach(files)

    for msg in NOTES:
        print(f"note: {msg}")

    if FAILURES:
        print(f"\ngreenlight-lint: {len(FAILURES)} problem(s)\n")
        for msg in FAILURES:
            print(f"  ✗ {msg}")
        print("\nThe app contradicts the spec it shipped with, or breaks a rule the")
        print("template guarantees. Fix the code or change the spec — but if the spec")
        print("changes, the tier may change with it, and that is a decision for the")
        print("reviewer, not a way round the check.")
        return 1

    tier = (spec or {}).get("tier", "?")
    print(f"greenlight-lint: clean — {len(files)} files, declared tier '{tier}'")
    return 0


if __name__ == "__main__":
    sys.exit(main())
