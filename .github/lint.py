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
# .github/ is the CI that checks it, and design-system/ is the vendored snapshot it
# is supposed to use rather than fork. .claude/ is here for a different reason: it is
# an instruction channel aimed at whoever reviews this pull request. The build agent
# does not read it — its own skills come from Anthropic's Skills API, attached to the
# agent, never from the repository — but a human reviewing the PR with an agentic tool
# would, and the human review is the enforcement point of the entire platform. An app
# that could write instructions into its own review is an app that reviews itself.
PROTECTED_PREFIXES = (".github/", "design-system/", ".claude/")
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
        if path.startswith(PROTECTED_PREFIXES):
            fail(f"{path}: this path is not the generated app's to change (CI and the design system are fixed)")


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
    check_hooks(spec, files)

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
