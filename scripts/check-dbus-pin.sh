#!/usr/bin/env bash
# Validate the explicit Git pin against Cargo.lock without network access.
set -euo pipefail
repo_root="$(cd "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
python3 - "$repo_root/Cargo.toml" "$repo_root/Cargo.lock" <<'CHECK'
import re
import sys
import tomllib
from pathlib import Path

manifest, lockfile = sys.argv[1:]
dep = tomllib.loads(Path(manifest).read_text())["dependencies"]["lyra-vega-dbus"]
packages = [p for p in tomllib.loads(Path(lockfile).read_text())["package"] if p["name"] == "lyra-vega-dbus"]
if len(packages) != 1:
    raise SystemExit("expected one locked lyra-vega-dbus package")
package = packages[0]
expected_version = package["version"]
url = "https://github.com/lyra-os-linux/lyra-vega-dbus"
if dep.get("git") != url or package["version"] != expected_version:
    raise SystemExit("contract repository/version mismatch")
if set(dep) == {"git", "tag"} and dep["tag"] == "v" + expected_version:
    expected = "git+" + url + "?tag=" + dep["tag"] + "#"
    valid = package.get("source", "").startswith(expected) and re.fullmatch(r"[0-9a-f]{40}", package["source"][len(expected):])
elif set(dep) == {"git", "rev"} and re.fullmatch(r"[0-9a-f]{40}", dep["rev"]):
    valid = package.get("source") == "git+" + url + "?rev=" + dep["rev"] + "#" + dep["rev"]
else:
    valid = False
if not valid:
    raise SystemExit("contract must use a matching release tag or full immutable revision in manifest and lockfile")
print("consumer pins lyra-vega-dbus " + expected_version + " at an explicit matching Git reference")
CHECK
