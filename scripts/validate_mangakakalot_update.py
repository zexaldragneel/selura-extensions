#!/usr/bin/env python3
"""Fail-closed guard for publishing exactly one Mangakakalot extension update."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
from urllib.parse import urlparse

TARGET = "eu.kanade.tachiyomi.extension.en.seluramangakakalot"


def compare_catalog(old: dict, new: dict, expected_count=43, expected_sources=341):
    original = copy.deepcopy(old)
    updated = copy.deepcopy(new)
    before = original["extensionList"].pop("extensions")
    after = updated["extensionList"].pop("extensions")
    if original != updated:
        raise ValueError("Store signer, URL or global metadata changed")
    if len(before) != expected_count or len(after) != expected_count:
        raise ValueError("Unexpected extension inventory size")
    a = {x["packageName"]: x for x in before}
    b = {x["packageName"]: x for x in after}
    if len(a) != expected_count or set(a) != set(b) or TARGET not in a:
        raise ValueError("Extension packages were changed or duplicated")
    seen = set()
    for pkg, old_entry in a.items():
        new_entry = b[pkg]
        if pkg == TARGET:
            x, y = copy.deepcopy(old_entry), copy.deepcopy(new_entry)
            old_code, new_code = x.pop("versionCode"), y.pop("versionCode")
            old_ver, new_ver = x.pop("versionName"), y.pop("versionName")
            if new_code <= old_code or new_ver == old_ver:
                raise ValueError("Mangakakalot version must increase")
            if x != y:
                raise ValueError("Mangakakalot source identity or metadata changed")
        elif old_entry != new_entry:
            raise ValueError("Another extension changed: " + pkg)
        for item in new_entry["sources"]:
            source_id = str(item["id"])
            if source_id in seen:
                raise ValueError("Duplicate source ID: " + source_id)
            seen.add(source_id)
    if len(seen) != expected_sources:
        raise ValueError("Unexpected source ID inventory")


def compare_assets(old: dict, output: Path, git_ref: str):
    for item in old["extensionList"]["extensions"]:
        if item["packageName"] == TARGET:
            continue
        apk = Path(urlparse(item["resources"]["apkUrl"]).path).name
        if not apk.endswith(".apk") or "/" in apk or apk.startswith("."):
            raise ValueError("Invalid extension asset")
        was = subprocess.check_output(["git", "show", f"{git_ref}:apk/{apk}"])
        now = (output / "apk" / apk).read_bytes()
        if hashlib.sha256(was).digest() != hashlib.sha256(now).digest():
            raise ValueError("Unrelated APK was modified: " + apk)
    # The fix is Kotlin-only; icons must remain identical for every extension.
    for item in old["extensionList"]["extensions"]:
        icon = Path(urlparse(item["resources"]["iconUrl"]).path).name
        if not icon.endswith(".png") or "/" in icon or icon.startswith("."):
            raise ValueError("Invalid icon asset")
        was = subprocess.check_output(["git", "show", f"{git_ref}:icon/{icon}"])
        now = (output / "icon" / icon).read_bytes()
        if hashlib.sha256(was).digest() != hashlib.sha256(now).digest():
            raise ValueError("Extension icon changed: " + icon)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("before", type=Path)
    p.add_argument("after", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("repo_ref")
    a = p.parse_args()
    previous = json.loads(a.before.read_text(encoding="utf-8"))
    next_index = json.loads(a.after.read_text(encoding="utf-8"))
    compare_catalog(previous, next_index)
    compare_assets(previous, a.output, a.repo_ref)
    print("PASS: 43 packages, 341 identities, 42 unchanged APKs, all icons intact")


if __name__ == "__main__":
    main()
