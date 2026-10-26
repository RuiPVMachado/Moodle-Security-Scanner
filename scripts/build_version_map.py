#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Regenerate data/moodle_version_map.json from official Moodle git tags.

The map converts the numeric ``$CFG->version`` value (for example
``2026042004``) into a human release (``5.2.4``).  The scanner uses it to
match OSV advisories without guessing from page content.

Usage:
    python scripts/build_version_map.py
"""

from __future__ import annotations

import argparse
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

TAGS_API = "https://api.github.com/repos/moodle/moodle/tags?per_page=100&page={page}"
RAW = "https://raw.githubusercontent.com/moodle/moodle/{tag}/{path}"
DEFAULT_OUTPUT = Path(__file__).resolve().parent.parent / "data" / "moodle_version_map.json"


def get_tags(session: requests.Session) -> list[str]:
    tags: list[str] = []
    for page in (1, 2, 3):
        response = session.get(TAGS_API.format(page=page), timeout=30)
        if response.status_code != 200:
            break
        batch = response.json()
        if not batch:
            break
        tags.extend(item["name"] for item in batch)
    return [tag for tag in tags if re.fullmatch(r"v\d+\.\d+\.\d+", tag)]


def fetch_version(session: requests.Session, tag: str):
    for path in ("public/version.php", "version.php"):
        try:
            response = session.get(RAW.format(tag=tag, path=path), timeout=20)
            if response.status_code != 200:
                continue
            text = response.text
            version = re.search(r"\$version\s*=\s*([0-9]+)(?:\.[0-9]+)?\s*;", text)
            release = re.search(r"\$release\s*=\s*['\"]([^'\"]+)['\"]", text)
            branch = re.search(r"\$branch\s*=\s*['\"]([^'\"]+)['\"]", text)
            if version:
                release_text = release.group(1).strip() if release else tag.lstrip("v")
                release_clean = re.sub(r"\s*\(Build:.*$", "", release_text).strip()
                if re.fullmatch(r"\d+\.\d+", release_clean):
                    # Moodle calls the first release of a branch "4.4"; OSV
                    # expects the semver form "4.4.0" for exact matching.
                    release_clean += ".0"
                return tag, {
                    "release": release_clean or tag.lstrip("v"),
                    "branch": branch.group(1).strip()
                    if branch
                    else ".".join(tag.lstrip("v").split(".")[:2]),
                    "tag": tag,
                    "numeric": version.group(1),
                }
        except Exception:
            continue
    return tag, None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-o", "--output", default=str(DEFAULT_OUTPUT))
    args = parser.parse_args()

    session = requests.Session()
    session.headers.update(
        {"User-Agent": "moodle-security-scanner-version-map-builder/2.1"}
    )
    tags = get_tags(session)
    print(f"Found {len(tags)} stable tags")

    mapping = {}
    errors = []
    with ThreadPoolExecutor(max_workers=12) as pool:
        futures = {pool.submit(fetch_version, session, tag): tag for tag in tags}
        for future in as_completed(futures):
            tag, info = future.result()
            if info:
                mapping[info["numeric"]] = {
                    "release": info["release"],
                    "branch": info["branch"],
                    "tag": info["tag"],
                }
            else:
                errors.append(tag)

    ordered = dict(sorted(mapping.items(), key=lambda item: int(item[0])))
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(ordered, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {len(ordered)} entries to {output}")
    if errors:
        print(f"Could not resolve {len(errors)} tags (first 10: {errors[:10]})")


if __name__ == "__main__":
    main()
