"""Publish verified feeds, reconciling ambiguous GitHub API failures by digest."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time


class NotFound(Exception):
    pass


def command(arguments):
    return subprocess.run(arguments, check=False)


def api(endpoint):
    for attempt in range(3):
        result = subprocess.run(["gh", "api", endpoint], capture_output=True, text=True, check=False)
        if not result.returncode:
            return json.loads(result.stdout)
        if "HTTP 404" in result.stderr:
            raise NotFound(endpoint)
        transient = re.search(r"HTTP (?:5[0-9]{2}|429)", result.stderr) or "error connecting to" in result.stderr
        if not transient or attempt == 2:
            raise RuntimeError(result.stderr.strip())
        time.sleep(2)


def read_release(repository, tag):
    return api(f"repos/{repository}/releases/tags/{tag}")


def verify_tag(repository, tag, source):
    ref = api(f"repos/{repository}/git/ref/tags/{tag}")
    if ref["object"].get("type") != "commit" or ref["object"].get("sha") != source:
        raise ValueError("release tag does not identify the expected source commit")


def publish(repository, tag, source, assets, title, notes, delay=5):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("invalid repository")
    if not re.fullmatch(r"data-feeds-[0-9]+", tag) or not re.fullmatch(r"[0-9a-f]{40}", source):
        raise ValueError("invalid source or feed tag")
    expected = {}
    for asset in assets:
        if asset.is_symlink() or not asset.is_file() or asset.name in expected:
            raise ValueError("invalid or duplicate release asset")
        expected[asset.name] = (asset.stat().st_size, "sha256:" + hashlib.sha256(asset.read_bytes()).hexdigest())
    if not expected:
        raise ValueError("release assets are required")
    for attempt in range(4):
        try:
            release = read_release(repository, tag)
        except NotFound:
            if attempt == 3:
                break
            command(["gh", "release", "create", tag, *map(str, assets), "--repo", repository,
                     "--target", source, "--title", title, "--notes-file", str(notes)])
        else:
            if release["tag_name"] != tag or release["target_commitish"] != source or release["prerelease"]:
                raise ValueError("existing release has a different source or channel")
            verify_tag(repository, tag, source)
            actual = {}
            for asset in release["assets"]:
                if asset["name"] in actual or asset["state"] != "uploaded":
                    raise ValueError("release contains duplicate or incomplete assets")
                actual[asset["name"]] = (asset["size"], asset.get("digest"))
            if actual != expected:
                raise ValueError("release asset mismatch; existing data was not overwritten")
            if not release["draft"]:
                return release
            if attempt == 3:
                break
            command(["gh", "release", "edit", tag, "--repo", repository, "--draft=false"])
        if attempt < 3:
            time.sleep(delay)
    raise RuntimeError("release publication was not confirmed after three attempts")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--title", required=True)
    parser.add_argument("--notes", required=True, type=Path)
    parser.add_argument("assets", nargs="+", type=Path)
    args = parser.parse_args()
    release = publish(args.repo, args.tag, args.source, args.assets, args.title, args.notes)
    print(json.dumps({"url": release["html_url"], "assets": len(release["assets"]), "verified": True}))


if __name__ == "__main__":
    main()
