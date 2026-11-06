import os
import hashlib
import json
import platform
import re
import stat
import urllib.request
from pathlib import Path


def expected_digest(release_tag, asset_name):
    configured = os.environ.get('NEXTTRACE_SHA256', '')
    pinned = Path(__file__).with_name('nexttrace-checksums.json')
    checksums = json.loads(pinned.read_text()) if pinned.exists() else {}
    digest = configured or checksums.get(release_tag, {}).get(asset_name)
    if not digest:
        path = 'latest' if release_tag == 'latest' else 'tags/' + release_tag
        request = urllib.request.Request('https://api.github.com/repos/nxtrace/NTrace-core/releases/' + path,
                                         headers={'Accept': 'application/vnd.github+json', 'User-Agent': 'nexttraceweb-build'})
        with urllib.request.urlopen(request, timeout=30) as response:
            release = json.load(response)
        digest = next((asset.get('digest', '') for asset in release['assets'] if asset['name'] == asset_name), '')
        digest = (digest or '').removeprefix('sha256:')
    if not re.fullmatch('[0-9a-fA-F]{64}', digest):
        raise SystemExit('Missing valid SHA256 for NextTrace asset; provide NEXTTRACE_SHA256')
    return digest.lower()


def default_target_arch():
    machine = platform.machine().lower()
    if machine in {"amd64", "x86_64"}:
        return "amd64"
    if machine in {"arm64", "aarch64"}:
        return "arm64"
    return machine


def main():
    target_os = os.environ.get("TARGETOS") or "linux"
    target_arch = os.environ.get("TARGETARCH") or default_target_arch()
    asset_prefix = os.environ["NEXTTRACE_ASSET_PREFIX"]
    release_tag = os.environ["NEXTTRACE_RELEASE_TAG"]
    if asset_prefix not in {'ntr', 'nexttrace', 'nexttrace-tiny'} or not re.fullmatch(r'[A-Za-z0-9_.-]+', release_tag):
        raise SystemExit('Invalid NextTrace release or flavor')

    asset_map = {
        ("linux", "amd64"): f"{asset_prefix}_linux_amd64",
        ("linux", "arm64"): f"{asset_prefix}_linux_arm64",
    }

    asset_name = asset_map.get((target_os, target_arch))
    if not asset_name:
        raise SystemExit(f"Unsupported platform: {target_os}/{target_arch}")

    release_path = "latest/download" if release_tag == "latest" else f"download/{release_tag}"
    url = f"https://github.com/nxtrace/NTrace-core/releases/{release_path}/{asset_name}"
    destination = "/usr/local/bin/nexttrace"
    expected = expected_digest(release_tag, asset_name)

    digest = hashlib.sha256()
    total = 0
    with urllib.request.urlopen(url, timeout=30) as response, open(destination, "wb") as output:
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            if total > 128 * 1024 * 1024:
                raise SystemExit('NextTrace asset exceeds size limit')
            digest.update(chunk)
            output.write(chunk)
    if digest.hexdigest() != expected:
        os.unlink(destination)
        raise SystemExit('NextTrace asset SHA256 mismatch')

    current_mode = os.stat(destination).st_mode
    os.chmod(destination, current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


if __name__ == "__main__":
    main()
