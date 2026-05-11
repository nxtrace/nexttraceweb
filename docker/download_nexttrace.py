import os
import platform
import stat
import urllib.request


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

    with urllib.request.urlopen(url) as response, open(destination, "wb") as output:
        output.write(response.read())

    current_mode = os.stat(destination).st_mode
    os.chmod(destination, current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


if __name__ == "__main__":
    main()
