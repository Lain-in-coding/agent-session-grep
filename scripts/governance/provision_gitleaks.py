"""Provision only pinned public archives; scanning never downloads anything."""
import hashlib
import io
from pathlib import Path
import platform as host
import stat
import tarfile
import urllib.request
import zipfile
from common import Parser, fail, main_guard, read_bytes

VERSION = "8.30.1"
SOURCE = "83d9cd684c87d95d656c1458ef04895a7f1cbd8e"
ASSETS = {
    "linux_x64": ("tar.gz", "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"),
    "windows_x64": ("zip", "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e"),
    "darwin_x64": ("tar.gz", "dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709"),
    "darwin_arm64": ("tar.gz", "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5"),
}
MAX_ARCHIVE = 50 * 1024 * 1024
MAX_MEMBER = 64 * 1024 * 1024


def native_platform():
    system = host.system().lower()
    machine = host.machine().lower()
    arch = "x64" if machine in ("amd64", "x86_64") else "arm64" if machine in ("arm64", "aarch64") else None
    name = f"{system}_{arch}"
    if name not in ASSETS:
        fail("unsupported-scanner-platform")
    return name


def asset_name(platform):
    if platform not in ASSETS:
        fail("unsupported-scanner-platform")
    return f"gitleaks_{VERSION}_{platform}.{ASSETS[platform][0]}"


def verify_archive(path, platform):
    asset_name(platform)
    data = read_bytes(path, MAX_ARCHIVE)
    if hashlib.sha256(data).hexdigest() != ASSETS[platform][1]:
        fail("scanner-archive-hash-mismatch")
    return data


def extract_verified(path, platform):
    # Verify the same bytes that are parsed, avoiding a verify/reopen race.
    data = verify_archive(path, platform)
    binary = "gitleaks.exe" if platform == "windows_x64" else "gitleaks"
    allowed = {binary, "LICENSE", "README.md"}
    result = {}

    def member(name, size, regular, reader):
        if name not in allowed or name in result or not regular or not 0 < size <= MAX_MEMBER:
            fail("unsafe-scanner-archive")
        payload = reader()
        if len(payload) != size:
            fail("incomplete-scanner-archive")
        result[name] = payload

    try:
        if ASSETS[platform][0] == "zip":
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for info in archive.infolist():
                    mode = info.external_attr >> 16
                    regular = not info.is_dir() and not info.flag_bits & 1
                    regular = regular and stat.S_IFMT(mode) in (0, stat.S_IFREG)
                    member(info.filename, info.file_size, regular,
                           lambda i=info: archive.read(i))
        else:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
                for info in archive:
                    member(info.name, info.size, info.isfile() and not info.issparse(),
                           lambda i=info: archive.extractfile(i).read(MAX_MEMBER + 1))
    except (zipfile.BadZipFile, tarfile.TarError, EOFError, RuntimeError):
        fail("invalid-scanner-archive")
    if set(result) != allowed:
        fail("incomplete-scanner-archive")
    return result


def install_members(members, destination):
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name, data in members.items():
        path = destination / name
        with path.open("xb") as handle:
            handle.write(data)
        path.chmod(0o700 if name in ("gitleaks", "gitleaks.exe") else 0o600)


def main():
    parser = Parser(description=__doc__, epilog=(
        "This is the ONLY network operation. Fixed HTTPS release assets only; "
        "archive SHA256 is checked before parsing or executing. Keep LICENSE. "
        "Offline scanning re-verifies the archive, not a mutable installed executable."))
    parser.add_argument("--platform", choices=tuple(ASSETS), help="Defaults to supported native platform")
    parser.add_argument("--archive-file", help="Use an existing archive instead of downloading")
    parser.add_argument("--output-dir", required=True, help="New directory for archive, binary and MIT license")
    args = parser.parse_args()
    platform = args.platform or native_platform()
    output = Path(args.output_dir).resolve()
    if output.exists():
        fail("new-provision-directory-required")
    if args.archive_file:
        data = verify_archive(args.archive_file, platform)
        members = extract_verified(args.archive_file, platform)
    else:
        import tempfile
        url = f"https://github.com/gitleaks/gitleaks/releases/download/v{VERSION}/{asset_name(platform)}"
        # No environment proxy/credential injection. Redirects remain HTTPS.
        class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                if not newurl.startswith("https://"):
                    fail("unsafe-download-redirect")
                return super().redirect_request(req, fp, code, msg, headers, newurl)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), HTTPSRedirect())
        try:
            with opener.open(url, timeout=120) as response:
                data = response.read(MAX_ARCHIVE + 1)
        except OSError:
            fail("scanner-download-unavailable")
        if len(data) > MAX_ARCHIVE:
            fail("scanner-archive-size-limit")
        with tempfile.TemporaryDirectory(prefix="governance-provision-") as temporary:
            archive = Path(temporary) / asset_name(platform)
            archive.write_bytes(data)
            members = extract_verified(archive, platform)
    install_members(members, output)
    (output / asset_name(platform)).write_bytes(data)
    return {"status": "provisioned", "scanner": VERSION, "source": SOURCE,
            "platform": platform, "archive_sha256": ASSETS[platform][1]}


if __name__ == "__main__":
    raise SystemExit(main_guard(main))
