#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Create a macOS .app launcher with credential and file-safety guards."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import math
import os
import plistlib
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unicodedata
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlparse


CREATOR_ID = "macos-web-app-shortcut"
CREATOR_VERSION = "0.2.0"
MAX_RETRIES = 120
MAX_RETRY_DELAY = 10.0
OSACOMPILE = "/usr/bin/osacompile"
SIPS = "/usr/bin/sips"
ICONUTIL = "/usr/bin/iconutil"
CODESIGN = "/usr/bin/codesign"

SENSITIVE_NAME_PATTERN = (
    r"(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|"
    r"id[_-]?token|session[_-]?token|oauth[_-]?token|authorization[_-]?code|"
    r"code[_-]?verifier|signed[_-]?request|cookies?|session(?:[_-]?id)?|"
    r"secret[_-]?key|auth(?:entication|orization)?(?:[_-]?(?:token|key))?|"
    r"authorization|credentials?|tokens?|secrets?|keys?|pass(?:word|wd)?)"
)
SENSITIVE_ASSIGNMENT = re.compile(
    rf"(?ix)\b(?P<key>{SENSITIVE_NAME_PATTERN})\b\s*[=:]\s*(?P<value>\S+)"
)
SENSITIVE_FLAG = re.compile(
    rf"(?ix)(?:^|\s)--(?P<key>{SENSITIVE_NAME_PATTERN})\s+(?P<value>\S+)"
)
ENV_REFERENCE = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\})")

SECRET_PATTERNS = (
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,})\b"),
    re.compile(r"\b(?:sk-[A-Za-z0-9_-]{16,}|sk_(?:live|test)_[A-Za-z0-9_-]{16,})\b"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\b(?:set-)?cookie\s*:\s*(?!\$|\$\{)\S+"),
)

SENSITIVE_QUERY_KEY = re.compile(
    r"(?ix)^(?:api[_-]?key|access[_-]?token|refresh[_-]?token|auth(?:orization)?|"
    r"auth[_-]?(?:token|key)|token|secret|key|pass(?:word|wd)?|credentials?|"
    r"cookie|session(?:[_-]?(?:id|token))?|id[_-]?token|oauth[_-]?token|"
    r"code(?:[_-]?verifier)?|authorization[_-]?code|signed[_-]?request)$"
)
SENSITIVE_PARAMETER_SEGMENTS = {
    "token", "secret", "key", "password", "passwd", "authorization",
    "credential", "credentials", "cookie", "session",
}


def fail(message: str) -> None:
    raise SystemExit(f"Error: {message}")


def run(command: list[str]) -> None:
    try:
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.PIPE, text=True)
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or "").strip().splitlines()
        suffix = f": {detail[-1]}" if detail else ""
        fail(f"{Path(command[0]).name} failed with exit code {exc.returncode}{suffix}")


def applescript_quote(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def assert_plain_text(label: str, value: str | None) -> None:
    if value and any(
        unicodedata.category(character) in {"Cc", "Cf", "Cs"}
        or character in {"\u2028", "\u2029"}
        for character in value
    ):
        fail(f"{label} must not contain control characters")


def assert_no_secret(label: str, value: str | None) -> None:
    if not value:
        return
    for pattern in SECRET_PATTERNS:
        if pattern.search(value):
            fail(
                f"{label} appears to contain a credential. Store secrets in the "
                "service's protected configuration instead."
            )
    for pattern in (SENSITIVE_ASSIGNMENT, SENSITIVE_FLAG):
        for match in pattern.finditer(value):
            if not ENV_REFERENCE.fullmatch(match.group("value")):
                fail(
                    f"{label} appears to assign a credential named {match.group('key')!r}. "
                    "Only an exact $NAME or ${NAME} reference is allowed; store the value "
                    "in the service's protected configuration."
                )


def is_loopback_host(hostname: str) -> bool:
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def is_sensitive_parameter_name(name: str) -> bool:
    decoded = unquote(name).lower()
    if SENSITIVE_QUERY_KEY.fullmatch(decoded):
        return True
    segments = [segment for segment in re.split(r"[^a-z0-9]+", decoded) if segment]
    if any(segment in SENSITIVE_PARAMETER_SEGMENTS for segment in segments):
        return True
    normalized = "_".join(segments)
    return normalized in {
        "code", "code_verifier", "authorization_code", "id_token",
        "session_token", "oauth_token", "signed_request",
    }


def validate_url(
    label: str,
    value: str,
    allow_remote: bool = False,
    allow_insecure_remote_http: bool = False,
) -> None:
    assert_plain_text(label, value)
    assert_no_secret(label, value)
    if any(character.isspace() for character in value) or "\\" in value:
        fail(f"{label} must not contain whitespace or backslashes")
    try:
        parsed = urlparse(value)
    except ValueError:
        fail(f"{label} is malformed")
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        fail(f"{label} must be an http(s) URL")
    try:
        parsed.port
    except ValueError:
        fail(f"{label} contains an invalid port")
    if parsed.username or parsed.password:
        fail(f"{label} must not contain embedded credentials")
    for component_name, component in (
        ("path", parsed.path), ("query", parsed.query), ("fragment", parsed.fragment)
    ):
        decoded = unquote(component)
        assert_plain_text(f"{label} {component_name}", decoded)
        assert_no_secret(f"{label} {component_name}", decoded)
    for key, query_value in parse_qsl(parsed.query, keep_blank_values=True):
        if query_value and is_sensitive_parameter_name(key):
            fail(f"{label} contains a sensitive query parameter named {key!r}")
        assert_no_secret(f"{label} query value", query_value)
    for key, fragment_value in parse_qsl(parsed.fragment, keep_blank_values=True):
        if fragment_value and is_sensitive_parameter_name(key):
            fail(f"{label} contains a sensitive fragment parameter named {key!r}")
        assert_no_secret(f"{label} fragment value", fragment_value)
    if not is_loopback_host(parsed.hostname):
        if not allow_remote:
            fail(f"{label} must use localhost or a loopback address unless remote access is explicitly authorized")
        if parsed.scheme != "https" and not allow_insecure_remote_http:
            fail(f"{label} must use HTTPS for a remote host; cleartext HTTP needs a separate explicit override")


def display_origin(value: str) -> str:
    parsed = urlparse(value)
    hostname = parsed.hostname or ""
    host = f"[{hostname}]" if ":" in hostname else hostname
    try:
        port = f":{parsed.port}" if parsed.port else ""
    except ValueError:
        port = ""
    return f"{parsed.scheme}://{host}{port}"


def url_origin(value: str) -> tuple[str, str, int]:
    parsed = urlparse(value)
    default_port = 443 if parsed.scheme == "https" else 80
    return parsed.scheme, (parsed.hostname or "").lower(), parsed.port or default_port


def log_filename(name: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-.").lower()[:40]
    digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:10]
    return f"{slug or 'app'}-{digest}-launcher.log"


def create_icns(source: Path, destination: Path, build_dir: Path) -> None:
    if source.suffix.lower() == ".icns":
        shutil.copyfile(source, destination)
        return
    if source.suffix.lower() != ".png":
        fail("icon must be a PNG or ICNS file")
    iconset = build_dir / "AppIcon.iconset"
    iconset.mkdir()
    sizes = (
        (16, "icon_16x16.png"), (32, "icon_16x16@2x.png"),
        (32, "icon_32x32.png"), (64, "icon_32x32@2x.png"),
        (128, "icon_128x128.png"), (256, "icon_128x128@2x.png"),
        (256, "icon_256x256.png"), (512, "icon_256x256@2x.png"),
        (512, "icon_512x512.png"), (1024, "icon_512x512@2x.png"),
    )
    for pixels, filename in sizes:
        run([SIPS, "-z", str(pixels), str(pixels), str(source), "--out", str(iconset / filename)])
    run([ICONUTIL, "-c", "icns", str(iconset), "-o", str(destination)])


def health_probe(url: str) -> str:
    parsed = urlparse(url)
    no_proxy = "--noproxy '*' " if parsed.hostname and is_loopback_host(parsed.hostname) else ""
    return (
        "{ if http_status=$(/usr/bin/curl --disable --globoff "
        f"{no_proxy}"
        "--silent "
        "--output /dev/null --write-out '%{http_code}' --max-time 1 "
        f"--url {shlex.quote(url)}); then case \"$http_status\" in "
        "2??) true ;; *) false ;; esac; else false; fi; }"
    )


def make_shell_command(args: argparse.Namespace, log_path: Path) -> str:
    if not args.command:
        return ""
    command = args.command
    if args.working_dir:
        command = f"cd {shlex.quote(str(args.working_dir))} && {command}"
    background = (
        f"/usr/bin/nohup /bin/zsh -fc {shlex.quote(command)} "
        f">> {shlex.quote(str(log_path))} 2>&1 &"
    )
    log_message = (
        f"/usr/bin/printf '%s\\n' 'Port {args.port} is already occupied and the health check failed; "
        f"startup was stopped.' >> {shlex.quote(str(log_path))}"
    )
    port_busy = (
        f"/usr/sbin/lsof -nP -iTCP:{args.port} -sTCP:LISTEN >/dev/null 2>&1"
        if args.port else ""
    )
    log_guard = (
        f"if [ -L {shlex.quote(str(log_path))} ] || "
        f"[ ! -f {shlex.quote(str(log_path))} ] || "
        f"[ ! -O {shlex.quote(str(log_path))} ]; then exit 73; fi; "
    )
    if args.health_url and port_busy:
        logic = (
            f"if {health_probe(args.health_url)}; then :; "
            f"elif {port_busy}; then {log_message}; exit 69; else {background} fi"
        )
    elif args.health_url:
        logic = f"if {health_probe(args.health_url)}; then :; else {background} fi"
    elif port_busy:
        logic = f"if {port_busy}; then {log_message}; exit 69; else {background} fi"
    else:
        logic = background
    return log_guard + logic


def build_applescript(args: argparse.Namespace, shell_command: str) -> str:
    lines = ["on run", "  try"]
    if shell_command:
        lines.append(f'    do shell script "{applescript_quote(shell_command)}"')
    if args.health_url:
        health = health_probe(args.health_url)
        lines.extend([
            "    set serviceReady to false",
            f"    repeat {args.retries} times",
            "      try",
            f'        do shell script "{applescript_quote(health)}"',
            "        set serviceReady to true",
            "        exit repeat",
            "      on error",
            f"        delay {args.retry_delay}",
            "      end try",
            "    end repeat",
            "    if serviceReady is false then",
            f'      set dialogResult to display dialog "{applescript_quote(args.name)} did not become ready." buttons {{"Cancel", "Open Anyway"}} default button "Cancel" with icon caution',
            '      if button returned of dialogResult is "Cancel" then return',
            "    end if",
        ])
    lines.extend([
        f'    open location "{applescript_quote(args.url)}"',
        "  on error errorMessage",
        f'    display dialog "{applescript_quote(args.name)} failed to start:" & return & errorMessage buttons {{"OK"}} default button "OK" with icon stop',
        "  end try",
        "end run",
        "",
    ])
    return "\n".join(lines)


def update_plist(plist_path: Path, app_name: str) -> None:
    with plist_path.open("rb") as handle:
        data = plistlib.load(handle)
    data["CFBundleName"] = app_name
    data["CFBundleDisplayName"] = app_name
    data["CFBundleIdentifier"] = (
        "com.agenttools.macos-web-app-shortcut.app-"
        + hashlib.sha256(app_name.encode("utf-8")).hexdigest()[:16]
    )
    data["NSHighResolutionCapable"] = True
    data["MacOSWebShortcutCreator"] = CREATOR_ID
    data["MacOSWebShortcutCreatorVersion"] = CREATOR_VERSION
    with plist_path.open("wb") as handle:
        plistlib.dump(data, handle, sort_keys=True)


def validate_generated_bundle(target: Path) -> tuple[int, int]:
    if target.is_symlink():
        fail(f"refusing to replace a symbolic link: {target}")
    plist_path = target / "Contents" / "Info.plist"
    executable = target / "Contents" / "MacOS" / "applet"
    if not target.is_dir() or not plist_path.is_file() or not executable.is_file():
        fail(f"refusing to replace an unrecognized app bundle: {target}")
    try:
        with plist_path.open("rb") as handle:
            data = plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException):
        fail(f"refusing to replace an app with an unreadable Info.plist: {target}")
    if data.get("MacOSWebShortcutCreator") != CREATOR_ID:
        fail(f"refusing to replace an app not created by this tool: {target}")
    target_stat = target.lstat()
    return target_stat.st_dev, target_stat.st_ino


def prepare_log_path(log_path: Path, create_private_parent: bool = False) -> None:
    parent = log_path.parent
    if create_private_parent:
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if parent.is_symlink() or not parent.is_dir():
        fail(f"log directory must be a regular directory: {parent}")
    parent_stat = parent.stat()
    if parent_stat.st_uid != os.getuid() or stat.S_IMODE(parent_stat.st_mode) & 0o077:
        fail(f"log directory must be owned by the current user and private (0700): {parent}")
    if log_path.is_symlink():
        fail(f"log path must not be a symbolic link: {log_path}")
    existed = log_path.exists()
    if existed:
        existing_stat = log_path.lstat()
        if not stat.S_ISREG(existing_stat.st_mode) or existing_stat.st_nlink != 1:
            fail("existing log path must be a single-link regular file")
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(log_path, flags, 0o600)
    except OSError as exc:
        fail(f"could not securely open log file: {exc}")
    try:
        file_stat = os.fstat(descriptor)
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or file_stat.st_uid != os.getuid()
            or file_stat.st_nlink != 1
        ):
            fail("log file must be a regular file owned by the current user")
        if existed and stat.S_IMODE(file_stat.st_mode) & 0o077:
            fail("existing log file must not be accessible by group or other users")
        os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True, help="Visible application name")
    parser.add_argument("--url", required=True, help="URL opened by the shortcut")
    parser.add_argument("--health-url", help="Optional URL polled before opening")
    parser.add_argument("--port", type=int, help="Optional local port used to avoid duplicate starts")
    parser.add_argument("--command", help="Optional trusted command that starts the local service")
    parser.add_argument("--working-dir", type=Path, help="Optional working directory for the command")
    parser.add_argument("--icon", type=Path, help="Optional PNG or ICNS icon")
    parser.add_argument("--output-dir", type=Path, required=True, help="Directory that receives the .app")
    parser.add_argument("--log", type=Path, help="Launcher log path; defaults to the macOS temporary directory")
    parser.add_argument("--retries", type=int, default=30)
    parser.add_argument("--retry-delay", type=float, default=0.5)
    parser.add_argument("--allow-remote", action="store_true", help="Allow a non-loopback destination URL after explicit authorization")
    parser.add_argument("--allow-remote-health", action="store_true", help="Allow a non-loopback health URL after separate explicit authorization")
    parser.add_argument("--allow-insecure-remote-http", action="store_true", help="Allow cleartext HTTP to a remote host after explicit risk acceptance")
    parser.add_argument("--allow-cross-origin-health", action="store_true", help="Allow health and destination URLs to use different origins")
    parser.add_argument("--allow-port-mismatch", action="store_true", help="Allow --port to differ from the destination URL port")
    parser.add_argument("--overwrite", action="store_true", help="Replace a launcher previously created by this tool")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    if sys.platform != "darwin":
        fail("this script must run on macOS")
    args = parse_args(argv)
    if not args.name.strip() or "/" in args.name or ":" in args.name or args.name in {".", ".."}:
        fail("name must be a non-empty macOS application name without slashes or colons")
    values = (
        ("name", args.name), ("url", args.url), ("health URL", args.health_url),
        ("command", args.command),
        ("working directory", str(args.working_dir) if args.working_dir else None),
        ("icon path", str(args.icon) if args.icon else None),
        ("output directory", str(args.output_dir)),
        ("log path", str(args.log) if args.log else None),
    )
    for label, value in values:
        assert_plain_text(label, value)
        assert_no_secret(label, value)
    if args.icon and args.icon.is_symlink():
        fail(f"icon must not be a symbolic link: {args.icon}")
    if args.output_dir.is_symlink():
        fail(f"output directory must not be a symbolic link: {args.output_dir}")
    if args.log and args.log.is_symlink():
        fail(f"log path must not be a symbolic link: {args.log}")
    if args.working_dir:
        args.working_dir = args.working_dir.expanduser().resolve(strict=False)
    if args.icon:
        args.icon = args.icon.expanduser().resolve(strict=False)
    args.output_dir = args.output_dir.expanduser().resolve(strict=False)
    if args.log:
        args.log = args.log.expanduser().resolve(strict=False)
    validate_url("url", args.url, args.allow_remote, args.allow_insecure_remote_http)
    if args.health_url:
        validate_url(
            "health URL", args.health_url, args.allow_remote_health,
            args.allow_insecure_remote_http,
        )
        if not args.allow_cross_origin_health and url_origin(args.health_url) != url_origin(args.url):
            fail("health URL must use the destination origin unless --allow-cross-origin-health is explicitly authorized")
    if args.port is not None and not 1 <= args.port <= 65535:
        fail("port must be between 1 and 65535")
    if args.port is not None and not args.allow_port_mismatch and args.port != url_origin(args.url)[2]:
        fail("port must match the destination URL port unless --allow-port-mismatch is explicitly authorized")
    if args.working_dir and not args.working_dir.is_dir():
        fail(f"working directory does not exist: {args.working_dir}")
    if args.icon and (not args.icon.is_file() or args.icon.is_symlink()):
        fail(f"icon must be a regular PNG or ICNS file: {args.icon}")
    if not 1 <= args.retries <= MAX_RETRIES:
        fail(f"retries must be between 1 and {MAX_RETRIES}")
    if not math.isfinite(args.retry_delay) or not 0 < args.retry_delay <= MAX_RETRY_DELAY:
        fail(f"retry delay must be finite and between 0 and {MAX_RETRY_DELAY}")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    if not args.output_dir.is_dir():
        fail(f"output directory is not a directory: {args.output_dir}")
    output_stat = args.output_dir.stat()
    if output_stat.st_uid != os.getuid() or stat.S_IMODE(output_stat.st_mode) & 0o022:
        fail("output directory must be owned by the current user and not writable by group or others")
    target = args.output_dir / f"{args.name}.app"
    expected_target_identity: tuple[int, int] | None = None
    if target.exists() or target.is_symlink():
        if not args.overwrite:
            fail(f"target already exists: {target}; use --overwrite only after confirming it")
        expected_target_identity = validate_generated_bundle(target)

    default_log_dir = Path(tempfile.gettempdir()) / CREATOR_ID
    log_path = args.log or default_log_dir / log_filename(args.name)
    assert_no_secret("log path", str(log_path))
    prepare_log_path(log_path, create_private_parent=args.log is None)
    log_path = log_path.resolve(strict=True)

    with tempfile.TemporaryDirectory(prefix=".macos-web-shortcut-build-", dir=args.output_dir) as temporary:
        build_dir = Path(temporary)
        source = build_dir / "launcher.applescript"
        staged = build_dir / "Generated.app"
        source.write_text(build_applescript(args, make_shell_command(args, log_path)), encoding="utf-8")
        run([OSACOMPILE, "-o", str(staged), str(source)])
        update_plist(staged / "Contents" / "Info.plist", args.name)
        if args.icon:
            create_icns(args.icon, staged / "Contents" / "Resources" / "applet.icns", build_dir)
        # Ad-hoc signing is for local use only; public binaries need Developer ID signing and notarization.
        run([CODESIGN, "--force", "--sign", "-", str(staged)])
        run([CODESIGN, "--verify", "--strict", str(staged)])
        staged_stat = staged.lstat()
        staged_identity = (staged_stat.st_dev, staged_stat.st_ino)

        if target.exists() or target.is_symlink():
            if expected_target_identity is None:
                fail(f"target appeared during creation and will not be replaced: {target}")
            if validate_generated_bundle(target) != expected_target_identity:
                fail(f"target changed during creation and will not be replaced: {target}")
            backup_container = Path(tempfile.mkdtemp(
                prefix=".macos-web-shortcut-backup-", dir=args.output_dir
            ))
            backup = backup_container / "Previous.app"
            target.rename(backup)
            try:
                staged.rename(target)
                target_stat = target.lstat()
                if (target_stat.st_dev, target_stat.st_ino) != staged_identity:
                    fail("installed target identity changed before verification")
                validate_generated_bundle(target)
                run([CODESIGN, "--verify", "--strict", str(target)])
            except BaseException as install_error:
                current_identity: tuple[int, int] | None = None
                if target.exists() or target.is_symlink():
                    current_stat = target.lstat()
                    current_identity = (current_stat.st_dev, current_stat.st_ino)
                if current_identity is not None and current_identity != staged_identity:
                    fail(
                        f"installation conflict detected; conflicting target was preserved at {target} "
                        f"and the previous launcher remains at {backup}"
                    )
                failed_path: Path | None = None
                if current_identity == staged_identity:
                    failed_container = Path(tempfile.mkdtemp(
                        prefix=".macos-web-shortcut-failed-", dir=args.output_dir
                    ))
                    failed_path = failed_container / "Failed.app"
                    target.rename(failed_path)
                try:
                    backup.rename(target)
                    backup_container.rmdir()
                except OSError as restore_error:
                    fail(
                        f"installation failed and automatic restore also failed; the previous "
                        f"launcher remains at {backup}: {restore_error}"
                    )
                if failed_path:
                    print(f"Failed replacement preserved at: {failed_path}", file=sys.stderr)
                raise install_error
            shutil.rmtree(backup_container)
        else:
            if expected_target_identity is not None:
                fail(f"existing target disappeared during creation and will not be replaced: {target}")
            staged.rename(target)
            try:
                target_stat = target.lstat()
                if (target_stat.st_dev, target_stat.st_ino) != staged_identity:
                    fail("installed target identity changed before verification")
                validate_generated_bundle(target)
                run([CODESIGN, "--verify", "--strict", str(target)])
            except BaseException as install_error:
                current_identity: tuple[int, int] | None = None
                if target.exists() or target.is_symlink():
                    current_stat = target.lstat()
                    current_identity = (current_stat.st_dev, current_stat.st_ino)
                if current_identity is not None and current_identity != staged_identity:
                    fail(f"installation conflict detected; conflicting target was preserved at {target}")
                if current_identity == staged_identity:
                    failed_container = Path(tempfile.mkdtemp(
                        prefix=".macos-web-shortcut-failed-", dir=args.output_dir
                    ))
                    failed_path = failed_container / "Failed.app"
                    target.rename(failed_path)
                    fail(f"final verification failed; generated launcher was preserved at {failed_path}")
                raise install_error

    print(f"Created: {target}")
    print(f"URL origin: {display_origin(args.url)}")
    print(f"Log: {log_path}")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except (OSError, plistlib.InvalidFileException, UnicodeError) as error:
        fail(f"operation failed safely: {error}")
