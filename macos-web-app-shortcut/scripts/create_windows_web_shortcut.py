#!/usr/bin/env python3
"""Create a Windows .lnk launcher with credential and path-safety guards."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import math
import os
import re
import subprocess
import tempfile
import unicodedata
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlparse


CREATOR_ID = "windows-web-app-shortcut"
CREATOR_VERSION = "0.1.0"
MAX_RETRIES = 120
MAX_RETRY_DELAY = 10.0
REPARSE_POINT = 0x400
WINDOWS_RESERVED_NAMES = {
    "con", "prn", "aux", "nul",
    *(f"com{number}" for number in range(1, 10)),
    *(f"lpt{number}" for number in range(1, 10)),
}

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
    rf"(?ix)(?:^|\s)-{{1,2}}(?P<key>{SENSITIVE_NAME_PATTERN})\s+(?P<value>\S+)"
)
ENV_REFERENCE = re.compile(
    r"\$(?:[A-Za-z_][A-Za-z0-9_]*|env:[A-Za-z_][A-Za-z0-9_]*|"
    r"\{(?:env:)?[A-Za-z_][A-Za-z0-9_]*\})"
)

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
                    "Only an exact environment-variable reference is allowed; store the "
                    "value in the service's protected configuration."
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
        hostname = parsed.hostname
    except ValueError:
        fail(f"{label} is malformed")
    if parsed.scheme not in {"http", "https"} or not hostname:
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
    if not is_loopback_host(hostname):
        if not allow_remote:
            fail(
                f"{label} must use localhost or a loopback address unless remote access "
                "is explicitly authorized"
            )
        if parsed.scheme != "https" and not allow_insecure_remote_http:
            fail(
                f"{label} must use HTTPS for a remote host; cleartext HTTP needs a "
                "separate explicit override"
            )


def url_origin(value: str) -> tuple[str, str, int]:
    parsed = urlparse(value)
    default_port = 443 if parsed.scheme == "https" else 80
    return parsed.scheme, (parsed.hostname or "").lower(), parsed.port or default_port


def display_origin(value: str) -> str:
    scheme, hostname, port = url_origin(value)
    default_port = 443 if scheme == "https" else 80
    host = f"[{hostname}]" if ":" in hostname else hostname
    suffix = f":{port}" if port != default_port else ""
    return f"{scheme}://{host}{suffix}"


def ps_quote(value: str) -> str:
    """Quote a value as a PowerShell single-quoted string literal."""
    return "'" + value.replace("'", "''") + "'"


def windows_path_is_reparse(path: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return False
    return bool(attributes & REPARSE_POINT)


def log_filename(name: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-.").lower()[:40]
    digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:10]
    return f"{slug or 'app'}-{digest}-launcher.log"


def validate_name(name: str) -> None:
    assert_plain_text("name", name)
    if not name.strip() or name in {".", ".."}:
        fail("name must be non-empty")
    if len(name) > 120 or name[-1] in {".", " "}:
        fail("name is too long or ends with a dot/space")
    if any(character in name for character in '<>:/\\|?*"'):
        fail("name contains characters not allowed in Windows file names")
    if name.split(".", 1)[0].lower() in WINDOWS_RESERVED_NAMES:
        fail("name uses a reserved Windows device name")


def validate_generated_shortcut(target: Path, launcher: Path) -> None:
    if windows_path_is_reparse(target) or not target.is_file():
        fail(f"refusing to replace an unrecognized shortcut: {target}")
    if windows_path_is_reparse(launcher) or not launcher.is_file():
        fail(f"refusing to replace a launcher without a creator marker: {launcher}")
    try:
        header = launcher.read_text(encoding="utf-8-sig")[:512]
    except (OSError, UnicodeError):
        fail(f"refusing to replace an unreadable launcher: {launcher}")
    if f"# {CREATOR_ID} = {CREATOR_VERSION}" not in header:
        fail(f"refusing to replace a launcher not created by this tool: {launcher}")


def powershell_path() -> Path:
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    return Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"


def build_launcher_script(args: argparse.Namespace, log_path: Path) -> str:
    command = ps_quote(args.command) if args.command else "$null"
    working_dir = ps_quote(str(args.working_dir)) if args.working_dir else "$null"
    health_url = ps_quote(args.health_url) if args.health_url else "$null"
    health_proxy_disabled = "\u0024true" if args.health_url and is_loopback_host(urlparse(args.health_url).hostname or "") else "\u0024false"
    port = str(args.port) if args.port is not None else "$null"
    return f'''# {CREATOR_ID} = {CREATOR_VERSION}
# This launcher is inspectable and must never contain credentials.
$ErrorActionPreference = "Stop"
$Name = {ps_quote(args.name)}
$TargetUrl = {ps_quote(args.url)}
$HealthUrl = {health_url}
$DisableHealthProxy = {health_proxy_disabled}
$Command = {command}
$WorkingDirectory = {working_dir}
$Port = {port}
$Retries = {args.retries}
$RetryDelay = {args.retry_delay}
$LogPath = {ps_quote(str(log_path))}
$PowerShellPath = {ps_quote(str(powershell_path()))}

function Write-LauncherLog([string]$Message) {{
    $parent = Split-Path -Parent $LogPath
    if (!(Test-Path -LiteralPath $parent -PathType Container)) {{
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }}
    $existing = Get-Item -LiteralPath $LogPath -Force -ErrorAction SilentlyContinue
    if ($existing -and (($existing.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $existing.PSIsContainer)) {{
        throw "Refusing a reparse-point or directory log path."
    }}
    Add-Content -LiteralPath $LogPath -Value ("{{0}} {{1}}" -f (Get-Date -Format o), $Message) -Encoding UTF8
}}

function Show-Notice([string]$Message) {{
    try {{
        Add-Type -AssemblyName PresentationFramework
        [System.Windows.MessageBox]::Show($Message, $Name, "OK", "Warning") | Out-Null
    }} catch {{
        Write-Host $Message
    }}
}}

function Test-Health([string]$Url) {{
    if ([string]::IsNullOrWhiteSpace($Url)) {{ return $true }}
    try {{
        $request = @{{ UseBasicParsing = $true; Uri = $Url; TimeoutSec = 1; MaximumRedirection = 0 }}
        if ($DisableHealthProxy) {{ $request.Proxy = $null }}
        $response = Invoke-WebRequest @request
        return ($response.StatusCode -ge 200 -and $response.StatusCode -lt 300)
    }} catch {{
        return $false
    }}
}}

function Test-Port([int]$PortNumber) {{
    if (!$PortNumber) {{ return $false }}
    $client = New-Object System.Net.Sockets.TcpClient
    try {{
        $task = $client.ConnectAsync("127.0.0.1", $PortNumber)
        if (!$task.Wait(500)) {{ return $false }}
        return $client.Connected
    }} catch {{
        return $false
    }} finally {{
        $client.Dispose()
    }}
}}

try {{
    $serviceReady = if ($HealthUrl) {{ Test-Health $HealthUrl }} else {{ $false }}
    if (!$serviceReady -and $Command) {{
        if (Test-Port $Port) {{
            Write-LauncherLog ("Port {{0}} is occupied while the health check is failing; startup stopped." -f $Port)
            Show-Notice "The port is already in use, but the expected service is not healthy."
            exit 69
        }}
        $startParameters = @{{
            FilePath = $PowerShellPath
            ArgumentList = @("-NoProfile", "-NonInteractive", "-Command", $Command)
            WindowStyle = "Hidden"
        }}
        if ($WorkingDirectory) {{ $startParameters.WorkingDirectory = $WorkingDirectory }}
        Start-Process @startParameters | Out-Null
    }}
    if ($HealthUrl) {{
        $serviceReady = $false
        for ($attempt = 0; $attempt -lt $Retries; $attempt++) {{
            if (Test-Health $HealthUrl) {{ $serviceReady = $true; break }}
            Start-Sleep -Milliseconds ([int]($RetryDelay * 1000))
        }}
        if (!$serviceReady) {{
            Show-Notice "$Name did not become ready."
            exit 1
        }}
    }}
    Start-Process -FilePath $TargetUrl | Out-Null
}} catch {{
    try {{ Write-LauncherLog $_.Exception.Message }} catch {{}}
    Show-Notice "$Name failed to start: $($_.Exception.Message)"
    exit 1
}}
'''


def create_lnk(
    shortcut_path: Path,
    launcher_path: Path,
    output_dir: Path,
    icon_path: Path | None,
) -> None:
    ps = powershell_path()
    if not ps.is_file():
        fail(f"Windows PowerShell was not found at {ps}")
    helper_fd, helper_name = tempfile.mkstemp(prefix="web-shortcut-", suffix=".ps1")
    os.close(helper_fd)
    helper = Path(helper_name)
    helper.write_text(
        '''$ErrorActionPreference = "Stop"
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($env:DSH_SHORTCUT_PATH)
$shortcut.TargetPath = $env:DSH_TARGET_PATH
$shortcut.Arguments = $env:DSH_ARGUMENTS
$shortcut.WorkingDirectory = $env:DSH_WORKING_DIRECTORY
$shortcut.Description = $env:DSH_DESCRIPTION
if ($env:DSH_ICON_PATH) { $shortcut.IconLocation = $env:DSH_ICON_PATH + ",0" }
$shortcut.Save()
''',
        encoding="utf-8-sig",
    )
    environment = os.environ.copy()
    environment.update({
        "DSH_SHORTCUT_PATH": str(shortcut_path),
        "DSH_TARGET_PATH": str(ps),
        "DSH_ARGUMENTS": f'-NoProfile -NonInteractive -File "{launcher_path}"',
        "DSH_WORKING_DIRECTORY": str(output_dir),
        "DSH_DESCRIPTION": "Generated by windows-web-app-shortcut",
        "DSH_ICON_PATH": str(icon_path) if icon_path else "",
    })
    try:
        subprocess.run(
            [str(ps), "-NoProfile", "-NonInteractive", "-File", str(helper)],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", "") or str(exc)
        fail(f"PowerShell could not create the .lnk: {detail.strip()}")
    finally:
        try:
            helper.unlink()
        except OSError:
            pass
    if windows_path_is_reparse(shortcut_path) or not shortcut_path.is_file():
        fail(f"PowerShell did not create a regular shortcut: {shortcut_path}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True, help="Visible shortcut name")
    parser.add_argument("--url", required=True, help="URL opened by the shortcut")
    parser.add_argument("--health-url", help="Optional URL polled before opening")
    parser.add_argument("--port", type=int, help="Optional local port used to avoid duplicate starts")
    parser.add_argument("--command", help="Optional trusted PowerShell command that starts the local service")
    parser.add_argument("--working-dir", type=Path, help="Optional working directory for the command")
    parser.add_argument("--icon", type=Path, help="Optional ICO, EXE, or DLL icon file")
    parser.add_argument("--output-dir", type=Path, required=True, help="Directory receiving the .lnk and launcher")
    parser.add_argument("--log", type=Path, help="Launcher log path; defaults to the user's local app data")
    parser.add_argument("--retries", type=int, default=30)
    parser.add_argument("--retry-delay", type=float, default=0.5)
    parser.add_argument("--allow-remote", action="store_true")
    parser.add_argument("--allow-remote-health", action="store_true")
    parser.add_argument("--allow-insecure-remote-http", action="store_true")
    parser.add_argument("--allow-cross-origin-health", action="store_true")
    parser.add_argument("--allow-port-mismatch", action="store_true")
    parser.add_argument("--overwrite", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    if os.name != "nt":
        fail("this script must run on Windows")
    args = parse_args(argv)
    validate_name(args.name)
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
    args.output_dir = args.output_dir.expanduser().resolve(strict=False)
    if args.output_dir.exists() and windows_path_is_reparse(args.output_dir):
        fail(f"output directory must not be a reparse point: {args.output_dir}")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    if not args.output_dir.is_dir():
        fail(f"output directory is not a directory: {args.output_dir}")
    if args.working_dir:
        args.working_dir = args.working_dir.expanduser().resolve(strict=False)
        if windows_path_is_reparse(args.working_dir) or not args.working_dir.is_dir():
            fail(f"working directory must be a regular directory: {args.working_dir}")
    if args.icon:
        args.icon = args.icon.expanduser().resolve(strict=False)
        if windows_path_is_reparse(args.icon) or not args.icon.is_file():
            fail(f"icon must be a regular ICO, EXE, or DLL file: {args.icon}")
        if args.icon.suffix.lower() not in {".ico", ".exe", ".dll"}:
            fail("Windows icons must be ICO, EXE, or DLL files")
    if args.log:
        args.log = args.log.expanduser().resolve(strict=False)
    log_root = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    log_path = args.log or log_root / CREATOR_ID / log_filename(args.name)
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
    if args.working_dir is None and args.command and os.name == "nt":
        args.working_dir = Path.cwd()
    if not 1 <= args.retries <= MAX_RETRIES:
        fail(f"retries must be between 1 and {MAX_RETRIES}")
    if not math.isfinite(args.retry_delay) or not 0 < args.retry_delay <= MAX_RETRY_DELAY:
        fail(f"retry delay must be finite and between 0 and {MAX_RETRY_DELAY}")

    shortcut = args.output_dir / f"{args.name}.lnk"
    launcher = args.output_dir / f"{args.name}.launcher.ps1"
    if shortcut.exists() or shortcut.is_symlink() or launcher.exists() or launcher.is_symlink():
        if not args.overwrite:
            fail(f"target already exists: {shortcut}; use --overwrite only after confirming it")
        validate_generated_shortcut(shortcut, launcher)

    launcher_text = build_launcher_script(args, log_path)
    launcher_fd, launcher_name = tempfile.mkstemp(
        prefix=".windows-web-shortcut-", suffix=".ps1", dir=args.output_dir
    )
    os.close(launcher_fd)
    temporary_launcher = Path(launcher_name)
    try:
        temporary_launcher.write_text(launcher_text, encoding="utf-8-sig")
        os.replace(temporary_launcher, launcher)
    except OSError as exc:
        fail(f"could not write launcher safely: {exc}")
    finally:
        if temporary_launcher.exists():
            temporary_launcher.unlink(missing_ok=True)
    create_lnk(shortcut, launcher, args.output_dir, args.icon)
    print(f"Created: {shortcut}")
    print(f"Launcher: {launcher}")
    print(f"URL origin: {display_origin(args.url)}")
    print(f"Log: {log_path}")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except (OSError, UnicodeError) as error:
        fail(f"operation failed safely: {error}")
