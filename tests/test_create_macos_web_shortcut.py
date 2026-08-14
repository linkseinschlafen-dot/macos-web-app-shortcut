from __future__ import annotations

import importlib.util
import os
import plistlib
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "macos-web-app-shortcut" / "scripts" / "create_macos_web_shortcut.py"
SYSTEM_ICON = Path(
    "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/GenericApplicationIcon.icns"
)
SPEC = importlib.util.spec_from_file_location("shortcut_builder", SCRIPT)
assert SPEC and SPEC.loader
shortcut_builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(shortcut_builder)


class SecretDetectionTests(unittest.TestCase):
    def assert_rejected(self, value: str) -> None:
        with self.assertRaises(SystemExit):
            shortcut_builder.assert_no_secret("test input", value)

    def test_rejects_common_secret_shapes(self) -> None:
        # Synthetic values are split so repository secret scanners do not mistake them for live credentials.
        jwt_value = "eyJhbGciOiJIUzI1NiJ9" + "." + "abcdefghijklmno" + "." + "pqrstuvwxyz1234"
        samples = (
            "TOKEN=not-a-real-secret-value",
            "secret_key=not-a-real-secret-value",
            "Authorization: Bearer abcdefghijklmnop",
            "Bearer " + jwt_value,
            jwt_value,
            "AWS_ACCESS_KEY_ID=" + "AK" + "IA" + "IOSFODNN7EXAMPLE",
            "gl" + "pat-" + "0123456789abcdef",
            "xox" + "b-" + "1234567890-abcdefghijklmnop",
            "AI" + "za" + "0123456789abcdefghijklmnopqrst",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
            "Cookie: session-value-is-private",
            "Cookie: $'synthetic-secret'",
            "--cookie synthetic-secret",
            "--session-token synthetic-secret",
            "TOKEN=$'synthetic-secret'",
            "--client-secret synthetic-secret",
        )
        for sample in samples:
            with self.subTest(sample=sample.split("=")[0]):
                self.assert_rejected(sample)

    def test_allows_environment_variable_reference(self) -> None:
        shortcut_builder.assert_no_secret("command", "TOKEN=$TOKEN")
        shortcut_builder.assert_no_secret("command", "API_KEY=${API_KEY}")

    def test_rejects_sensitive_url_query(self) -> None:
        with self.assertRaises(SystemExit):
            shortcut_builder.validate_url("url", "http://127.0.0.1:3000/?token=test-value")

    def test_rejects_percent_encoded_secrets_in_url_components(self) -> None:
        samples = (
            "http://127.0.0.1:3000/path/sk%2Dsyntheticcredential123456",
            "http://127.0.0.1:3000/?view=sk%2Dsyntheticcredential123456",
            "http://127.0.0.1:3000/#access%5Ftoken=synthetic-value",
            "http://127.0.0.1:3000/?token%5B%5D=synthetic-value",
            "http://127.0.0.1:3000/?auth%5Btoken%5D=synthetic-value",
            "http://127.0.0.1:3000/#code_verifier=synthetic-value",
            "http://127.0.0.1:3000/#id_token=synthetic-value",
            "http://127.0.0.1:3000/?oauth.token=synthetic-value",
            "http://127.0.0.1:3000/?signed_request=synthetic-value",
        )
        for sample in samples:
            with self.subTest(sample=sample):
                with self.assertRaises(SystemExit):
                    shortcut_builder.validate_url("url", sample)


class InputValidationTests(unittest.TestCase):
    def test_rejects_control_characters(self) -> None:
        with self.assertRaises(SystemExit):
            shortcut_builder.assert_plain_text("name", "line one\nline two")

    def test_remote_url_requires_explicit_permission(self) -> None:
        with self.assertRaises(SystemExit):
            shortcut_builder.validate_url("url", "https://example.com/")
        shortcut_builder.validate_url("url", "https://example.com/", allow_remote=True)
        with self.assertRaises(SystemExit):
            shortcut_builder.validate_url("url", "http://example.com/", allow_remote=True)
        shortcut_builder.validate_url(
            "url", "http://example.com/", allow_remote=True,
            allow_insecure_remote_http=True,
        )

    def test_rejects_malformed_or_obfuscated_url(self) -> None:
        for sample in ("http://[invalid", "http://127.0.0.1/path with space", "http://127.0.0.1/a\\b"):
            with self.subTest(sample=sample):
                with self.assertRaises(SystemExit):
                    shortcut_builder.validate_url("url", sample)

    def test_url_output_omits_path_and_query(self) -> None:
        self.assertEqual(
            shortcut_builder.display_origin("http://127.0.0.1:3000/private/path?view=one"),
            "http://127.0.0.1:3000",
        )

    def test_health_probe_curl_options_follow_origin_policy(self) -> None:
        local_probe = shortcut_builder.health_probe("http://127.0.0.1:3000/health{one}")
        remote_probe = shortcut_builder.health_probe("https://example.com/health")
        self.assertIn("--disable --globoff", local_probe)
        self.assertIn("--url", local_probe)
        self.assertIn("--noproxy", local_probe)
        self.assertNotIn("--noproxy", remote_probe)

    def test_non_ascii_log_names_do_not_collide(self) -> None:
        first = shortcut_builder.log_filename("我的服务")
        second = shortcut_builder.log_filename("我的面板")
        self.assertNotEqual(first, second)
        self.assertTrue(first.startswith("app-"))

@unittest.skipUnless(sys.platform == "darwin", "macOS integration test")
class MacOSIntegrationTests(unittest.TestCase):
    def run_builder(
        self, *arguments: str, env: dict[str, str] | None = None,
        timeout: float = 10.0, cwd: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), *arguments],
            capture_output=True,
            text=True,
            check=False,
            env=env,
            timeout=timeout,
            cwd=cwd,
        )

    @unittest.skipUnless(SYSTEM_ICON.is_file(), "system test icon unavailable")
    def test_creates_signed_marked_app_with_icon(self) -> None:
        with tempfile.TemporaryDirectory(prefix="shortcut-test-") as temporary:
            log_path = Path(temporary) / "launcher.log"
            result = self.run_builder(
                "--name", "测试服务",
                "--url", "http://127.0.0.1:39001/",
                "--icon", str(SYSTEM_ICON),
                "--log", str(log_path),
                "--output-dir", temporary,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            app = Path(temporary) / "测试服务.app"
            with (app / "Contents" / "Info.plist").open("rb") as handle:
                plist = plistlib.load(handle)
            self.assertEqual(plist["MacOSWebShortcutCreator"], shortcut_builder.CREATOR_ID)
            self.assertTrue(plist["CFBundleIdentifier"].startswith("com.agenttools."))
            self.assertTrue((app / "Contents" / "Resources" / "applet.icns").is_file())
            self.assertEqual(os.stat(log_path).st_mode & 0o777, 0o600)
            verify = subprocess.run(
                [shortcut_builder.CODESIGN, "--verify", "--strict", str(app)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(verify.returncode, 0, verify.stderr)

    def test_refuses_to_overwrite_unmarked_app_directory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="shortcut-test-") as temporary:
            target = Path(temporary) / "Unrelated.app"
            target.mkdir()
            protected = target / "important.txt"
            protected.write_text("keep", encoding="utf-8")
            result = self.run_builder(
                "--name", "Unrelated",
                "--url", "http://127.0.0.1:39002/",
                "--output-dir", temporary,
                "--overwrite",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(protected.read_text(encoding="utf-8"), "keep")

    def test_overwrites_only_a_marked_launcher_and_compiles_health_flow(self) -> None:
        with tempfile.TemporaryDirectory(prefix="shortcut-test-") as temporary:
            common = (
                "--name", "Health Test",
                "--url", "http://127.0.0.1:39003/",
                "--health-url", "http://127.0.0.1:39003/health",
                "--port", "39003",
                "--command", "python3 -m http.server 39003 --bind 127.0.0.1",
                "--working-dir", temporary,
                "--output-dir", temporary,
            )
            first = self.run_builder(*common)
            self.assertEqual(first.returncode, 0, first.stderr)
            second = self.run_builder(*common, "--overwrite")
            self.assertEqual(second.returncode, 0, second.stderr)
            app = Path(temporary) / "Health Test.app"
            decompiled = subprocess.run(
                ["/usr/bin/osadecompile", str(app)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(decompiled.returncode, 0, decompiled.stderr)
            self.assertIn("serviceReady", decompiled.stdout)
            self.assertIn("--noproxy", decompiled.stdout)
            self.assertIn("Open Anyway", decompiled.stdout)

    def test_refuses_symbolic_link_target(self) -> None:
        with tempfile.TemporaryDirectory(prefix="shortcut-test-") as temporary:
            protected_dir = Path(temporary) / "protected"
            protected_dir.mkdir()
            protected_file = protected_dir / "important.txt"
            protected_file.write_text("keep", encoding="utf-8")
            (Path(temporary) / "Linked.app").symlink_to(protected_dir, target_is_directory=True)
            result = self.run_builder(
                "--name", "Linked",
                "--url", "http://127.0.0.1:39004/",
                "--output-dir", temporary,
                "--overwrite",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(protected_file.read_text(encoding="utf-8"), "keep")

    def test_rejects_non_finite_retry_delay(self) -> None:
        with tempfile.TemporaryDirectory(prefix="shortcut-test-") as temporary:
            result = self.run_builder(
                "--name", "Retry Test",
                "--url", "http://127.0.0.1:39005/",
                "--output-dir", temporary,
                "--retry-delay", "inf",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("retry delay", result.stderr)

    def test_rejects_cross_origin_health_and_port_mismatch_by_default(self) -> None:
        with tempfile.TemporaryDirectory(prefix="shortcut-test-") as temporary:
            cross_origin = self.run_builder(
                "--name", "Origin Test",
                "--url", "http://127.0.0.1:39007/",
                "--health-url", "http://127.0.0.1:39008/health",
                "--output-dir", temporary,
            )
            self.assertNotEqual(cross_origin.returncode, 0)
            self.assertIn("health URL must use", cross_origin.stderr)
            port_mismatch = self.run_builder(
                "--name", "Port Test",
                "--url", "http://127.0.0.1:39007/",
                "--port", "39008",
                "--output-dir", temporary,
            )
            self.assertNotEqual(port_mismatch.returncode, 0)
            self.assertIn("port must match", port_mismatch.stderr)

    def test_rejects_fifo_log_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory(prefix="shortcut-test-") as temporary:
            fifo = Path(temporary) / "launcher.log"
            os.mkfifo(fifo, 0o600)
            result = self.run_builder(
                "--name", "FIFO Test",
                "--url", "http://127.0.0.1:39009/",
                "--log", str(fifo),
                "--output-dir", temporary,
                timeout=3.0,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("single-link regular file", result.stderr)

    def test_health_probe_rejects_incomplete_200_response(self) -> None:
        class IncompleteResponse(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                self.request.recv(1024)
                self.request.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\n"
                )
                time.sleep(1.3)

        server = socketserver.TCPServer(("127.0.0.1", 0), IncompleteResponse)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}/health"
            result = subprocess.run(
                ["/bin/sh", "-c", shortcut_builder.health_probe(url)],
                capture_output=True,
                text=True,
                check=False,
                timeout=3.0,
            )
            self.assertNotEqual(result.returncode, 0)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2.0)

    @unittest.skipUnless(SYSTEM_ICON.is_file(), "system test icon unavailable")
    def test_ignores_path_shims_for_macos_build_tools(self) -> None:
        with tempfile.TemporaryDirectory(prefix="shortcut-test-") as temporary:
            root = Path(temporary)
            shims = root / "shims"
            shims.mkdir()
            for tool in ("osacompile", "sips", "iconutil", "codesign"):
                shim = shims / tool
                shim.write_text("#!/bin/sh\nexit 97\n", encoding="utf-8")
                shim.chmod(0o700)
            png_icon = root / "test-icon.png"
            conversion = subprocess.run(
                [shortcut_builder.SIPS, "-s", "format", "png", str(SYSTEM_ICON),
                 "--out", str(png_icon)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(conversion.returncode, 0, conversion.stderr)
            environment = os.environ.copy()
            environment["PATH"] = str(shims) + os.pathsep + environment.get("PATH", "")
            result = self.run_builder(
                "--name", "Trusted Tools",
                "--url", "http://127.0.0.1:39006/",
                "--icon", str(png_icon),
                "--output-dir", temporary,
                env=environment,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            verify = subprocess.run(
                [shortcut_builder.CODESIGN, "--verify", "--strict",
                 str(root / "Trusted Tools.app")],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(verify.returncode, 0, verify.stderr)

    @unittest.skipUnless(SYSTEM_ICON.is_file(), "system test icon unavailable")
    def test_canonicalizes_relative_and_dash_prefixed_paths(self) -> None:
        with tempfile.TemporaryDirectory(prefix="shortcut-test-") as temporary:
            root = Path(temporary)
            icon = root / "--out.png"
            conversion = subprocess.run(
                [shortcut_builder.SIPS, "-s", "format", "png", str(SYSTEM_ICON),
                 "--out", str(icon)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(conversion.returncode, 0, conversion.stderr)
            result = self.run_builder(
                "--name=-App",
                "--url", "http://127.0.0.1:39010/",
                "--icon=--out.png",
                "--log", "relative.log",
                "--output-dir", ".",
                cwd=temporary,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((root / "-App.app").is_dir())
            self.assertEqual((root / "relative.log").stat().st_mode & 0o777, 0o600)
            self.assertIn(str(root / "relative.log"), result.stdout)


if __name__ == "__main__":
    unittest.main()
