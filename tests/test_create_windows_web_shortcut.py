from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "macos-web-app-shortcut" / "scripts" / "create_windows_web_shortcut.py"
SPEC = importlib.util.spec_from_file_location("windows_shortcut_builder", SCRIPT)
assert SPEC and SPEC.loader
windows_shortcut_builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(windows_shortcut_builder)


class SecretDetectionTests(unittest.TestCase):
    def test_rejects_secret_shapes_and_sensitive_flags(self) -> None:
        samples = (
            "TOKEN=$'synthetic-secret'",
            "--client-secret synthetic-secret",
            "Cookie: synthetic-secret",
            "--cookie synthetic-secret",
            "Bearer abcdefghijklmnop",
        )
        for sample in samples:
            with self.subTest(sample=sample):
                with self.assertRaises(SystemExit):
                    windows_shortcut_builder.assert_no_secret("command", sample)

    def test_allows_exact_environment_references(self) -> None:
        windows_shortcut_builder.assert_no_secret("command", "TOKEN=$env:API_TOKEN")
        windows_shortcut_builder.assert_no_secret("command", "--api-key ${env:API_KEY}")

    def test_rejects_encoded_sensitive_url_values(self) -> None:
        for value in (
            "http://127.0.0.1:3080/?token%5B%5D=synthetic-value",
            "http://127.0.0.1:3080/#id_token=synthetic-value",
            "http://127.0.0.1:3080/?view=sk%2Dsyntheticcredential123456",
        ):
            with self.subTest(value=value):
                with self.assertRaises(SystemExit):
                    windows_shortcut_builder.validate_url("url", value)


class InputValidationTests(unittest.TestCase):
    def test_remote_url_requires_explicit_authorization(self) -> None:
        with self.assertRaises(SystemExit):
            windows_shortcut_builder.validate_url("url", "https://example.com/")
        windows_shortcut_builder.validate_url("url", "https://example.com/", allow_remote=True)
        with self.assertRaises(SystemExit):
            windows_shortcut_builder.validate_url("url", "http://example.com/", allow_remote=True)

    def test_windows_name_rules(self) -> None:
        for value in ("CON", "name.", "bad/name", "trailing "):
            with self.subTest(value=value):
                with self.assertRaises(SystemExit):
                    windows_shortcut_builder.validate_name(value)
        windows_shortcut_builder.validate_name("DeepSeek Harness")

    def test_powershell_quote_and_launcher_contents(self) -> None:
        self.assertEqual(
            windows_shortcut_builder.ps_quote("C:\\Users\\A O'Neil"),
            "'C:\\Users\\A O''Neil'",
        )
        args = SimpleNamespace(
            name="Harness",
            url="http://127.0.0.1:3080/",
            health_url="http://127.0.0.1:3080/health",
            command="python -m http.server 3080",
            working_dir=Path(r"C:\work"),
            port=3080,
            retries=4,
            retry_delay=0.5,
        )
        script = windows_shortcut_builder.build_launcher_script(args, Path(r"C:\logs\harness.log"))
        self.assertIn("windows-web-app-shortcut = 0.1.0", script)
        self.assertIn("Invoke-WebRequest", script)
        self.assertIn("$DisableHealthProxy = $true", script)
        self.assertIn("Start-Process -FilePath $TargetUrl", script)
        self.assertIn("if ($HealthUrl) { Test-Health $HealthUrl } else { $false }", script)
        self.assertIn("-NoProfile", script)
        self.assertNotIn("api_key=", script.lower())

    def test_generated_shortcut_marker_is_required_for_overwrite(self) -> None:
        with tempfile.TemporaryDirectory(prefix="windows-shortcut-test-") as temporary:
            root = Path(temporary)
            shortcut = root / "Harness.lnk"
            launcher = root / "Harness.launcher.ps1"
            shortcut.write_bytes(b"synthetic lnk")
            launcher.write_text(
                "# windows-web-app-shortcut = 0.1.0\n", encoding="utf-8"
            )
            windows_shortcut_builder.validate_generated_shortcut(shortcut, launcher)
            launcher.write_text("# unrelated launcher\n", encoding="utf-8")
            with self.assertRaises(SystemExit):
                windows_shortcut_builder.validate_generated_shortcut(shortcut, launcher)


@unittest.skipUnless(os.name != "nt", "non-Windows guard only")
class PlatformGuardTests(unittest.TestCase):
    def test_main_refuses_to_run_on_non_windows(self) -> None:
        with self.assertRaises(SystemExit):
            windows_shortcut_builder.main([
                "--name", "Harness",
                "--url", "http://127.0.0.1:3080/",
                "--output-dir", ".",
            ])


if __name__ == "__main__":
    unittest.main()
