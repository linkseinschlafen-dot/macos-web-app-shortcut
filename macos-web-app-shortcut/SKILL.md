---
name: macos-web-app-shortcut
description: Create a guarded macOS .app or Windows .lnk shortcut for a local web service, optionally launching the service, waiting for its health endpoint, opening it in the default browser, and applying a user-provided icon. Use for requests such as “make a desktop shortcut for this localhost app,” “turn DeepSeek Harness into a Mac or Windows app icon,” or “make one-click startup for a web dashboard.”
---

# Web App Shortcut (macOS + Windows)

Create a small macOS application bundle or Windows shortcut that starts an authorized local service and opens its URL. Apply credential safeguards and verify the result. Resolve every `scripts/` and `references/` path relative to the directory containing this `SKILL.md`.

## Workflow

1. Detect the host platform. On macOS, confirm `osacompile` is available; on Windows, confirm Windows PowerShell and the `WScript.Shell` shortcut component are available.
2. Collect or confirm:
   - Visible application name.
   - Local URL and optional health-check URL.
   - Service start command, unless the shortcut only opens an existing service. Display the exact command and obtain explicit confirmation; do not infer a materially different command.
   - Working directory, if the command needs one.
   - Destination directory. Default to the user's Desktop only when explicitly requested.
   - Optional icon that the user owns or is authorized to use: PNG or ICNS on macOS; ICO, EXE, or DLL on Windows.
3. Check the inputs for privacy hazards before creating anything.
4. Run the platform-specific script with explicit arguments: `scripts/create_macos_web_shortcut.py` on macOS or `scripts/create_windows_web_shortcut.py` on Windows.
5. Verify the generated shortcut, its icon resource, and its launch behavior.
6. Report the shortcut location, URL, log location, and whether the service test succeeded.

## Privacy and Safety Rules

- Never read, copy, package, print, or commit API keys, OAuth files, cookies, account IDs, shell history, session databases, or private logs.
- Never place a secret directly in any argument or the generated AppleScript. The compiled launcher is inspectable and is not a credential store.
- Never place a secret directly in any argument or the generated PowerShell launcher. The `.lnk` and companion `.ps1` are inspectable and are not credential stores.
- Stop if an input resembles a token or an inline secret assignment. Ask the user to configure credentials in the service's own secure storage.
- Use placeholders in examples. Do not preserve usernames or absolute home-directory paths in files intended for sharing.
- Bind newly configured development services to `127.0.0.1` by default. Use `--allow-remote` only after explicit user authorization.
- Do not overwrite an existing `.app` or Windows `.lnk` unless the user explicitly authorizes `--overwrite`, the exact target has been confirmed, and the launcher was previously created by this tool.
- Do not publish to GitHub or another external service unless the user explicitly requests publishing.

Read `references/security-review.md`, relative to this Skill directory, before preparing a shortcut or repository for sharing.

## Create the Shortcut

Run:

```bash
python3 scripts/create_macos_web_shortcut.py \
  --name "My Local App" \
  --url "http://127.0.0.1:3000/" \
  --health-url "http://127.0.0.1:3000/" \
  --port 3000 \
  --command "npm run dev -- --host 127.0.0.1 --port 3000" \
  --working-dir "/absolute/path/to/project" \
  --icon "/absolute/path/to/icon.png" \
  --output-dir "/absolute/path/to/destination"
```

For an already-running service, omit `--command`, `--working-dir`, and `--port`.

Use `--overwrite` only after confirming the exact existing app bundle or Windows shortcut and its creator marker with the user.

For a non-loopback destination URL, explain the exposure risk and add `--allow-remote` only after explicit authorization. Authorize a remote health URL separately with `--allow-remote-health`. Require HTTPS unless the user explicitly accepts the additional risk represented by `--allow-insecure-remote-http`. Keep the health URL on the destination origin and keep `--port` equal to the destination port unless the user separately authorizes `--allow-cross-origin-health` or `--allow-port-mismatch` for a known topology.

## Create the Windows Shortcut

Run this on Windows PowerShell or from an Agent running on Windows:

```powershell
python scripts/create_windows_web_shortcut.py `
  --name "DeepSeek Harness" `
  --url "http://127.0.0.1:3080/" `
  --health-url "http://127.0.0.1:3080/" `
  --port 3080 `
  --command "npm run web" `
  --working-dir "C:\Users\example\deepseek-harness" `
  --icon "C:\Users\example\deepseek-harness.ico" `
  --output-dir "C:\Users\example\Desktop"
```

The Windows builder creates a `.lnk` and a companion `.launcher.ps1`; keep them together. It uses Windows PowerShell to create the shortcut and to start the authorized command. Windows shortcuts accept ICO, EXE, or DLL icon sources; convert PNG files to ICO before passing `--icon`.

## Verify

- Confirm `<name>.app/Contents/MacOS/applet` exists.
- Confirm `<name>.app/Contents/Resources/applet.icns` exists when an icon was supplied.
- Inspect the generated AppleScript and confirm it contains no secret. Remember that runtime paths may be user-specific, so do not distribute the generated `.app` unless those paths are intended to be shared.
- Open the app once. Confirm the expected URL loads and repeated launches do not start duplicate processes when both `--health-url` and `--port` are provided.
- Confirm the app's `Info.plist` contains `MacOSWebShortcutCreator = macos-web-app-shortcut`.
- If testing for distribution, test on another macOS account or replace all paths with neutral examples first.
- On Windows, confirm `<name>.lnk` and `<name>.launcher.ps1` exist together, and inspect the launcher marker before allowing `--overwrite`.
- Open the Windows shortcut once and confirm the expected URL loads; keep the companion `.ps1` beside the `.lnk` if the shortcut is moved.

## Failure Handling

- If startup fails, inspect the launcher log path reported by the script and verify the start command manually without copying sensitive log content into chat or source control.
- If the health check times out, let the user choose whether to cancel or open the URL anyway; do not silently bypass the failure.
- If the icon remains cached, relaunch Finder or log out and back in; do not repeatedly rebuild unrelated files.
- If Gatekeeper warns about an unidentified developer, explain that ad-hoc signing is suitable for local use but public distribution normally requires Developer ID signing and notarization.
- If Windows PowerShell blocks the companion script, explain the local execution-policy requirement and do not silently weaken the user's system-wide policy.
