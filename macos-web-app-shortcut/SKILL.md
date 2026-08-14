---
name: macos-web-app-shortcut
description: Create a native-looking macOS .app shortcut for a local web service, optionally launching the service, waiting for its health endpoint, opening it in the default browser, and applying a custom PNG or ICNS icon. Use for requests such as “make a desktop shortcut for this localhost app,” “turn this local Agent UI into a Mac app icon,” or “make one-click startup for a web dashboard.”
---

# macOS Web App Shortcut

Create a small macOS application bundle that starts an authorized local service and opens its URL. Apply credential safeguards and verify the result. Resolve every `scripts/` and `references/` path relative to the directory containing this `SKILL.md`.

## Workflow

1. Confirm the host is macOS and `osacompile` is available.
2. Collect or confirm:
   - Visible application name.
   - Local URL and optional health-check URL.
   - Service start command, unless the shortcut only opens an existing service. Display the exact command and obtain explicit confirmation; do not infer a materially different command.
   - Working directory, if the command needs one.
   - Destination directory. Default to the user's Desktop only when explicitly requested.
   - Optional PNG or ICNS icon that the user owns or is authorized to use.
3. Check the inputs for privacy hazards before creating anything.
4. Run `scripts/create_macos_web_shortcut.py` with explicit arguments.
5. Verify the `.app` bundle, its icon resource, and its launch behavior.
6. Report the app location, URL, log location, and whether the service test succeeded.

## Privacy and Safety Rules

- Never read, copy, package, print, or commit API keys, OAuth files, cookies, account IDs, shell history, session databases, or private logs.
- Never place a secret directly in any argument or the generated AppleScript. The compiled launcher is inspectable and is not a credential store.
- Stop if an input resembles a token or an inline secret assignment. Ask the user to configure credentials in the service's own secure storage.
- Use placeholders in examples. Do not preserve usernames or absolute home-directory paths in files intended for sharing.
- Bind newly configured development services to `127.0.0.1` by default. Use `--allow-remote` only after explicit user authorization.
- Do not overwrite an existing `.app` unless the user explicitly authorizes `--overwrite`, the exact target has been confirmed, and the app was previously created by this tool.
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

Use `--overwrite` only after confirming the exact existing app bundle with the user.

For a non-loopback destination URL, explain the exposure risk and add `--allow-remote` only after explicit authorization. Authorize a remote health URL separately with `--allow-remote-health`. Require HTTPS unless the user explicitly accepts the additional risk represented by `--allow-insecure-remote-http`. Keep the health URL on the destination origin and keep `--port` equal to the destination port unless the user separately authorizes `--allow-cross-origin-health` or `--allow-port-mismatch` for a known topology.

## Verify

- Confirm `<name>.app/Contents/MacOS/applet` exists.
- Confirm `<name>.app/Contents/Resources/applet.icns` exists when an icon was supplied.
- Inspect the generated AppleScript and confirm it contains no secret. Remember that runtime paths may be user-specific, so do not distribute the generated `.app` unless those paths are intended to be shared.
- Open the app once. Confirm the expected URL loads and repeated launches do not start duplicate processes when both `--health-url` and `--port` are provided.
- Confirm the app's `Info.plist` contains `MacOSWebShortcutCreator = macos-web-app-shortcut`.
- If testing for distribution, test on another macOS account or replace all paths with neutral examples first.

## Failure Handling

- If startup fails, inspect the launcher log path reported by the script and verify the start command manually without copying sensitive log content into chat or source control.
- If the health check times out, let the user choose whether to cancel or open the URL anyway; do not silently bypass the failure.
- If the icon remains cached, relaunch Finder or log out and back in; do not repeatedly rebuild unrelated files.
- If Gatekeeper warns about an unidentified developer, explain that ad-hoc signing is suitable for local use but public distribution normally requires Developer ID signing and notarization.
