# Release security checklist

Last local review: 2026-08-14

## Completed locally

- [x] No API keys, OAuth tokens, authorization codes, cookies, passwords, or private keys found in tracked content.
- [x] No real username, email address, account ID, device name, session ID, or private home-directory path found.
- [x] No credential directories, browser data, shell history, session databases, generated apps, or logs included.
- [x] Local URLs are required by default; remote URLs need explicit `--allow-remote` authorization.
- [x] Sensitive command, header, token-shape, private-key, and URL-query inputs have automated rejection tests.
- [x] Control characters and unsafe retry values are rejected.
- [x] Existing targets are replaced only when they are marked app bundles or Windows shortcut companions previously created by this tool.
- [x] Symbolic-link targets and log files are rejected.
- [x] Logs are pre-created in a private directory with mode `0600` and rechecked at launch.
- [x] FIFO and multiply linked logs are rejected; health probes honor curl failures and require a complete 2xx response.
- [x] Health and destination origins/ports must align unless separate explicit overrides are authorized.
- [x] macOS build/signing tools use fixed system paths and ignore hostile `PATH` shims.
- [x] Existing launcher identity is rechecked before replacement; the old launcher remains recoverable until the installed replacement passes final verification.
- [x] The script does not modify firewall, routing, login items, system permissions, or security settings.
- [x] Skill structure validation, macOS packaging/signature integration tests, and Windows launcher safety tests pass locally.
- [x] The unverified whale logo was removed from the public package and Skill metadata.
- [x] Gitleaks 8.30.1 directory scan passed after a synthetic canary confirmed detector operation.
- [x] Public copyright holder confirmed as `MengMengjiang`.
- [x] ZIP creation excludes AppleDouble files and extended attributes.

## Final publication checks

- [x] Run Gitleaks against the final Git history and working tree.
- [x] Review the exact staged Git diff before the first push.
- [x] Confirm public repository target: `linkseinschlafen-dot/macos-web-app-shortcut`.
- [x] Re-run unit tests and Skill Creator validation from the clean release tree.

## Distribution notes

- Generated `.app` bundles, `.lnk` files, and companion `.launcher.ps1` files are local artifacts and must not be committed.
- Ad-hoc signing is not Developer ID signing or Apple notarization.
- Windows `.lnk` and companion PowerShell launchers still require a real Windows host test before claiming end-to-end Windows compatibility.
- If distributing prebuilt apps, use a separate release process with documented signing, notarization, and provenance.
