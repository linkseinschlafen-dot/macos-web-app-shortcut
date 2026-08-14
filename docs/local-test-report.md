# Local test report

Test date: 2026-08-14

## Environment

- Repository target: `linkseinschlafen-dot/macos-web-app-shortcut`; Git commits are identified by the hosting history.
- macOS: 27.0 (build 26A5406e).
- Architecture: arm64.
- Python: 3.9.6.
- Skill validator: Codex bundled `quick_validate.py`, SHA-256 `6cc9dc3199c935916cf6f73fcbbbb0e3bb1b58c8f5109fefa499978908164f51`.
- Windows runtime: not available in this macOS test environment; Windows PowerShell/COM integration remains a platform-specific follow-up test.

## Commands

```bash
python3 -m unittest discover -s tests -v
python3 "$SKILL_CREATOR_DIR/scripts/quick_validate.py" macos-web-app-shortcut
gitleaks dir --redact=100 --no-banner --no-color .
```

Result: 28 tests passed; Skill validation passed.

## Passed

- Skill Creator structure validation.
- Python syntax and standard-library unit tests.
- macOS `.app` compilation with `osacompile`.
- ICNS input handling and icon resource validation using the macOS generic application icon during tests.
- Ad-hoc signature verification with `codesign --verify --strict`.
- Generated creator marker validation.
- Common secret shapes, Bearer/JWT, cloud/provider token prefixes, private keys, cookies, and sensitive query-parameter rejection.
- Environment-variable reference acceptance without embedding a value.
- Separate remote URL/health opt-ins, remote HTTPS enforcement, Unicode-control rejection, CLI numeric limits, non-ASCII log-name uniqueness, and URL output redaction.
- Private log creation with mode `0600`, curl configuration isolation, strict 2xx health checks, stable bundle identifiers, and post-sign verification.
- Rejection of FIFO logs without blocking, curl URL-globbing prevention, remote-proxy preservation, and rejection of incomplete HTTP 200 responses.
- Same-origin health and destination-port matching by default, with explicit override flags for reviewed special topologies.
- Canonical absolute-path handling for relative log/output/icon inputs and dash-prefixed names.
- Absolute trusted paths for macOS build/signing tools; a test PATH containing failing tool shims was ignored as intended.
- User-owned, non-shared output-directory enforcement; target identity recheck; external backup and rollback structure for launcher replacement.
- Refusal to overwrite an unmarked `.app` directory; protected test content remained intact.
- Windows launcher validation: sensitive command and URL rejection, PowerShell quoting, `.lnk` creator-marker checks, Windows name rules, and non-Windows platform guard.
- Content scan for local identity, known account identifiers, common credential prefixes, and private-key headers.
- Removal of the unverified whale image from the public package.
- Gitleaks 8.30.1 directory scan with full redaction: no leaks found. A synthetic canary was detected before the project scan.
- Gitleaks 8.30.1 full Git-history scan after the initial commit: one commit scanned, no leaks found.
- Local-identity scan: no unapproved username, private home path, known account identifier, credential directory, provider-specific name, or actual email address found. `MengMengjiang` is intentionally present as the user-approved public copyright holder. Apparent email matches were the mandatory ICNS `@2x.png` filename strings.
- Clean ZIP verification: no `__MACOSX`, AppleDouble `._*`, `.DS_Store`, generated app, log, cache, or excluded whale-logo entry. `zip -X` was used so extended attributes are not embedded.

## Not covered

- Apple Developer ID signing and notarization.
- Execution on a second Mac or separate macOS account.
- Actual Windows `.lnk` creation, Windows PowerShell execution, `WScript.Shell` COM behavior, and Windows shortcut launch on a Windows host.
- Every possible shell command and Unicode edge case.
- Crash testing at every filesystem instruction and adversarial same-user race testing beyond the guarded identity checks.
- macOS automatically reattached `com.apple.provenance` to the local working files after `xattr -cr`; Git does not preserve this attribute, and the verified `zip -X` archive does not contain its sidecar metadata.
- Remote GitHub settings, search indexing, and hosting availability are outside these local tests.

These results describe one local test environment and are not a warranty. Re-run the tests from the final clean Git tree before release.
