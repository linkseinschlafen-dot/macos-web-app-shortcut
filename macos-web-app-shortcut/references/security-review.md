# Security review rules

Apply these checks before creating, sharing, or publishing a launcher.

## Keep secrets out of the launcher

The script rejects common secret assignments, authorization headers, Bearer/JWT values, cloud and provider token prefixes, cookies, private-key headers, URL user information, and sensitive query parameters. This is best-effort defense, not proof that an input is safe.

- Inspect the complete command and URLs before creation.
- Never pass a credential value through the command line, URL, path, plist, environment assignment, or log example.
- A variable reference such as `TOKEN=$TOKEN` may pass validation, but a Finder-launched app might not inherit an interactive shell environment. Prefer having the service retrieve credentials from its own protected store.
- Treat the generated AppleScript as readable content. Anyone with the `.app` can inspect it.
- Run a dedicated secret scanner before publishing a repository or generated artifact.

## Remove local identity before sharing

Search tracked content and Git history for:

- Usernames and `/Users/<name>/...` paths.
- Email addresses, account IDs, device names, network addresses, and session identifiers.
- Browser profiles, shell history, application support data, service configuration, and logs.

Use placeholders such as `/Users/example/project` only in documentation. A generated launcher can contain runtime paths for its owner, but do not distribute that launcher unless those paths are intentionally public.

## Limit network exposure

- Default to `localhost`, `127.0.0.1`, or another loopback address.
- Require explicit authorization before using `--allow-remote`, and separate authorization before using `--allow-remote-health`.
- Require HTTPS for remote hosts. Use `--allow-insecure-remote-http` only after the user explicitly accepts cleartext transport risk.
- Do not open firewall rules, configure port forwarding, or make a service public as part of shortcut creation.
- When both a health URL and port are supplied, treat an occupied port plus failed health check as an error instead of opening an unknown service.
- Require the health URL to share the destination origin and require `--port` to match the destination port by default. Use the two explicit mismatch overrides only for a reviewed topology.
- A health endpoint does not authenticate a service. Use a service-specific, non-secret health path when possible.

## Protect files

- Treat the start command as trusted local code supplied or approved by the user.
- Run it with `/bin/zsh -fc` so user shell startup files are not loaded. Prefer absolute executable paths or an explicit minimal, non-secret `PATH`.
- Reject control characters and symbolic-link icon or log inputs.
- Require an output directory owned by the current user and not writable by group or other users.
- Pre-create logs in a private directory with mode `0600`; refuse FIFOs, multiply linked files, missing files, symbolic links, or differently owned logs.
- Replace only app bundles carrying this tool's creator marker. Never use `--overwrite` for an unrelated app.
- Build the replacement before moving the prior marked launcher, and restore the prior launcher if installation fails.
- Invoke macOS compilation and signing tools by their fixed `/usr/bin` paths and verify the final installed bundle.
- Treat service logs as sensitive even when their default location is temporary.

## Understand distribution limits

The generated app is ad-hoc signed for local use. GitHub publication of this Skill does not make generated apps notarized. A broadly distributed binary requires a separate Apple Developer ID signing and notarization workflow.

Use only icons whose provenance and redistribution rights are appropriate for the user's intended use.
