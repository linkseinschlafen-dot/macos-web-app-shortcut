# Security policy

## Supported code

Security fixes apply to the latest commit on the default branch. Reproducible generator defects that make generated `.app` bundles, Windows `.lnk` files, or companion PowerShell launchers unsafe are in scope. Bugs in unrelated third-party services launched by a shortcut are outside this repository's support boundary.

## Reporting a vulnerability

Use a private GitHub Security Advisory after the repository is published. Do not open a public issue containing credentials, private paths, exploit payloads with live tokens, or personal data.

Include the affected file and function, impact, a reproduction using synthetic data, and a proposed mitigation. Redact every real credential value.

## Security model

- Treat the supplied start command as trusted local code authorized by the user.
- Never embed secrets in launcher inputs; the generated AppleScript and PowerShell launcher are inspectable.
- Restrict services to loopback by default.
- Treat launcher logs as potentially sensitive and exclude them from source control.
- Use `--overwrite` only for launchers previously created by this tool, including the Windows `.lnk` and its marked companion script.
- Run a dedicated secret scanner before publishing.
