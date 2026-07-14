# Privacy and data handling

This project is designed to minimize disclosure during software-security review.

## Data rules

- Review only repositories, systems, and data the user is authorized to assess.
- Prefer file paths, line ranges, hashes, and short redacted excerpts over copying large code blocks.
- Replace credentials, tokens, keys, cookies, personal data, customer data, and internal hostnames with descriptive placeholders.
- Do not put production data or private repository content into issues, pull requests, fixtures, screenshots, release notes, or public ledgers.
- Use synthetic fixtures for reproduction.
- Do not upload repository content to external scanners or services without explicit authorization and an appropriate data-processing decision.

## Public artifacts

Before release, the project checks for private absolute paths, project-specific private names, common secret formats, oversized files, and symlinks. These checks reduce risk but cannot prove that no sensitive material exists. Contributors and maintainers remain responsible for reviewing the actual diff and generated artifacts.

## Security-review evidence

Evidence should be sufficient to support the conclusion without reproducing a usable secret or harmful payload. If redaction makes a claim impossible to verify, record the check as `not-tested` or keep the evidence in an authorized private channel.
