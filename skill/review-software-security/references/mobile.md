# Mobile review

Use OWASP MASVS as the mobile control baseline, MASWE for weakness mapping, and MASTG for test procedures. Verify and record the current release before citing identifiers.

## Scope

- Identify platform, app flavor/build type, minimum OS, distribution channel, backend/API dependencies, deep links, web views, native bridges, local data, cryptographic keys, push notifications, and third-party SDKs.
- Review both client and backend. A mobile control cannot repair missing server-side authorization.

## Control areas

- Storage: secrets, credentials, personal data, logs, backups, screenshots, clipboard, caches, and database/file protections.
- Cryptography: platform APIs, randomness, key generation/storage, rotation, and deprecated algorithms.
- Authentication and authorization: token lifecycle, biometrics, device binding, account recovery, offline behavior, and server enforcement.
- Network: TLS validation, cleartext policy, certificate handling, proxies, endpoint configuration, and sensitive metadata.
- Platform interaction: intents/deep links, URL schemes, exported components, permissions, pasteboard, IPC, notifications, and universal/app links.
- Code quality and resilience: unsafe deserialization, injection, memory safety where relevant, debug/test features, tamper assumptions, root/jailbreak behavior, and update integrity.
- Privacy: permission minimization, tracking/SDK behavior, data disclosure, consent, retention, and deletion.

## Testing boundary

Static review alone cannot establish runtime protections. Record emulator/device, OS, build flavor, signing, test account, and backend environment for authorized dynamic tests. Do not test a production backend or real user data without explicit permission.
