# Keybooks

Keybooks is a **local-only Android secrets vault** built with Kotlin and Jetpack Compose.

## What it does

- Create as many **projects** as you want.
- Add **services/tools** inside each project, such as GitHub, OpenAI, Vercel, AWS, etc.
- Add multiple secrets to each service.
- Each secret has:
  - Name, e.g. `GITHUB_TOKEN`
  - Value, e.g. `ghp_...`
  - Hidden / visible setting
  - Authentication: none / biometric / custom password
- Reveal and copy secret values from the project screen.
- Configure clipboard clearing as a custom number of seconds or disable automatic clearing entirely.
- Everything is stored **only on the device**.

Example:

```text
My Project
└─ GitHub        +
   ├─ GITHUB_TOKEN
   ├─ GITHUB_CLIENT_ID
   └─ GITHUB_CLIENT_SECRET
```

## Security model

Secret values are never written to SQLite as plaintext.

- AES-256-GCM is used for encryption.
- `None` authentication uses an AES key stored in Android Keystore.
- `Biometric` authentication uses a separate Android Keystore AES key that requires strong biometric authentication for each use.
- `Password` authentication derives a per-secret AES key with `PBKDF2WithHmacSHA256`, a random 32-byte per-secret salt, and 600,000 iterations.
- Android Keystore keys explicitly require randomized encryption.
- AES-GCM IV lengths are validated before decryption.
- Project names, service names, secret names, auth type, and timestamps are currently stored as metadata in plaintext; secret values remain encrypted.
- Screenshots and screen recording are blocked with `FLAG_SECURE`.
- Overlay windows are hidden on supported Android versions.
- Autofill and Content Capture are disabled for the app window to reduce accidental secret exposure.
- Android cloud backup/device transfer is disabled for app data.
- Cleartext network traffic is disabled, and the app intentionally has **no `INTERNET` permission**.
- Clipboard entries are marked sensitive on Android 13+.
- Clipboard auto-clear is configurable: a custom number of seconds or unlimited/no automatic clearing.
- Clipboard clearing uses a random token and only clears the clipboard entry that Keybooks itself placed there; copying something else in another app will not be erased by an old Keybooks timer.
- Revealed secrets are re-masked after 30 seconds and immediately re-masked when the app leaves the foreground.
- Release builds enable R8 minification and resource shrinking.

> If Android Keystore keys become invalidated, secrets encrypted by those keys may become unrecoverable. Password-protected entries also cannot be recovered if the password is forgotten. There is intentionally no recovery server.

## Icons

UI icons are vector-based. SVG path data is converted to Android `VectorDrawable` resources and rendered directly from Compose, keeping icons resolution-independent without adding a network or image-loading dependency.

## Storage structure

```text
projects
  └─ services
      └─ secrets
```

SQLite tables:

```text
projects
- id
- name
- created_at

services
- id
- project_id
- name
- created_at

secrets
- id
- service_id
- name
- encrypted_value
- iv
- hidden
- auth_type
- password_salt
- created_at
```

## Tech stack

- Kotlin
- Jetpack Compose
- Android SQLite (`SQLiteOpenHelper`)
- Android Keystore
- AES/GCM/NoPadding
- AndroidX Biometric
- Android VectorDrawable / SVG path assets

## Current MVP flow

1. Open Keybooks.
2. Tap `+` and create a project.
3. Open the project.
4. Tap the project-level `+` and create a service such as `GitHub`.
5. Tap the `+` on the GitHub card.
6. Enter:
   - Name: `GITHUB_TOKEN`
   - Key / value: `ghp_...`
   - Hidden: yes/no
   - Authentication: none / biometric / password
7. Save it.
8. The project screen shows `GitHub` and all secrets saved under it.
9. Open Settings to choose a clipboard auto-clear delay or unlimited mode.

## Notes

This repository currently contains the first MVP implementation. Export/import, editing/deleting entries, search, project-level locking, encrypted metadata, and encrypted backup files are good next steps.
