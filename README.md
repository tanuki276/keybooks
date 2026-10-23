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

Sensitive user data is never intentionally written to SQLite as plaintext.

- AES-256-GCM is used for encryption.
- Secret values and metadata use **separate Android Keystore keys**.
- Project names are encrypted at rest.
- Service/tool names are encrypted at rest.
- Secret names, hidden/visible setting, authentication type, and password salt are bundled into encrypted metadata.
- Metadata encryption uses AES-GCM Additional Authenticated Data (AAD) bound to a random per-record identifier and record type, so moving metadata ciphertext between unrelated records causes authentication failure.
- `None` authentication uses an AES key stored in Android Keystore.
- `Biometric` authentication uses a separate Android Keystore AES key that requires strong biometric authentication for each use.
- `Password` authentication derives a per-secret AES key with `PBKDF2WithHmacSHA256`, a random 32-byte per-secret salt, and 600,000 iterations.
- Android Keystore keys explicitly require randomized encryption.
- AES-GCM IV lengths are validated before decryption.
- Temporary PBKDF2 key bytes are cleared after constructing the AES key object.
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

> SQLite still contains structural information such as numeric IDs, parent/child relationships, creation timestamps, random record IDs, IVs, and ciphertext sizes. This can reveal approximate record counts and hierarchy, but not names, secret values, auth type, hidden state, or password salts without the device-held keys.

> If Android Keystore keys become invalidated, data encrypted by those keys may become unrecoverable. Password-protected entries also cannot be recovered if the password is forgotten. There is intentionally no recovery server.

## Database migration

Database version 2 migrates the original plaintext metadata schema automatically.

During migration:

1. Existing project, service, and secret metadata is read locally.
2. Metadata is encrypted with the dedicated metadata key.
3. Secret values remain encrypted and are copied without being exposed as plaintext by the migration.
4. New encrypted tables are populated.
5. Legacy plaintext tables are deleted.

The migration is performed locally and does not use a server or network permission.

## Icons

UI icons are vector-based. SVG path data is converted to Android `VectorDrawable` resources and rendered directly from Compose, keeping icons resolution-independent without adding a network or image-loading dependency.

## Storage structure

```text
projects
  └─ services
      └─ secrets
```

SQLite v2 tables intentionally avoid plaintext names and auth metadata:

```text
projects
- id
- record_id
- encrypted_metadata
- metadata_iv
- created_at

services
- id
- record_id
- project_id
- encrypted_metadata
- metadata_iv
- created_at

secrets
- id
- record_id
- service_id
- encrypted_metadata
- metadata_iv
- encrypted_value
- iv
- created_at
```

For a secret, `encrypted_metadata` contains the encrypted logical fields:

```text
name
hidden
authType
passwordSalt (when applicable)
```

## Tech stack

- Kotlin
- Jetpack Compose
- Android SQLite (`SQLiteOpenHelper`)
- Android Keystore
- AES/GCM/NoPadding
- PBKDF2WithHmacSHA256
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
8. The project screen shows `GitHub` and all secrets saved under it after local decryption in memory.
9. Open Settings to choose a clipboard auto-clear delay or unlimited mode.

## Notes

Project-level locking is not implemented. See the recovery and checks sections below for the current backup and validation behavior.

## Recovery and portable backups

Settings → **暗号化Export / Import** writes a `.kbb` file through Android's document picker. Export requires authentication for **every** protected entry. A failed or cancelled authentication aborts the entire export; entries are never silently omitted. Use a long, unique backup passphrase (at least 12 characters) and keep the file outside this device. Verify a backup by importing it before uninstalling, changing fingerprints, or resetting the device.

The portable format is `KBB1 || salt[32] || IV[12] || ciphertext+tag`. PBKDF2-HMAC-SHA256 (600,000 iterations) derives a 256-bit key. AES-GCM authenticates the complete fixed header and payload. Import limits files to 16 MiB, validates all records first, and merges in a single SQLite transaction. It never clears existing records. Repeated imports create additional copies. All restored secrets use **PASSWORD** protection with the backup passphrase; authenticate and edit them to choose a different method. The archive stores logical data, not device keys or original authentication passwords.

New biometric entries require a separate recovery passphrase. It encrypts an independent envelope stored inside encrypted metadata. If enrollment invalidates the biometric key, use **回復パスワードで解除**, then edit the value and choose biometric protection again to bind a new key. This recovery path is deliberately an alternative to biometric authentication. It does not recover lost metadata/standard Keystore keys: use the portable backup for device loss or reinstall. Existing biometric entries have no recovery passphrase until authenticated and saved with the new editor. Data already inaccessible before this update cannot be recovered without an earlier usable backup.

New secret writes use envelope encryption (`KBE1`): a random AES-256 data key encrypts each value, and the chosen Keystore/password key wraps that data key. Legacy ciphertext remains readable and is upgraded when edited. Metadata remains protected by its separate Keystore key. StrongBox is attempted for newly generated keys, with fallback on `StrongBoxUnavailableException`; existing keys are retained. New secret metadata also authenticates a SHA-256 digest of the stored value ciphertext and IV, detecting value swaps/modification before display. Legacy records gain that binding when edited. This is not full database rollback protection.

Project, service, and secret names can be edited. Values/authentication can be edited after unlocking the original secret. Deletion asks for confirmation and cascades to children. Search operates locally on decrypted names, never on secret values. Password strength warnings encourage long passphrases.

## Checks

CI runs `gradle :app:assembleDebug :app:testDebugUnitTest :app:lintDebug` on every push and pull request (JDK 17, Gradle 9.8.2, Android SDK 37). A separate emulator job runs database integrity, CRUD/cascade, and atomic import tests. JVM tests cover backup wrong passwords, salt/header/IV/ciphertext/tag tampering, truncation/size limits, envelope corruption, legacy compatibility, and randomization. Hardware biometric enrollment, StrongBox, real document providers, and process-death recovery still need physical-device testing.
