# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

This is a Burp Suite Extension that generates TOTP/HOTP two-factor codes.

## What it does

`2FA Code Generator` registers 2FA accounts and displays live one-time codes in a Burp suite tab. Accounts can be registered from:

- `otpauth://` provisioning URIs (pasted)
- QR code images (file or system clipboard)
- Google Authenticator `otpauth-migration://` export payloads
- Provisioning data found in HTTP responses (context menu on Proxy/Site map/message editor)

Accounts can also be **exported and imported** to share testing progress with teammates:

- Encrypted JSON (default) - PBKDF2-HMAC-SHA256 + AES-256-GCM, passphrase protected
- Plaintext JSON
- Plaintext `otpauth://` URI list (`.txt`), interoperable with phones/other tools

## Architecture

- **Main Entry Point**: `src/main/java/Extension.java` - implements `BurpExtension`; wires the store, worker thread, suite tab and context menu, and cleans everything up on unload.
- **Build System**: Gradle with Kotlin DSL, Java 21.
- **Dependencies**: Montoya API 2026.7 (compile-only), `com.google.zxing:core` (bundled into the JAR). The `jar` task unpacks `runtimeClasspath` so the BApp is self-contained.
- **No HTTP requests**: the extension does not perform any network I/O.

### Packages

- `twofactor` (domain logic, no Swing/Burp dependencies where possible)
  - `OtpCodeGenerator` - RFC 4226 (HOTP) / RFC 6238 (TOTP) code generation.
  - `Base32` - tolerant RFC 4648 Base32 codec.
  - `OtpAuthUriParser` - Key URI format parsing + URI discovery in free-form text.
  - `MigrationPayloadParser` - hand-rolled protobuf reader for Google Authenticator export payloads.
  - `QrDecoder` - ZXing wrapper (files, bytes, data-URI images) with size/rotation guards.
  - `ResponseScanner` - extracts provisioning data from `HttpRequestResponse` bodies.
  - `Json` - minimal self-contained JSON reader/writer (keeps the transfer format testable without Burp).
  - `Crypto` - PBKDF2 + AES-GCM encryption for exports.
  - `AccountTransfer` - import/export of account lists (encrypted JSON, plaintext JSON, URI list).
  - `TwoFactorAccount` / `OtpType` / `OtpAlgorithm` - the account model.
  - `AccountStore` - thread-safe registry + project-scoped persistence + account merging.
- `twofactor.ui` (Swing)
  - `TwoFactorTab` - suite tab (table, toolbar, filters, background QR decoding).
  - `AccountTableModel`, `AccountRenderers` - live code/expiry rendering.
  - `AccountPreviewDialog`, `AccountEditorDialog` - confirmation and editing.
  - `TransferDialogs`, `TransferActions` - import/export dialogs, passphrase prompts and file IO.
  - `TwoFactorContextMenuProvider` - Burp context menu integration.
  - `UiUtils` - clipboard, masking and dialog helpers.

### Key behaviours

- **Threading**: QR decoding and response scanning run on a single background `ExecutorService`; the UI refreshes codes with a 1-second Swing `Timer`. The worker is shut down on unload.
- **Persistence**: accounts are stored in `Persistence.extensionData()` (project file). Secrets are stored unencrypted; the "Remember secrets" checkbox (backed by `Preferences`) turns persistence off and keeps secrets in memory only.
- **Security**: HTTP bodies are untrusted. Parsed accounts are always shown in a confirmation dialog before registration, secrets are masked in the preview, sizes/limits are enforced, and no untrusted text is rendered as HTML or logged with its secret. Exports default to passphrase encryption; files are written with owner-only permissions where the filesystem supports it.
- **Merging**: import skips accounts that already exist (same secret/parameters) but advances the local HOTP counter when the imported one is further along, so teammates can hand over in-progress HOTP testing.

## Key Development Commands

```bash
./gradlew build    # Compile, run unit tests, build the JAR
./gradlew test     # Run tests only
./gradlew jar      # Create the extension JAR file
./gradlew clean    # Clean build artifacts
```

The built JAR is `build/libs/twofa-code-generator.jar` and can be loaded directly into Burp Suite.

## Extension Loading in Burp

1. Build the JAR using `./gradlew jar`
2. In Burp: Extensions > Installed > Add > Select the JAR file
3. For quick reloading during development: Ctrl/⌘ + click the Loaded checkbox

## Documentation Structure

- See @docs/bapp-store-requirements.md for BApp Store submission requirements
- See @docs/montoya-api-examples.md for code patterns and extension structure
- See @docs/development-best-practices.md for development guidelines
- See @docs/resources.md for external documentation and links

## Testing

Unit tests live in `src/test/java/twofactor` and cover the RFC 4226/6238 test
vectors, Base32, URI parsing, migration payloads, QR round-trips (QR codes are
generated with ZXing's encoder and decoded with this extension's decoder),
JSON parsing and import/export round-trips (including wrong-passphrase and
tamper detection).
