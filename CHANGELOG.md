# Changelog

All notable changes to this project will be documented in this file.

## [2.0.0] – 2025-11-30

### Added
- Initial public release of **iOS RE Toolkit – PowerShell Scanner)**.
- Goal-aware scanning modes:
  - Auth / login bypass
  - License / activation / subscription
  - Security / jailbreak / anti-debug
  - Network / API / hosts
  - General recon
- Smart string extraction with relevance scoring tuned for:
  - Auth, license, security, network, crypto, storage, UI patterns.
- High-priority string lists for Ghidra / IDA search.
- Plist / entitlements parsing for:
  - Bundle ID
  - Version
  - Minimum OS version
  - Selected entitlements (e.g. keychain, app-groups, push)
- Optional JSON export of analysis results for custom tooling.
- Colored console logging with timestamps.
- Configurable Smart and Full modes.

### Fixed
- Robust handling when certain pattern categories are missing in a given file.
- Avoided null-indexing on pattern maps when no matches are present.
- Resolved `StringBuilder` vs `.Trim()` type issue in string filtering.
- Reduced risk of memory spikes by chunking string processing and trimming maps.

### Changed
- Tuned Smart mode limits for AI-friendly report size while keeping high signal.
- Slightly reduced Full mode caps to avoid ridiculous output sizes on very large apps.

---

## [Unreleased]

Planned / ideas:
- More granular configuration (e.g. external pattern config file).
- More detailed Mach-O parsing (proper LC_ENCRYPTION_INFO, fat binaries, etc.).
- Optional HTML / Markdown report output.
- Scripted Ghidra/IDA helper snippets based on findings.