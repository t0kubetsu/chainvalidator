# Changelog

All notable changes to **chainvalidator** are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Version numbers follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [0.1.1] — 2026-04-27

### Changed
- Repository moved to the
  [NC3-TestingPlatform](https://github.com/NC3-TestingPlatform) GitHub
  organisation; all internal URLs updated.

---

## [0.1.0] — 2026-03-11

### Added
- Initial release of **chainvalidator**.
- Full DNSSEC chain-of-trust validation (IANA root → TLD → target).
- Status reporting: `SECURE` / `INSECURE` / `BOGUS`.
- CLI: `chainvalidator check <domain>` with `--type`, `--timeout`,
  `--output` flags.
- `chainvalidator info algorithms` — lists supported DNSSEC algorithm OIDs.
- Report export to `.txt`, `.svg`, `.html`.
- 100% test coverage via pytest.

---

[Unreleased]: https://github.com/NC3-TestingPlatform/chainvalidator/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/NC3-TestingPlatform/chainvalidator/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/NC3-TestingPlatform/chainvalidator/releases/tag/v0.1.0
