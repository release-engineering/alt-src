# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- n/a

## [1.6.3] - 2023-09-19
### Fixed
- Fixed parsing of `pagure_api_key_file`

## [1.6.2] - 2022-07-12
### Fixed
- Fixed a Python 3 issue where bytes are expected as argument instead of string
- Fixed compatibility with latest PyYAML

## [1.6.1] - 2021-05-17
### Fixed
- Fixed a crash when a repo cannot be fetched

## [1.6.0] - 2021-01-20

### Fixed
- Fixed a crash when a config file is missing
- Fixed logger setup

### Added
- Added option to keep sources in lookaside cache,
  now by default lookaside cache folder is cleaned

## [1.5.0] - 2020-09-03

### Fixed
- Fixed handling of SRPMs which do not contain a `SOURCES` directory
  [#27](https://github.com/release-engineering/alt-src/issues/27)

## [1.4.2] - 2020-08-03

### Fixed
- Fixed a crash introduced in 1.4.0 when alt-src is used with rpm-python versions
  older than 4.12.0.

## [1.4.1] - 2020-07-29

### Fixed
- Fixed a crash introduced in 1.4.0 when alt-src is used with older versions of
  the `six` package, as available in RHEL6.

## [1.4.0] - 2020-07-27

### Added
- Added rpm2cpio fallback during RPM unpacking. This improves compatibility when RPMs
  built with a newer OS are handled via alt-src on an older OS (though compatibility
  is still not guaranteed).

## [1.3.0] - 2020-06-11

### Changed
- Improved logging for commands failure

## [1.2.0] - 2020-05-25

### Added
- Added Python 3 compatibility

## [1.1.0] - 2020-04-02

### Changed
- Used Yaml BaseLoader to avoid conversion errors
- Use rpm-py-installer instead of rpm as dependency

### Added
- Local tags are removed if already exist on re-push

### Fixed
- Fixed branch initialization when target repo has no default branch
- Fixed handling of lockfile during cleanup

## 1.0.0 - 2019-10-15

- Initial release to PyPI

[Unreleased]: https://github.com/release-engineering/alt-src/compare/v1.6.3...HEAD
[1.6.3]: https://github.com/release-engineering/alt-src/compare/v1.6.2...v1.6.3
[1.6.2]: https://github.com/release-engineering/alt-src/compare/v1.6.1...v1.6.2
[1.6.1]: https://github.com/release-engineering/alt-src/compare/v1.6.0...v1.6.1
[1.6.0]: https://github.com/release-engineering/alt-src/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/release-engineering/alt-src/compare/v1.4.2...v1.5.0
[1.4.2]: https://github.com/release-engineering/alt-src/compare/v1.4.1...v1.4.2
[1.4.1]: https://github.com/release-engineering/alt-src/compare/v1.4.0...v1.4.1
[1.4.0]: https://github.com/release-engineering/alt-src/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/release-engineering/alt-src/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/release-engineering/alt-src/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/release-engineering/alt-src/compare/v1.0.0...v1.1.0
