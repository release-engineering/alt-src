# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- n/a

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

[Unreleased]: https://github.com/release-engineering/alt-src/compare/v1.2.0...HEAD
[1.1.0]: https://github.com/release-engineering/alt-src/compare/v1.0.0...v1.1.0
[1.2.0]: https://github.com/release-engineering/alt-src/compare/v1.1.0...v1.2.0
[1.3.0]: https://github.com/release-engineering/alt-src/compare/v1.1.0...v1.3.0
