# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## v0.2.0 - 2021-03-02
### Added
- Allow configuring the limiter with custom slack.
  [#64](https://github.com/uber-go/ratelimit/pull/64)
- Allow configuring the limiter per arbitrary time duration.
  [#54](https://github.com/uber-go/ratelimit/pull/54)
### Changed
- Switched from Glide to Go Modules.
### Fixed
- Fix not working slack.
  [#60](https://github.com/uber-go/ratelimit/pull/60)

## v0.1.0
### Fixed
- Changed the import path for `go.uber.org/atomic` to its newer, canonical
  import path.
  [#18](https://github.com/uber-go/ratelimit/issues/18)
