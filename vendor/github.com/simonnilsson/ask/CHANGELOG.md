# Changelog
All notable changes to this project will be documented in this file.

## [Unreleased]


## [0.3.0] - 2022-08-21
### Changed
- Added support for handling custom types derived from `map[string]interface{}` and `[]interface{}`
- **Breaking:** Minimum Go version bumped from 1.15 to 1.17 


## [0.2.0] - 2021-02-07
### Changed
- Now using reflection for number assertions, reduces complexity
- If integer would not fit in requested type operation will fail and return default value.
- Improved test coverage

### Fixed
- Fixed some typos


## [0.1.0] - 2020-09-13
- Initial release
