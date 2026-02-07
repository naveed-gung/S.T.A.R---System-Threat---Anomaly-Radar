# Contributing to S.T.A.R.

Thank you for your interest in contributing to S.T.A.R. (System Threat & Anomaly Radar). This document outlines the process for contributing to this project.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and professional environment. Harassment, discrimination, and disruptive behavior will not be tolerated.

## How to Contribute

### Reporting Bugs

1. Check existing issues to avoid duplicates.
2. Use the bug report template when creating a new issue.
3. Include: OS version, kernel version, build configuration, steps to reproduce, expected vs actual behavior.
4. For security vulnerabilities, see [SECURITY.md](SECURITY.md) instead.

### Suggesting Features

1. Open a feature request issue with a clear description.
2. Explain the use case and how it aligns with the project goals.
3. Reference relevant SRS requirements if applicable.

### Submitting Code

1. Fork the repository.
2. Create a feature branch from `main`: `git checkout -b feature/your-feature`
3. Write your code following the style guidelines below.
4. Add or update tests as needed.
5. Ensure all tests pass and the build succeeds on both Windows and Linux.
6. Submit a pull request with a clear description of changes.

## Security Review Process

All contributions that touch the following areas require an additional security review before merge:

- Kernel driver code (`src/drivers/`)
- Memory analysis routines (`src/core/`)
- Platform abstraction layer (`src/core/platform/`)
- Privilege elevation code
- Any code that handles raw memory or process data

Security reviews are conducted by maintainers with kernel development experience.

## Code Style Guidelines

### C Code

- C11 standard
- 4-space indentation (no tabs)
- Opening braces on the same line for control structures, next line for functions
- Prefix all public symbols with `star_`
- Use `STAR_` prefix for macros and constants
- Document all public functions with block comments
- No compiler warnings with `-Wall -Wextra -Wpedantic`

### Commit Messages

- Use present tense: "Add feature" not "Added feature"
- First line: 50 characters max, imperative mood
- Body: wrap at 72 characters, explain what and why

### File Organization

```
src/core/include/   - Public headers
src/core/platform/  - Platform-specific implementations
src/drivers/        - Kernel driver source
src/daemon/         - User-space daemon
src/ui/             - Web dashboard
tests/              - Test suites
docs/               - Documentation
```

## Build & Test

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
cmake --build .
ctest --output-on-failure
```

## License

By contributing, you agree that your contributions will be licensed under the GPLv3 license (core engine) or MIT license (UI components) as specified in the project LICENSE file.
