# Contributing to VeriTrace

Thank you for your interest in contributing to **VeriTrace**!

VeriTrace is an open-source Windows digital forensics framework focused on detecting potential indicators of anti-forensic activity through cross-artifact consistency analysis. The goal of the project is to support investigators by improving confidence in digital evidence through transparent, explainable, and repeatable forensic analysis.

At this stage, VeriTrace is being developed as part of a master's capstone project. Contributions are welcome as the project matures.

---

## Code of Conduct

Please be respectful, constructive, and professional in all interactions.

We welcome contributors from all backgrounds who are interested in digital forensics, DFIR, cybersecurity, software engineering, and open-source development.

---

## Before Contributing

Please:

- Search existing Issues before creating a new one.
- Open an Issue to discuss significant feature requests before beginning implementation.
- Keep pull requests focused on a single change whenever possible.
- Follow the project's coding standards.

---

## Development Environment

Recommended environment:

- Python 3.12+
- Visual Studio Code
- Git
- GitHub

Clone the repository:

```bash
git clone https://github.com/Gear-I/VeriTrace.git
cd VeriTrace
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Coding Standards

VeriTrace follows the following standards:

- PEP 8
- Type hints
- Google-style docstrings
- Meaningful variable and function names
- Small, modular functions
- Robust exception handling
- Logging instead of print statements

Please avoid unnecessary complexity.

---

## Running Tests

Run all unit tests before submitting a pull request.

```bash
pytest
```

Run Pylint:

```bash
pylint veritrace/
```

Pull requests should pass all GitHub Actions workflows.

---

## Branch Naming

Please use descriptive branch names.

Examples:

```
feature/registry-parser
feature/prefetch-parser
feature/html-report

bugfix/event-log-parser

docs/readme-update

test/registry-tests
```

---

## Commit Messages

Use Conventional Commits whenever possible.

Examples:

```
feat: add registry parser

feat(parser): implement prefetch parser

fix: correct EVTX timestamp parsing

docs: update README

test: add parser unit tests

refactor: simplify correlation engine
```

---

## Pull Requests

Please include:

- A clear summary
- Motivation for the change
- Testing performed
- Screenshots (if applicable)
- Related Issue number

Example:

```
## Summary

Implemented the initial Registry parser.

## Changes

- Added Registry parser
- Added error handling
- Added unit tests

## Testing

- pytest
- pylint

Closes #12
```

---

## Reporting Bugs

When reporting bugs, include:

- Operating system
- Python version
- Sample input (if possible)
- Expected behavior
- Actual behavior
- Error messages
- Stack trace

---

## Feature Requests

Feature requests are encouraged.

Please describe:

- The problem
- Why it matters
- Proposed solution
- Example workflow

---

## Project Goals

Version 1 focuses on:

- Windows Event Logs (EVTX)
- Windows Registry
- Windows Prefetch
- Cross-artifact consistency analysis
- HTML reporting
- JSON reporting

Future releases may include support for additional Windows forensic artifacts.

---

## Security

If you discover a security issue within VeriTrace itself, please do not publicly disclose it immediately.

Instead, open a private discussion or contact the project maintainer.

---

## License

By contributing to VeriTrace, you agree that your contributions will be licensed under the project's MIT License.

---

## Thank You

Thank you for helping improve VeriTrace and supporting the digital forensics community.

Every contribution—whether code, documentation, bug reports, or ideas—is appreciated.