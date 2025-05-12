# Contributing to Enterprise SOC SIEM Implementation

Thank you for your interest in contributing to the Enterprise SOC SIEM Implementation! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Enhancements](#suggesting-enhancements)
  - [Code Contributions](#code-contributions)
  - [Documentation Contributions](#documentation-contributions)
- [Development Workflow](#development-workflow)
  - [Branching Strategy](#branching-strategy)
  - [Commit Messages](#commit-messages)
  - [Pull Requests](#pull-requests)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [License](#license)

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## Getting Started

1. **Fork the repository** on GitHub.
2. **Clone your fork** to your local machine.
3. **Set up the development environment** by following the instructions in the [README.md](README.md) and [docs/installation.md](docs/installation.md).
4. **Create a new branch** for your contribution.

## How to Contribute

### Reporting Bugs

Before submitting a bug report:

1. **Check the issue tracker** to see if the bug has already been reported.
2. **Check the documentation** to make sure it's not a configuration issue.

When submitting a bug report, please include:

- A clear and descriptive title
- Exact steps to reproduce the issue
- Expected behavior
- Actual behavior
- Screenshots or logs if applicable
- Environment details (OS, Docker version, etc.)

Use the provided bug report template when creating an issue.

### Suggesting Enhancements

For feature requests or enhancements:

1. **Clearly describe the enhancement** and why it would be valuable.
2. **Provide specific examples** of how the enhancement would work.
3. **Explain how this enhancement benefits** the broader user base.

Use the provided feature request template when creating an issue.

### Code Contributions

1. **Select an issue** to work on, or create a new one and wait for approval.
2. **Comment on the issue** to indicate you're working on it.
3. **Create a new branch** from the `develop` branch with a descriptive name.
4. **Write your code** following the [Coding Standards](#coding-standards).
5. **Add tests** for new functionality.
6. **Update documentation** as needed.
7. **Submit a pull request** to the `develop` branch.

### Documentation Contributions

Documentation is crucial for the project. Contributions can include:

- Fixing typos or grammatical errors
- Improving clarity of existing documentation
- Adding examples or use cases
- Documenting undocumented features
- Translating documentation to other languages

Follow the same process as code contributions when submitting documentation changes.

## Development Workflow

### Branching Strategy

We follow a simplified GitFlow workflow:

- `main`: Production-ready code
- `develop`: Integration branch for new features
- `feature/*`: New features and improvements
- `bugfix/*`: Bug fixes
- `hotfix/*`: Critical fixes for production
- `docs/*`: Documentation updates

### Commit Messages

Follow these guidelines for commit messages:

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less
- Reference issues and pull requests liberally after the first line
- Consider starting the commit message with an applicable prefix:
  - `feat:` for new features
  - `fix:` for bug fixes
  - `docs:` for documentation updates
  - `test:` for test additions or modifications
  - `chore:` for maintenance tasks

Example:
```
feat: Add SSH brute force detection rule

- Adds detection for repeated SSH login failures
- Configurable threshold and time window
- Includes documentation and tests

Fixes #42
```

### Pull Requests

When submitting a pull request:

1. **Link the pull request** to any related issues.
2. **Describe the changes** clearly in the pull request description.
3. **Include screenshots** for UI changes.
4. **Make sure CI tests pass**.
5. **Request a review** from a maintainer.

## Coding Standards

### Python

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide.
- Use docstrings for all functions, classes, and modules.
- Name variables, functions, and classes descriptively.
- Add type hints to function definitions where appropriate.
- Maximum line length of 88 characters.

### YAML (for configurations and rules)

- Use 2-space indentation.
- Use descriptive keys.
- Include comments to explain complex configurations.

### Bash scripts

- Include a helpful header comment explaining the script's purpose.
- Define exit codes at the top of the script.
- Use functions for reusable code.
- Validate input parameters.

### General

- Write self-documenting code.
- Follow the existing style of the project.
- Keep functions and files focused on a single responsibility.

## Testing Guidelines

### Python Testing

- Write unit tests using pytest.
- Mock external systems when testing components that interact with them.
- Aim for high test coverage, especially for security-critical code.

### Rule Testing

- Provide sample data that triggers the rule.
- Provide sample data that should not trigger the rule.
- Document any specific conditions required for testing.

### Integration Testing

- Test individual components and their integrations.
- Use Docker Compose for testing multi-component interactions.
- Document test environment setup requirements.

## License

By contributing to this project, you agree that your contributions will be licensed under the project's [Apache License 2.0](LICENSE).

## Questions?

If you have any questions or need further clarification, please open an issue with the "question" label or reach out to the maintainers directly.