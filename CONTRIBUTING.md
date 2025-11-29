# Contributing to NetSnap

Thank you for considering contributing to NetSnap! This document provides guidelines and instructions for contributing.

## Development Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/hcoin/netsnap.git
   cd netsnap
   ```

2. **Create a virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install in development mode**:
   ```bash
   pip install -e ".[dev]"
   ```

## Project Structure

```
netsnap/
├── netsnap/              # Main package directory
│   ├── __init__.py      # Package initialization
│   ├── device_info.py   # Network device/address information
│   ├── route_info.py    # Routing table information
│   ├── neighbor_info.py # Neighbor table information
│   ├── mdb_info.py      # Multicast database
│   ├── rule_info.py     # Routing rules
│   └── *.html           # HTML documentation
├── tests/               # Test suite
│   ├── __init__.py
│   └── test_package.py
├── examples/            # Example scripts
├── docs/                # Additional documentation
├── pyproject.toml       # Modern package configuration
├── setup.py             # Legacy package configuration
├── README.md            # Main documentation
├── LICENSE              # MIT License
├── CHANGELOG.md         # Version history
└── CONTRIBUTING.md      # This file
```

## Code Style

We follow standard Python conventions:

- **PEP 8**: Python style guide
- **Line length**: 100 characters maximum
- **Docstrings**: Use triple quotes for all functions and classes
- **Type hints**: Encouraged but not required

### Formatting

Use `black` for code formatting:

```bash
black netsnap/
```

### Linting

Check code quality with `flake8`:

```bash
flake8 netsnap/
```

### Type Checking

Use `mypy` for type checking:

```bash
mypy netsnap/
```

## Testing

Run tests with pytest:

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=netsnap --cov-report=html

# Run specific test file
pytest tests/test_package.py

# Run with verbose output
pytest -v
```

Note: Many netsnap features require root privileges and will be skipped in regular test runs.

## Making Changes

1. **Create a branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**:
   - Write clear, commented code
   - Add tests for new features
   - Update documentation as needed

3. **Test your changes**:
   ```bash
   # Run tests
   pytest
   
   # Format code
   black netsnap/
   
   # Check style
   flake8 netsnap/
   ```

4. **Commit your changes**:
   ```bash
   git add .
   git commit -m "Description of changes"
   ```

5. **Push and create a pull request**:
   ```bash
   git push origin feature/your-feature-name
   ```

## Commit Messages

Use clear, descriptive commit messages:

```
Add support for XYZ feature

- Implement XYZ functionality
- Add tests for XYZ
- Update documentation
```

## Pull Request Process

1. Update the README.md with details of changes if applicable
2. Update the CHANGELOG.md with a note describing your changes
3. Ensure all tests pass and code is properly formatted
4. The PR will be merged once you have approval from maintainers

## Adding New Features

When adding new netlink features:

1. **Research the netlink API**:
   - Check Linux kernel headers
   - Review kernel documentation
   - Test with actual netlink commands

2. **Implement in C code**:
   - Add C structures and functions
   - Handle all attribute types
   - Include proper error checking

3. **Add Python wrapper**:
   - Parse C structures into Python dicts
   - Add human-readable names
   - Handle edge cases

4. **Document**:
   - Add docstrings
   - Update README if user-facing
   - Create HTML documentation if needed

5. **Test**:
   - Test on multiple kernel versions
   - Test with various configurations
   - Add unit tests

## Debugging

### CFFI Compilation Issues

If CFFI fails to compile:

```bash
# Install development headers
sudo apt-get install python3-dev gcc  # Debian/Ubuntu
sudo yum install python3-devel gcc    # RHEL/CentOS

# Verify CFFI can compile
python3 -c "from cffi import FFI; ffi = FFI(); print('CFFI OK')"
```

### Netlink Communication Issues

Enable debug output by modifying C_SOURCE to include debug prints:

```c
fprintf(stderr, "DEBUG: Message type: %d\n", nlh->nlmsg_type);
```

### Testing with Different Kernel Versions

Test your changes on different Linux distributions and kernel versions:

- Ubuntu 20.04 LTS (kernel 5.4)
- Ubuntu 22.04 LTS (kernel 5.15)
- Ubuntu 24.04 LTS (kernel 6.8)
- Debian 11 (kernel 5.10)
- RHEL/CentOS 8 (kernel 4.18)

## Documentation

Update documentation when:

- Adding new features
- Changing command-line arguments
- Modifying output formats
- Fixing bugs that affect behavior

## Questions?

Feel free to open an issue for:

- Bug reports
- Feature requests
- Questions about the code
- Documentation improvements

## Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Help others learn and grow
- Focus on what is best for the community

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
