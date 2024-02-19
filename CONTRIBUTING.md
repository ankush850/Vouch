# Contributing to Vouch

Thank you for contributing to Vouch!

## Development Setup
```bash
git clone https://github.com/ankush850/Vouch.git
cd Vouch
pip install -e ".[dev]"
```

## Running Tests
```bash
pytest tests/
```

## Code Guidelines
- **Typing**: Use standard Python 3.11+ type hints throughout (`from __future__ import annotations`).
- **Security First**: No feature or flag should ever bypass cryptographic verification.
