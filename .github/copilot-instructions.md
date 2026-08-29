# peepdf Development Guidelines & Instructions

This repository contains the modernized, Python 3.12+ compatible version of `peepdf`, a security tool to analyze and modify PDF files.

## Core Engineering Principles

### 1. Keep It Simple, Stupid (KISS)
- Prefer simple, readable, and direct solutions over complex abstractions or over-engineered design patterns.
- Keep function and method implementations short and focused on a single responsibility.
- Avoid unnecessary dependencies; leverage Python Standard Library (`argparse`, `contextvars`, `dataclasses`, `xml.etree.ElementTree`, `hashlib`, `unittest`).

### 2. Clean Code Principles
- **Explicit Imports**: Never use wildcard imports (`from module import *`). Always import required symbols explicitly.
- **Resource Management**: Always use `with` statements (`with open(...) as f:`) for file and network resource handling to prevent resource leaks.
- **Immutability & State Isolation**: Use dataclasses (`@dataclass(frozen=True)`) and `contextvars` (`ParserContext`) to manage runtime options rather than global module state.
- **No Mutable Defaults**: Never use mutable objects (`list`, `dict`) as default argument values in functions/methods. Use `None` and initialize inside the function.
- **Explicit Type Annotations**: Add type hints for new functions and public APIs where beneficial for clarity and IDE tooling.

### 3. Architecture & Modular Structure
The codebase follows a modular domain separation:
- `parser_context.py`: Thread/task-isolated context manager for parser options (`force_mode`, `manual_analysis`).
- `pdf_constants.py`: Constants, delimiter tables, and vulnerability dictionaries (`vulnsDict`, `jsVulns`).
- `pdf_objects.py`: Low-level PDF primitives and data structures (`PDFObject`, `PDFDictionary`, `PDFStream`, `PDFObjectStream`).
- `pdf_structure.py`: Document structural elements (`PDFFile`, `PDFBody`, `PDFTrailer`, `PDFCrossRefSection`).
- `pdf_parser.py`: Primary PDF parsing engine (`PDFParser`).
- `PDFCore.py`: Re-exports all components for backward compatibility.

### 4. Testing & Quality Gates
Before committing or submitting changes, all quality gates must pass:
1. **Unit Tests**: All tests in `tests/` must pass:
   ```bash
   python3 -m unittest discover -s tests -p 'test_*.py' -v
   ```
2. **Warning-Free Compilation**: Code must compile without `SyntaxWarning` or `ResourceWarning`:
   ```bash
   python3 -W error::SyntaxWarning -W error::ResourceWarning -m compileall -q .
   ```
3. **Git Diff Check**: Ensure no trailing whitespace or CRLF formatting issues:
   ```bash
   git diff --check
   ```
