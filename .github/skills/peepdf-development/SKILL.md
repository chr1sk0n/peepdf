---
name: peepdf-development
description: Development, testing, and Clean Code refactoring workflows for the peepdf project under Python 3.12+.
---

# peepdf Development Skill

Use this skill when developing, refactoring, or running test suites for `peepdf`.

## Workflows

### 1. Running Unit Tests
To run all unit tests in the repository using Python 3.12+:
```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

### 2. Quality Gate & Compilation Check
To verify syntax correctness, resource management, and absence of warnings across all modules:
```bash
python3 -W error::SyntaxWarning -W error::ResourceWarning -m compileall -q .
```

### 3. Whitespace & Formatting Verification
To check for trailing whitespace or illegal line endings before committing:
```bash
git diff --check
```

## Refactoring Guidelines
When refactoring code in `peepdf`:
- Maintain the facade in `PDFCore.py` so external callers and scripts do not break.
- Ensure `ParserContext` in `parser_context.py` is used for option state instead of global variables.
- Wrap file operations in `with open(...) as f:` blocks to avoid `ResourceWarning`.
- Verify new features with dedicated unit tests in `tests/`.
