# 0001. Python 3.12+ Porting and Standard Library Modernization

* Status: Accepted
* Date: 2026-08-29

## Context and Problem Statement

`peepdf` was originally developed for Python 2.7. Python 2 reached End-of-Life in 2020. The codebase contained deprecated idioms, Python 2 string/bytes assumptions, `optparse` command-line parsing, and external `lxml` dependencies for basic XML generation.

## Decision Drivers

* Target modern Python versions (`>= 3.12.10`).
* Follow Clean Code principles by eliminating deprecated modules and zero-warning compilation (`SyntaxWarning`, `ResourceWarning`).
* Follow KISS principle by minimizing external dependencies and leveraging the Python Standard Library.

## Considered Options

* Minimal Python 2-to-3 syntax fix with legacy library retention (`optparse`, unclosed file handles).
* Complete modernization to Python 3.12+ standard library (`argparse`, `contextvars`, `xml.etree.ElementTree`, `with open(...)` resource management).

## Decision Outcome

Chosen option: "Complete modernization to Python 3.12+ standard library".

### Key Changes
1. Replaced `optparse` with `argparse` in [peepdf.py](peepdf.py).
2. Replaced `lxml` dependency with `xml.etree.ElementTree` fallback in [peepdf.py](peepdf.py).
3. Used `with open(...)` blocks for deterministic file cleanup in [pdf_parser.py](pdf_parser.py) and [peepdf.py](peepdf.py).
4. Used `raw` regex strings (`r'...'`) across [JSAnalysis.py](JSAnalysis.py) and [pdf_parser.py](pdf_parser.py) to prevent `SyntaxWarning` escape sequence errors.

## Consequences

* Positive: Executable on modern Python 3.12+ runtimes without warnings.
* Positive: Reduced dependency burden on external binary packages (`lxml`).
* Positive: Proper OS resource management preventing file handle leaks.
* Negative: Requires latin-1 / bytes handling care when processing binary PDF contents in Python 3.
