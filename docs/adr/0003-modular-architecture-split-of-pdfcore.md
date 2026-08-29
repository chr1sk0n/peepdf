# 0003. Modular Architecture Split of PDFCore

* Status: Accepted
* Date: 2026-08-29

## Context and Problem Statement

`PDFCore.py` was an 8,000+ line monolithic file containing constants, object models, cross-reference tables, stream decoders, document structures, and the parser engine. This violated the Single Responsibility Principle (SRP) and made maintenance and code navigation difficult.

## Decision Drivers

* Adhere to SOLID (Single Responsibility Principle) and Clean Code principles.
* Maintain 100% backward compatibility for existing scripts importing `PDFCore`.
* Keep modules cohesive and focused.

## Considered Options

* Keep `PDFCore.py` as a single file.
* Completely break `PDFCore.py` into separate modules and break backward compatibility.
* Decompose `PDFCore.py` into cohesive domain modules and retain `PDFCore.py` as a re-exporting facade.

## Decision Outcome

Chosen option: "Decompose into cohesive modules with `PDFCore.py` as a backward-compatible facade".

### Module Structure
- [parser_context.py](parser_context.py): Thread/task-isolated context manager for parser options.
- [pdf_constants.py](pdf_constants.py): Constant definitions, magic values, vulnerability dictionaries (`vulnsDict`, `jsVulns`).
- [pdf_objects.py](pdf_objects.py): Low-level PDF primitives and data structures (`PDFObject`, `PDFDictionary`, `PDFStream`, `PDFObjectStream`).
- [pdf_structure.py](pdf_structure.py): High-level document structural elements (`PDFFile`, `PDFBody`, `PDFTrailer`, `PDFCrossRefSection`).
- [pdf_parser.py](pdf_parser.py): Primary PDF parsing engine (`PDFParser`).
- [PDFCore.py](PDFCore.py): Facade module re-exporting all symbols from the submodules.

## Consequences

* Positive: Dramatically improved code readability and maintainability.
* Positive: Isolated responsibility per module.
* Positive: Existing scripts continue to work via `from PDFCore import ...`.
* Negative: Facade file must be updated if new top-level classes or constants are added.
