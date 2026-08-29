# 0002. ParserContext and State Isolation

* Status: Accepted
* Date: 2026-08-29

## Context and Problem Statement

In the legacy codebase, parser flags like `isForceMode` and `isManualAnalysis` were stored as global module-level variables in `PDFCore.py`. This created tight coupling, prevented concurrent or re-entrant PDF parsing, and made unit testing difficult.

## Decision Drivers

* Thread and task safety for concurrent PDF processing.
* Single Source of Truth for runtime parser options.
* Clean Code & KISS principles (immutable state, explicit context boundaries).

## Considered Options

* Passing option flags through dozens of internal method signatures.
* Keeping global variables and mutating them per call.
* Encapsulating options in an immutable `ParserContext` dataclass managed by `contextvars.ContextVar` and a context manager.

## Decision Outcome

Chosen option: "Encapsulating options in `ParserContext` managed by `contextvars`".

### Implementation
1. Defined frozen `@dataclass ParserContext` in [parser_context.py](parser_context.py).
2. Created a `ContextVar` `_parser_context` with a default `ParserContext()`.
3. Created context manager `set_parser_context(force_mode, manual_analysis)` used by `PDFParser.parse()` to set options on entry and restore them on exit.
4. Converted flag reads in parser logic to call `get_parser_context().force_mode` and `get_parser_context().manual_analysis`.

## Consequences

* Positive: Thread-safe and task-isolated PDF parsing.
* Positive: Automatic cleanup and state restoration after parsing finishes.
* Positive: Highly testable without side-effects across test cases.
* Negative: Internal calls must access options via `get_parser_context()` rather than a local attribute.
