# 0000. Use Architectural Decision Records

* Status: Accepted
* Date: 2026-08-29

## Context and Problem Statement

We need a structured way to record technical architecture decisions made during the modernization, porting, and refactoring of `peepdf` so that future maintainers and automated coding agents understand the rationale, trade-offs, and design principles behind changes.

## Decision Drivers

* Maintain clarity on major architectural changes (e.g., Python 3 porting, state isolation, module decomposition).
* Preserve knowledge of design trade-offs and compatibility decisions.
* Provide clear guidance for AI development tools and human developers.

## Considered Options

* Documenting decisions in commit messages or pull requests only.
* Maintaining an unstructured Wiki or monolithic README section.
* Storing Markdown-based Architectural Decision Records (ADRs) in [docs/adr/0000-use-architectural-decision-records.md](docs/adr/0000-use-architectural-decision-records.md) inside the repository.

## Decision Outcome

Chosen option: "Storing Markdown-based Architectural Decision Records in [docs/adr/](docs/adr/)" because it keeps architectural history version-controlled alongside the codebase.

## Consequences

* Positive: Clear history of design evolution.
* Positive: Easily consumable by human engineers and AI coding agents.
* Negative: Requires discipline to create and maintain records when making major architectural changes.
