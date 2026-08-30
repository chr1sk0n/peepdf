# peepdf

`peepdf` is a **Python 3.12+ security tool to explore, analyze, and modify PDF files**. The aim of this tool is to provide all the necessary components for security researchers and analysts to inspect PDF documents in a single unified suite without switching between multiple tools.

With `peepdf`, you can inspect all objects in a document, highlight suspicious elements, parse filtered/encoded streams, handle multiple file revisions/updates, analyze object streams, and inspect encrypted PDFs.

---

## Key Features

### 🔍 Document Analysis
* **Structural Inspection**: Physical layout (file offsets), logical object tree, metadata, and multi-version updates (changelogs).
* **Decoding & Filters**: Hexadecimal, octal, name object decodings, and popular stream filters (`FlateDecode`, `ASCIIHexDecode`, `ASCII85Decode`, `LZWDecode`, `RunLengthDecode`, `CCITTFaxDecode`).
* **Object Stream Parsing**: Handles compressed objects within PDF Object Streams (`/ObjStm`).
* **Encryption Handling**: Decrypts password-protected PDFs and inspects security handlers.
* **JavaScript Analysis**: Identifies and extracts embedded JavaScript code, triggers, actions, and vulnerable functions. Supports dynamic evaluation via optional wrappers (`STPyV8` / `PyV8`).
* **Shellcode Detection**: Extracts shellcode payloads from streams and offers emulation capabilities via optional `pylibemu` integration.
* **VirusTotal Lookup**: Automated hash checking against VirusTotal API using the `PEEPDF_VT_KEY` environment variable.
* **Structured Data Export**: Export complete document reports in **XML (`-x`)** or **JSON (`-j`)** natively using standard library components without external dependencies (`lxml` is no longer required).

### 🛠️ Document Creation & Modification
* **PDF Scaffolding**: Create basic PDF structures or PDF documents carrying auto-executing JavaScript payloads for security testing.
* **Object Manipulation**: Modify, add, or delete PDF objects, streams, and filters.
* **Obfuscation**: Obfuscate strings, name objects, and stream encodings.
* **Malformed PDF Generation**: Generate malformed PDF files (missing `endobj`, garbage headers, corrupted trailers) to test parser robustness.

### ⚡ Execution Modes
* **Command Line Interface (CLI)**: Fast non-interactive analysis with flexible flags (`-x`, `-j`, `-c`, `-f`, `-l`, `-m`).
* **Interactive Shell**: Rich interactive console (`-i`) for step-by-step object navigation, stream extraction, JavaScript decoding, and state manipulation.
* **Batch & Command Automation**: Execute series of console commands directly from script files (`-s`) or command-line parameters (`-C`).

---

## Modular Architecture & Modernization

The codebase has been modernized for **Python 3.12+**, adhering to Clean Code and KISS (Keep It Simple, Stupid), DRY (Don't Repeat Yourself), YAGNI (You Aren't Gonna Need It), Composition over Inheritance and Duck Typing principles:

* `parser_context.py`: Thread/task-isolated context manager (`ParserContext`) backed by `contextvars.ContextVar` for safe, isolated execution flags (`force_mode`, `manual_analysis`).
* `pdf_constants.py`: Delimiters, error codes, and vulnerability dictionaries (`vulnsDict`, `jsVulns`).
* `pdf_objects.py`: PDF primitives (`PDFObject`, `PDFDictionary`, `PDFStream`, `PDFObjectStream`, `PDFIndirectObject`, `PDFArray`).
* `pdf_structure.py`: High-level PDF structure (`PDFFile`, `PDFBody`, `PDFTrailer`, `PDFCrossRefSection`).
* `pdf_parser.py`: Core parsing logic (`PDFParser`).
* `pdf_core.py`: Main library module re-exporting core classes. Backward-compatible facades (`PDFCore.py`, `PDFConsole.py`, `JSAnalysis.py`, etc.) are maintained for legacy scripts.

---

## Requirements & Installation

### Standard Requirements
* **Python 3.12+**
* **Zero Mandatory External Dependencies**: Core static analysis, stream extraction, XML/JSON exports, and CLI execution work out of the box using standard library modules (`argparse`, `dataclasses`, `contextvars`, `xml.etree.ElementTree`, `json`).

### Optional Enhancements
To unlock advanced features, install optional packages:
* **Colorized Terminal Output**: `pip install colorama`
* **Image Processing**: `pip install Pillow`
* **Dynamic JavaScript Engine**: [STPyV8](https://github.com/area1/stpyv8) (Modern Python 3 V8 engine wrapper) or PyV8
* **Shellcode Emulation**: [pylibemu](https://github.com/buffer/pylibemu)

### Installation
Clone the repository:
```bash
git clone https://github.com/chr1sk0n/peepdf.git
cd peepdf
```

---

## Command Line Usage

```
usage: peepdf.py [options] [PDF_file]
```

### Options

| Flag | Long Option | Description |
| :--- | :--- | :--- |
| `-h` | `--help` | Show help message and exit. |
| `-i` | `--interactive` | Launch interactive console mode. |
| `-s` | `--load-script` `FILE` | Load and execute commands from a script file. |
| `-C` | `--command` `CMD` | Execute an interactive console command directly. |
| `-c` | `--check-vt` | Query VirusTotal API for file hash reports (`PEEPDF_VT_KEY` required). |
| `-f` | `--force-mode` | Enable force parsing mode to ignore PDF syntax errors. |
| `-l` | `--loose-mode` | Enable loose parsing mode to catch malformed objects. |
| `-m` | `--manual-analysis` | Disable automatic JavaScript evaluation (prevents heap spray loops). |
| `-x` | `--xml` | Export document analysis report in XML format. |
| `-j` | `--json` | Export document analysis report in JSON format. |
| `-g` | `--grinch-mode` | Disable colorized output in interactive console. |
| `-u` | `--update` | Check and update `peepdf` files from the repository. |
| `-v` | `--version` | Display version information and exit. |

---

## Quickstart & Examples

### 1. Basic Static Analysis
Analyze a PDF file and view summary statistics:
```bash
python3 peepdf.py sample.pdf
```

### 2. Parse Corrupted / Malformed PDFs
Use force mode (`-f`) or loose mode (`-l`) to parse heavily obfuscated or malformed exploit payloads:
```bash
python3 peepdf.py -f malformed_exploit.pdf
```

### 3. Interactive Console
Launch the interactive shell for manual exploration:
```bash
python3 peepdf.py -i sample.pdf
```
Inside the interactive shell:
```
PPDF> info                       # Show general document information
PPDF> object 1                   # Inspect object ID 1
PPDF> stream 5 > stream5.bin     # Extract stream 5 raw content to file
PPDF> js_extract                 # Extract all embedded JavaScript code
PPDF> offsets                    # Show physical offset structure
```

### 4. Export JSON or XML Reports
Generate structured machine-readable reports for automated triage pipelines:
```bash
# JSON output
python3 peepdf.py -j sample.pdf > report.json

# XML output
python3 peepdf.py -x sample.pdf > report.xml
```

### 5. Single Command & Batch Script Execution
Execute specific commands non-interactively:
```bash
# Extract object 3 via CLI command flag
python3 peepdf.py -C "object 3" sample.pdf

# Run automated batch script
python3 peepdf.py -s commands_batch.txt sample.pdf
```

### 6. VirusTotal Hash Lookup
Set your VirusTotal API key in the environment and check file reputation:
```bash
export PEEPDF_VT_KEY="your_virustotal_api_key_here"
python3 peepdf.py -c sample.pdf
```

---

## Development & Testing

### Running Unit Tests
All unit tests are written using Python's standard `unittest` framework:
```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

### Running Quality Gates
To ensure compliance with warnings and syntax standards:
```bash
# Check for compilation warnings (SyntaxWarning, ResourceWarning)
python3 -W error::SyntaxWarning -W error::ResourceWarning -m compileall -q .

# Check git diff formatting
git diff --check
```

---

## Architectural Decision Records (ADRs)

Key architectural decisions for the modernization of `peepdf` are documented in `docs/adr/`:

* [ADR 0000: Architectural Decision Records Strategy](docs/adr/0000-use-architectural-decision-records.md)
* [ADR 0001: Python 3.12+ Porting & Standard Library Modernization](docs/adr/0001-python-312-porting-and-standard-library-modernization.md)
* [ADR 0002: Parser Context and Thread-Safe State Isolation](docs/adr/0002-parser-context-and-state-isolation.md)
* [ADR 0003: Modular Architecture Split of PDFCore](docs/adr/0003-modular-architecture-split-of-pdfcore.md)

---

## Historical Articles & Publications

* [Spammed CVE-2013-2729 PDF exploit dropping ZeuS-P2P/Gameover](http://eternal-todo.com/blog/cve-2013-2729-exploit-zeusp2p-gameover)
* [New peepdf v0.2 (Version Black Hat Vegas 2012)](http://eternal-todo.com/blog/peepdf-v0.2-black-hat-usa-arsenal-vegas)
* [peepdf supports CCITTFaxDecode encoded streams](http://eternal-todo.com/blog/peepdf-ccittfaxdecode-support)
* [Explanation of the changelog of peepdf for Black Hat Europe Arsenal 2012](http://eternal-todo.com/blog/peepdf-black-hat-arsenal-2012)
* [How to extract streams and shellcodes from a PDF, the easy way](http://eternal-todo.com/blog/extract-streams-shellcode-peepdf)
* [Static analysis of a CVE-2011-2462 PDF exploit](http://eternal-todo.com/blog/cve-2011-2462-exploit-analysis-peepdf)
* [Analysis of a malicious PDF from a SEO Sploit Pack](http://eternal-todo.com/blog/seo-sploit-pack-pdf-analysis)
* Analysing the [Honeynet Project challenge PDF file](http://www.honeynet.org/challenges/2010_6_malicious_pdf) with peepdf [Part 1](http://eternal-todo.com/blog/analysing-honeynet-pdf-challenge-peepdf-i) [Part 2](http://eternal-todo.com/blog/analysing-honeynet-pdf-challenge-peepdf-ii)
* [Analyzing Suspicious PDF Files With Peepdf](http://blog.zeltser.com/post/6780160077/peepdf-malicious-pdf-analysis)

---

## Included In
* **REMnux** (Reverse Engineering Malware Linux Distribution)
* **Kali Linux**
* **BackTrack 5**

---

## License & Author

* **Author**: Jose Miguel Esparza (<jesparza@eternal-todo.com>)
* **License**: GNU General Public License v3.0 (GPLv3)
