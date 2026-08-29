"""Core module for PDF parsing, analysis, and data structures.

This module re-exports components from specialized submodules:
- parser_context: Context-local parsing configuration
- pdf_constants: Constant definitions, magic values, and vulnerability tables
- pdf_objects: PDF data types (primitives, dictionaries, streams, indirect objects)
- pdf_structure: High-level document structural elements (xref, body, trailer, PDFFile)
- pdf_parser: PDF Parser engine
"""

from parser_context import ParserContext, get_parser_context, set_parser_context
from pdf_constants import (
    MAL_ALL,
    MAL_BAD_HEAD,
    MAL_EOBJ,
    MAL_ESTREAM,
    MAL_HEAD,
    MAL_XREF,
    bmpVuln,
    delimiterChars,
    jsContexts,
    jsVulns,
    monitorizedActions,
    monitorizedElements,
    monitorizedEvents,
    newLine,
    singUniqueName,
    spacesChars,
    vulnsDict,
)
from pdf_objects import (
    PDFArray,
    PDFBool,
    PDFDictionary,
    PDFHexString,
    PDFIndirectObject,
    PDFName,
    PDFNull,
    PDFNum,
    PDFObject,
    PDFObjectStream,
    PDFReference,
    PDFStream,
    PDFString,
)
from pdf_structure import (
    PDFBody,
    PDFCrossRefEntry,
    PDFCrossRefSection,
    PDFCrossRefSubSection,
    PDFFile,
    PDFTrailer,
)
from pdf_parser import PDFParser

__all__ = [
    'ParserContext',
    'get_parser_context',
    'set_parser_context',
    'MAL_ALL',
    'MAL_HEAD',
    'MAL_EOBJ',
    'MAL_ESTREAM',
    'MAL_XREF',
    'MAL_BAD_HEAD',
    'newLine',
    'spacesChars',
    'delimiterChars',
    'monitorizedEvents',
    'monitorizedActions',
    'monitorizedElements',
    'jsVulns',
    'singUniqueName',
    'bmpVuln',
    'vulnsDict',
    'jsContexts',
    'PDFObject',
    'PDFBool',
    'PDFNull',
    'PDFNum',
    'PDFName',
    'PDFString',
    'PDFHexString',
    'PDFReference',
    'PDFArray',
    'PDFDictionary',
    'PDFStream',
    'PDFObjectStream',
    'PDFIndirectObject',
    'PDFCrossRefSection',
    'PDFCrossRefSubSection',
    'PDFCrossRefEntry',
    'PDFBody',
    'PDFTrailer',
    'PDFFile',
    'PDFParser',
]
