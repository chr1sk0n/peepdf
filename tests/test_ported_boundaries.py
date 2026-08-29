import unittest
import zlib
from pathlib import Path

from pdf_core import PDFDictionary, PDFParser, ParserContext, get_parser_context
from pdf_filters import decodeStream
from pdf_utils import vtcheck


class FilterRegistryTests(unittest.TestCase):
    def test_flate_decoder_round_trip(self):
        status, decoded = decodeStream(zlib.compress(b"Hello"), "/FlateDecode")

        self.assertEqual(status, 0)
        self.assertEqual(decoded, b"Hello")

    def test_short_filter_alias_uses_same_decoder(self):
        status, decoded = decodeStream("48656c6c6f>", "/AHx")

        self.assertEqual(status, 0)
        self.assertTrue(decoded.startswith("Hello"))

    def test_unknown_filter_returns_error(self):
        status, message = decodeStream("", "/Unknown")

        self.assertEqual(status, -1)
        self.assertIn("Unknown filter", message)


class PdfModelTests(unittest.TestCase):
    fixture_path = Path(__file__).parent / "fixtures" / "minimal.pdf"
    malformed_fixture_path = Path(__file__).parent / "fixtures" / "malformed.pdf"

    def test_parser_reads_minimal_pdf_fixture(self):
        status, pdf_file = PDFParser().parse(str(self.fixture_path))

        self.assertEqual(status, 0)
        self.assertEqual(pdf_file.version, "1.4")
        self.assertEqual(pdf_file.numObjects, 4)
        self.assertEqual(pdf_file.numStreams, 1)
        self.assertEqual(pdf_file.errors, [])

    def test_parser_force_mode_reports_malformed_pdf_errors(self):
        status, pdf_file = PDFParser().parse(
            str(self.malformed_fixture_path), forceMode=True
        )

        self.assertEqual(status, 0)
        self.assertIn("PDF sections not found", pdf_file.errors)
        self.assertIn("No indirect objects found in the body", pdf_file.errors)

    def test_parser_context_is_restored_after_parse(self):
        self.assertEqual(get_parser_context(), ParserContext())

        PDFParser().parse(
            str(self.fixture_path), forceMode=True, manualAnalysis=True
        )

        self.assertEqual(get_parser_context(), ParserContext())

    def test_dictionary_elements_are_not_shared_between_instances(self):
        first = PDFDictionary()
        second = PDFDictionary()

        first.elements["/Name"] = "first"

        self.assertNotIn("/Name", second.elements)

    def test_virustotal_requires_external_api_key(self):
        status, message = vtcheck("hash", None)

        self.assertEqual(status, -1)
        self.assertIn("not configured", message)


if __name__ == "__main__":
    unittest.main()


class ModuleStructureTests(unittest.TestCase):
    def test_reexported_facade_symbols(self):
        import pdf_core
        import PDFCore
        import pdf_constants
        import pdf_objects
        import pdf_structure
        import pdf_parser

        self.assertIs(pdf_core.PDFParser, pdf_parser.PDFParser)
        self.assertIs(PDFCore.PDFParser, pdf_parser.PDFParser)
        self.assertIs(pdf_core.PDFFile, pdf_structure.PDFFile)
        self.assertIs(PDFCore.PDFFile, pdf_structure.PDFFile)
        self.assertIs(pdf_core.PDFDictionary, pdf_objects.PDFDictionary)
        self.assertIs(PDFCore.PDFDictionary, pdf_objects.PDFDictionary)
        self.assertEqual(pdf_core.MAL_ALL, pdf_constants.MAL_ALL)
        self.assertEqual(PDFCore.MAL_ALL, pdf_constants.MAL_ALL)

    def test_direct_modular_imports(self):
        from pdf_constants import MAL_ALL
        from pdf_objects import PDFDictionary
        from pdf_structure import PDFFile
        from pdf_parser import PDFParser

        self.assertEqual(MAL_ALL, 1)
        self.assertIsNotNone(PDFDictionary)
        self.assertIsNotNone(PDFFile)
        self.assertIsNotNone(PDFParser)
