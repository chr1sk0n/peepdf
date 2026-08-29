import unittest
from dataclasses import FrozenInstanceError

from parser_context import ParserContext, get_parser_context, set_parser_context


class ParserContextTests(unittest.TestCase):
    def test_default_context_is_inactive(self):
        ctx = get_parser_context()
        self.assertIsInstance(ctx, ParserContext)
        self.assertFalse(ctx.force_mode)
        self.assertFalse(ctx.manual_analysis)

    def test_context_manager_updates_and_resets_state(self):
        self.assertFalse(get_parser_context().force_mode)

        with set_parser_context(force_mode=True, manual_analysis=True):
            current = get_parser_context()
            self.assertTrue(current.force_mode)
            self.assertTrue(current.manual_analysis)

        self.assertFalse(get_parser_context().force_mode)
        self.assertFalse(get_parser_context().manual_analysis)

    def test_nested_context_restores_outer_state(self):
        with set_parser_context(force_mode=True, manual_analysis=False):
            self.assertTrue(get_parser_context().force_mode)
            self.assertFalse(get_parser_context().manual_analysis)

            with set_parser_context(force_mode=False, manual_analysis=True):
                self.assertFalse(get_parser_context().force_mode)
                self.assertTrue(get_parser_context().manual_analysis)

            self.assertTrue(get_parser_context().force_mode)
            self.assertFalse(get_parser_context().manual_analysis)

    def test_context_manager_resets_on_exception(self):
        try:
            with set_parser_context(force_mode=True):
                self.assertTrue(get_parser_context().force_mode)
                raise RuntimeError("Parser failure")
        except RuntimeError:
            pass

        self.assertFalse(get_parser_context().force_mode)

    def test_parser_context_is_frozen(self):
        ctx = ParserContext()
        with self.assertRaises(FrozenInstanceError):
            ctx.force_mode = True  # type: ignore


if __name__ == "__main__":
    unittest.main()
