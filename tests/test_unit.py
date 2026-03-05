#!/usr/bin/python3

"""
Unit tests for pure logic functions in IDAMagicStrings that do not require IDA.
"""

import os
import sys
import unittest
from unittest.mock import MagicMock

#-------------------------------------------------------------------------------
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(TESTS_DIR)

# Mock IDA modules so we can import IDAMagicStrings outside of IDA
IDA_MODULES = [
    "idc", "idaapi", "idautils", "ida_bytes", "ida_funcs", "ida_gdl",
    "ida_graph", "ida_ida", "ida_idaapi", "ida_kernwin", "ida_lines",
    "ida_name", "PySide6", "PySide6.QtCore", "PySide6.QtGui",
    "PySide6.QtWidgets",
]
for mod in IDA_MODULES:
    sys.modules.setdefault(mod, MagicMock())

sys.path.insert(0, ROOT_DIR)
import IDAMagicStrings as ims

#-------------------------------------------------------------------------------
class FakeString:
    def __init__(self, ea, s):
        self.ea = ea
        self.s = s

    def __str__(self):
        return str(self.s)

#-------------------------------------------------------------------------------
# Tests for seems_function_name()
class TestSeemsFunctionName(unittest.TestCase):
    def test_valid_function_names(self):
        self.assertTrue(ims.seems_function_name("processData"))
        self.assertTrue(ims.seems_function_name("calculate_result"))
        self.assertTrue(ims.seems_function_name("myFunction"))
        self.assertTrue(ims.seems_function_name("parseInput"))

    def test_too_short(self):
        self.assertFalse(ims.seems_function_name("foo"))
        self.assertFalse(ims.seems_function_name("ab"))
        self.assertFalse(ims.seems_function_name(""))
        self.assertFalse(ims.seems_function_name("12345"))

    def test_exactly_six_chars(self):
        self.assertTrue(ims.seems_function_name("abcDef"))
        self.assertFalse(ims.seems_function_name("abcde"))

    def test_all_uppercase_rejected(self):
        self.assertFalse(ims.seems_function_name("ALLCAPS"))
        self.assertFalse(ims.seems_function_name("MY_CONST"))
        self.assertFalse(ims.seems_function_name("SOME_DEFINE"))

    def test_blacklisted_names(self):
        for name in ["copyright", "warning", "integer", "unknown",
                      "localhost", "overflow", "argument"]:
            self.assertFalse(ims.seems_function_name(name), f"{name} should be rejected")

    def test_blacklist_is_case_insensitive(self):
        self.assertFalse(ims.seems_function_name("Copyright"))
        self.assertFalse(ims.seems_function_name("WARNING"))
        self.assertFalse(ims.seems_function_name("Integer"))


#-------------------------------------------------------------------------------
# Tests for is_valid_nltk_token()
class TestIsValidNltkToken(unittest.TestCase):
    def setUp(self):
        self._orig_has_nltk = ims.has_nltk
        self._orig_found_tokens = ims.FOUND_TOKENS.copy()

    def test_no_nltk_always_true(self):
        ims.has_nltk = False
        self.assertTrue(ims.is_valid_nltk_token("anything"))
        self.assertTrue(ims.is_valid_nltk_token("processData"))

    def test_candidate_not_in_tokens(self):
        ims.has_nltk = True
        ims.FOUND_TOKENS["other_word"] = {"NN"}
        self.assertFalse(ims.is_valid_nltk_token("missing_word"))

    def test_candidate_with_valid_token_type(self):
        ims.has_nltk = True
        ims.FOUND_TOKENS["process"] = {"NN", "VB"}
        self.assertTrue(ims.is_valid_nltk_token("process"))

    def test_candidate_with_no_valid_token_type(self):
        ims.has_nltk = True
        ims.FOUND_TOKENS["something"] = {"DT", "IN"}
        self.assertFalse(ims.is_valid_nltk_token("something"))

    def test_multiple_token_types_one_valid(self):
        ims.has_nltk = True
        ims.FOUND_TOKENS["handler"] = {"DT", "NNP", "IN"}
        self.assertTrue(ims.is_valid_nltk_token("handler"))

    def tearDown(self):
        ims.has_nltk = self._orig_has_nltk
        ims.FOUND_TOKENS.clear()
        ims.FOUND_TOKENS.update(self._orig_found_tokens)


#-------------------------------------------------------------------------------
# Tests for find_class_objects()
class TestFindClassObjects(unittest.TestCase):
    def test_simple_class(self):
        strings = [FakeString(0x1000, "std::string")]
        result = ims.find_class_objects(strings)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], [0x1000, ["std", "string"]])

    def test_nested_class(self):
        strings = [FakeString(0x2000, "std::map::iterator")]
        result = ims.find_class_objects(strings)
        self.assertTrue(len(result) >= 1)
        found_tokens = [tokens for _, tokens in result]
        self.assertIn(["std", "map", "iterator"], found_tokens)

    def test_destructor(self):
        strings = [FakeString(0x3000, "myclass::~myclass")]
        result = ims.find_class_objects(strings)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], [0x3000, ["myclass", "~myclass"]])

    def test_no_class_names(self):
        strings = [FakeString(0x4000, "just_a_plain_string")]
        result = ims.find_class_objects(strings)
        self.assertEqual(len(result), 0)

    def test_duplicate_from_different_strings(self):
        strings = [
            FakeString(0x5000, "foo::bar"),
            FakeString(0x6000, "foo::bar"),
        ]
        result = ims.find_class_objects(strings)
        # NOTE: dedup in find_class_objects compares tokens against [ea, tokens]
        # entries, so it does not actually prevent duplicates across strings.
        self.assertEqual(len(result), 2)

    def test_multiple_classes_in_one_string(self):
        strings = [FakeString(0x7000, "aaa::bbb and ccc::ddd")]
        result = ims.find_class_objects(strings)
        found_tokens = [tokens for _, tokens in result]
        self.assertIn(["aaa", "bbb"], found_tokens)
        self.assertIn(["ccc", "ddd"], found_tokens)

    def test_empty_input(self):
        result = ims.find_class_objects([])
        self.assertEqual(result, [])

    def test_template_syntax(self):
        strings = [FakeString(0x8000, "std::<allocator>")]
        result = ims.find_class_objects(strings)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], [0x8000, ["std", "<allocator>"]])


if __name__ == "__main__":
    unittest.main()
