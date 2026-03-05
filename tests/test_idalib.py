#!/usr/bin/python3

"""
Integration tests for IDAMagicStrings using idalib.
"""

import os
import sys
import unittest

#-------------------------------------------------------------------------------
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
BIN_DIR = os.path.join(TESTS_DIR, "bin")
ROOT_DIR = os.path.dirname(TESTS_DIR)

try:
    import idapro
    HAS_IDALIB = True
except ImportError:
    HAS_IDALIB = False

#-------------------------------------------------------------------------------
def open_database(binary_path):
    """Open a binary for analysis with idalib and wait for auto-analysis."""
    idapro.open_database(binary_path, True)
    import ida_auto
    ida_auto.auto_wait()

#-------------------------------------------------------------------------------
def close_database():
    """Close the current idalib database without saving."""
    idapro.close_database(False)

#-------------------------------------------------------------------------------
def import_plugin():
    """Import IDAMagicStrings after idalib has initialized IDA modules."""
    sys.path.insert(0, ROOT_DIR)
    import IDAMagicStrings
    return IDAMagicStrings

#-------------------------------------------------------------------------------
@unittest.skipUnless(HAS_IDALIB, "idalib not available")
class TestClassifierTester(unittest.TestCase):
    """Tests using the classifier_tester binary (C++ with source file strings)."""
    ims = None

    @classmethod
    def setUpClass(cls):
        binary = os.path.join(BIN_DIR, "classifier_tester")
        if not os.path.exists(binary):
            raise unittest.SkipTest(f"Test binary not found: {binary}")
        open_database(binary)
        cls.ims = import_plugin()

    @classmethod
    def tearDownClass(cls):
        close_database()

    def test_get_source_strings_finds_cpp_files(self):
        d, strings = self.ims.get_source_strings()
        self.assertGreater(len(d), 0, "Should find source file references")

        extensions = set()
        for path in d:
            ext = os.path.splitext(path)[1].lower()
            extensions.add(ext)

        cpp_exts = {".cpp", ".h", ".cc", ".cxx", ".hpp"}
        found = extensions & cpp_exts
        self.assertGreater(len(found), 0,
            f"Should find C/C++ source files, got extensions: {extensions}")

    def test_get_source_strings_known_paths(self):
        d, strings = self.ims.get_source_strings()
        all_paths = " ".join(d.keys()).lower()
        self.assertIn("trainingsampleset.cpp", all_paths)

    def test_find_function_names(self):
        _, strings = self.ims.get_source_strings()
        func_names, raw_func_strings, rarity, class_objects = \
            self.ims.find_function_names(strings)
        self.assertGreater(len(func_names) + len(class_objects), 0,
            "Should find function names or class objects")

    def test_find_class_objects_from_strings(self):
        _, strings = self.ims.get_source_strings()
        class_names = self.ims.collect_class_names_from_symbols()
        all_strings = class_names + list(strings)
        class_objects = self.ims.find_class_objects(all_strings)
        self.assertIsInstance(class_objects, list)
        for item in class_objects:
            self.assertEqual(len(item), 2)
            self.assertIsInstance(item[0], int)
            self.assertIsInstance(item[1], list)

#-------------------------------------------------------------------------------
@unittest.skipUnless(HAS_IDALIB, "idalib not available")
class TestDocker(unittest.TestCase):
    """Tests using the docker binary (Go with debug info and source file strings)."""
    ims = None

    @classmethod
    def setUpClass(cls):
        binary = os.path.join(BIN_DIR, "docker")
        if not os.path.exists(binary):
            raise unittest.SkipTest(f"Test binary not found: {binary}")
        open_database(binary)
        cls.ims = import_plugin()

    @classmethod
    def tearDownClass(cls):
        close_database()

    def test_get_source_strings_finds_go_files(self):
        d, strings = self.ims.get_source_strings()
        self.assertGreater(len(d), 0, "Should find source file references")

        extensions = set()
        for path in d:
            ext = os.path.splitext(path)[1].lower()
            extensions.add(ext)

        self.assertIn(".go", extensions, "Should find .go source files")

    def test_get_source_strings_known_paths(self):
        d, strings = self.ims.get_source_strings()
        all_paths = " ".join(d.keys()).lower()
        self.assertIn(".go", all_paths)

    def test_find_function_names(self):
        _, strings = self.ims.get_source_strings()
        func_names, raw_func_strings, rarity, class_objects = \
            self.ims.find_function_names(strings)
        self.assertIsInstance(func_names, dict)
        self.assertIsInstance(rarity, dict)
        self.assertIsInstance(class_objects, list)

if __name__ == "__main__":
    unittest.main()
