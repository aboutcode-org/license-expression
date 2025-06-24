# -*- coding: utf-8 -*-
#
# SPDX-License-Identifier: LicenseRef-scancode-public-domain
# See https://github.com/aboutcode-org/license-expression for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.

"""
Tests for Aho-Corasick string search algorithm.
Original Author: Wojciech Muła, wojciech_mula@poczta.onet.pl
WWW            : http://0x80.pl
License        : public domain

Modified for use in the license_expression library.
"""

import unittest

from license_expression._pyahocorasick import Trie
from license_expression._pyahocorasick import Token


class TestTrie(unittest.TestCase):
    def test_add_can_get(self):
        t = Trie()
        t.add("python", "value")
        assert ("python", "value") == t.get("python")

    def test_add_existing_WordShouldReplaceAssociatedValue(self):
        t = Trie()
        t.add("python", "value")
        assert ("python", "value") == t.get("python")

        t.add("python", "other")
        assert ("python", "other") == t.get("python")

    def test_get_UnknowWordWithoutDefaultValueShouldRaiseException(self):
        t = Trie()
        with self.assertRaises(KeyError):
            t.get("python")

    def test_get_UnknowWordWithDefaultValueShouldReturnDefault(self):
        t = Trie()
        self.assertEqual(t.get("python", "default"), "default")

    def test_exists_ShouldDetectAddedWords(self):
        t = Trie()
        t.add("python", "value")
        t.add("ada", "value")

        self.assertTrue(t.exists("python"))
        self.assertTrue(t.exists("ada"))

    def test_exists_ShouldReturnFailOnUnknownWord(self):
        t = Trie()
        t.add("python", "value")

        self.assertFalse(t.exists("ada"))

    def test_is_prefix_ShouldDetecAllPrefixesIncludingWord(self):
        t = Trie()
        t.add("python", "value")
        t.add("ada lovelace", "value")

        self.assertFalse(t.is_prefix("a"))
        self.assertFalse(t.is_prefix("ad"))
        self.assertTrue(t.is_prefix("ada"))

        self.assertFalse(t.is_prefix("p"))
        self.assertFalse(t.is_prefix("py"))
        self.assertFalse(t.is_prefix("pyt"))
        self.assertFalse(t.is_prefix("pyth"))
        self.assertFalse(t.is_prefix("pytho"))
        self.assertTrue(t.is_prefix("python"))

        self.assertFalse(t.is_prefix("lovelace"))

    def test_items_ShouldReturnAllItemsAlreadyAddedToTheTrie(self):
        t = Trie()

        t.add("python", 1)
        t.add("ada", 2)
        t.add("perl", 3)
        t.add("pascal", 4)
        t.add("php", 5)
        t.add("php that", 6)

        result = list(t.items())
        self.assertIn(("python", 1), result)
        self.assertIn(("ada", 2), result)
        self.assertIn(("perl", 3), result)
        self.assertIn(("pascal", 4), result)
        self.assertIn(("php", 5), result)
        self.assertIn(("php that", 6), result)

    def test_keys_ShouldReturnAllKeysAlreadyAddedToTheTrie(self):
        t = Trie()

        t.add("python", 1)
        t.add("ada", 2)
        t.add("perl", 3)
        t.add("pascal", 4)
        t.add("php", 5)
        t.add("php that", 6)

        result = list(t.keys())
        self.assertIn("python", result)
        self.assertIn("ada", result)
        self.assertIn("perl", result)
        self.assertIn("pascal", result)
        self.assertIn("php", result)
        self.assertIn("php that", result)

    def test_values_ShouldReturnAllValuesAlreadyAddedToTheTrie(self):
        t = Trie()

        t.add("python", 1)
        t.add("ada", 2)
        t.add("perl", 3)
        t.add("pascal", 4)
        t.add("php", 5)

        result = list(t.values())
        self.assertIn(1, result)
        self.assertIn(2, result)
        self.assertIn(3, result)
        self.assertIn(4, result)
        self.assertIn(5, result)

    def test_iter_should_not_return_non_matches_by_default(self):
        def get_test_automaton():
            words = "he her hers his she hi him man himan".split()
            t = Trie()
            for w in words:
                t.add(w, w)
            t.make_automaton()
            return t

        test_string = "he she himan"

        t = get_test_automaton()
        result = list(t.iter(test_string))
        assert "he she himan".split() == [r.value for r in result]

    def test_iter_should_can_return_non_matches_optionally(self):
        def get_test_automaton():
            words = "he her hers his she hi him man himan".split()
            t = Trie()
            for w in words:
                t.add(w, w)
            t.make_automaton()
            return t

        test_string = "  he she junk  himan  other stuffs   "
        #                        111111111122222222223333333
        #              0123456789012345678901234567890123456

        t = get_test_automaton()
        result = list(t.iter(test_string, include_unmatched=True, include_space=True))
        expected = [
            Token(0, 1, "  ", None),
            Token(2, 3, "he", "he"),
            Token(4, 4, " ", None),
            Token(5, 7, "she", "she"),
            Token(8, 8, " ", None),
            Token(9, 12, "junk", None),
            Token(13, 14, "  ", None),
            Token(15, 19, "himan", "himan"),
            Token(20, 21, "  ", None),
            Token(22, 26, "other", None),
            Token(27, 27, " ", None),
            Token(28, 33, "stuffs", None),
            Token(34, 36, "   ", None),
        ]

        assert expected == result

    def test_iter_vs_tokenize(self):
        def get_test_automaton():
            words = "( AND ) OR".split()
            t = Trie()
            for w in words:
                t.add(w, w)
            t.make_automaton()
            return t

        test_string = "((l-a + AND l-b) OR (l -c+))"

        t = get_test_automaton()
        result = list(t.iter(test_string, include_unmatched=True, include_space=True))
        expected = [
            Token(0, 0, "(", "("),
            Token(1, 1, "(", "("),
            Token(2, 4, "l-a", None),
            Token(5, 5, " ", None),
            Token(6, 6, "+", None),
            Token(7, 7, " ", None),
            Token(8, 10, "AND", "AND"),
            Token(11, 11, " ", None),
            Token(12, 14, "l-b", None),
            Token(15, 15, ")", ")"),
            Token(16, 16, " ", None),
            Token(17, 18, "OR", "OR"),
            Token(19, 19, " ", None),
            Token(20, 20, "(", "("),
            Token(21, 21, "l", None),
            Token(22, 22, " ", None),
            Token(23, 25, "-c+", None),
            Token(26, 26, ")", ")"),
            Token(27, 27, ")", ")"),
        ]

        assert expected == result

        result = list(t.tokenize(test_string, include_unmatched=True, include_space=True))
        assert expected == result

    def test_tokenize_with_unmatched_and_space(self):
        def get_test_automaton():
            words = "( AND ) OR".split()
            t = Trie()
            for w in words:
                t.add(w, w)
            t.make_automaton()
            return t

        test_string = "((l-a + AND l-b) OR an (l -c+))"
        #                        111111111122222222223
        #              0123456789012345678901234567890
        t = get_test_automaton()
        result = list(t.tokenize(test_string, include_unmatched=True, include_space=True))
        expected = [
            Token(0, 0, "(", "("),
            Token(1, 1, "(", "("),
            Token(2, 4, "l-a", None),
            Token(5, 5, " ", None),
            Token(6, 6, "+", None),
            Token(7, 7, " ", None),
            Token(8, 10, "AND", "AND"),
            Token(11, 11, " ", None),
            Token(12, 14, "l-b", None),
            Token(15, 15, ")", ")"),
            Token(16, 16, " ", None),
            Token(17, 18, "OR", "OR"),
            Token(19, 19, " ", None),
            Token(20, 21, "an", None),
            Token(22, 22, " ", None),
            Token(23, 23, "(", "("),
            Token(24, 24, "l", None),
            Token(25, 25, " ", None),
            Token(26, 28, "-c+", None),
            Token(29, 29, ")", ")"),
            Token(30, 30, ")", ")"),
        ]

        assert expected == result
        assert test_string == "".join(t.string for t in result)

    def test_iter_with_unmatched_simple(self):
        t = Trie()
        t.add("And", "And")
        t.make_automaton()
        test_string = "AND  an a And"
        result = list(t.iter(test_string))
        assert ["And", "And"] == [r.value for r in result]

    def test_iter_with_unmatched_simple2(self):
        t = Trie()
        t.add("AND", "AND")
        t.make_automaton()
        test_string = "AND  an a and"
        result = list(t.iter(test_string))
        assert ["AND", "AND"] == [r.value for r in result]

    def test_iter_with_unmatched_simple3(self):
        t = Trie()
        t.add("AND", "AND")
        t.make_automaton()
        test_string = "AND  an a andersom"
        result = list(t.iter(test_string))
        assert ["AND"] == [r.value for r in result]

    def test_iter_simple(self):
        t = Trie()
        t.add("AND", "AND")
        t.add("OR", "OR")
        t.add("WITH", "WITH")
        t.add("(", "(")
        t.add(")", ")")
        t.add("GPL-2.0", "GPL-2.0")
        t.add("mit", "MIT")
        t.add("Classpath", "Classpath")
        t.make_automaton()
        test_string = "(GPL-2.0 with Classpath) or (gpl-2.0) and (classpath or  gpl-2.0 OR mit) "
        #                        111111111122222222223333333333444444444455555555556666666666777
        #              0123456789012345678901234567890123456789012345678901234567890123456789012
        result = list(t.iter(test_string))
        expected = [
            Token(0, 0, "(", "("),
            Token(1, 7, "GPL-2.0", "GPL-2.0"),
            Token(9, 12, "with", "WITH"),
            Token(14, 22, "Classpath", "Classpath"),
            Token(23, 23, ")", ")"),
            Token(25, 26, "or", "OR"),
            Token(28, 28, "(", "("),
            Token(29, 35, "gpl-2.0", "GPL-2.0"),
            Token(36, 36, ")", ")"),
            Token(38, 40, "and", "AND"),
            Token(42, 42, "(", "("),
            Token(43, 51, "classpath", "Classpath"),
            Token(53, 54, "or", "OR"),
            Token(57, 63, "gpl-2.0", "GPL-2.0"),
            Token(65, 66, "OR", "OR"),
            Token(68, 70, "mit", "MIT"),
            Token(71, 71, ")", ")"),
        ]

        assert expected == result
