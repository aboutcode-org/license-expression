# -*- coding: utf-8 -*-

"""
Tests for Aho-Corasick string search algorithm.
Original Author: Wojciech Muła, wojciech_mula@poczta.onet.pl
WWW            : http://0x80.pl
License        : public domain

Modified for use in the license_expression library and in particular:
 - add support for unicode key strinsg.
 - rename word to key and output to value (to be more like a mapping/dict)
 - case insensitive search
 - improve returned results with the actual start,end and matched string.
 - support returning non-matched parts of a string
"""

from __future__ import unicode_literals
from __future__ import absolute_import
from __future__ import print_function

import unittest

from license_expression._pyahocorasick import Trie
from license_expression._pyahocorasick import Output
from license_expression._pyahocorasick import Result


class TestTrie(unittest.TestCase):
    def testAddedWordShouldBeCountedAndAvailableForRetrieval(self):
        t = Trie()
        t.add('python', 'value')
        assert Output('python', 'value') == t.get('python')

    def testAddingExistingWordShouldReplaceAssociatedValue(self):
        t = Trie()
        t.add('python', 'value')
        assert Output('python', 'value') == t.get('python')

        t.add('python', 'other')
        assert Output('python', 'other') == t.get('python')

    def testGetUnknowWordWithoutDefaultValueShouldRaiseException(self):
        t = Trie()
        with self.assertRaises(KeyError):
            t.get('python')

    def testGetUnknowWordWithDefaultValueShouldReturnDefault(self):
        t = Trie()
        self.assertEqual(t.get('python', 'default'), 'default')

    def testExistShouldDetectAddedWords(self):
        t = Trie()
        t.add('python', 'value')
        t.add('ada', 'value')

        self.assertTrue(t.exists('python'))
        self.assertTrue(t.exists('ada'))

    def testExistShouldReturnFailOnUnknownWord(self):
        t = Trie()
        t.add('python', 'value')

        self.assertFalse(t.exists('ada'))

    def test_is_prefix_ShouldDetecAllPrefixesIncludingWord(self):
        t = Trie()
        t.add('python', 'value')
        t.add('ada', 'value')

        self.assertTrue(t.is_prefix('a'))
        self.assertTrue(t.is_prefix('ad'))
        self.assertTrue(t.is_prefix('ada'))

        self.assertTrue(t.is_prefix('p'))
        self.assertTrue(t.is_prefix('py'))
        self.assertTrue(t.is_prefix('pyt'))
        self.assertTrue(t.is_prefix('pyth'))
        self.assertTrue(t.is_prefix('pytho'))
        self.assertTrue(t.is_prefix('python'))

    def testItemsShouldReturnAllItemsAlreadyAddedToTheTrie(self):
        t = Trie()

        t.add('python', 1)
        t.add('ada', 2)
        t.add('perl', 3)
        t.add('pascal', 4)
        t.add('php', 5)

        result = list(t.items())
        self.assertIn(('python', 1), result)
        self.assertIn(('ada', 2), result)
        self.assertIn(('perl', 3), result)
        self.assertIn(('pascal', 4), result)
        self.assertIn(('php', 5), result)


    def testKeysShouldReturnAllKeysAlreadyAddedToTheTrie(self):
        t = Trie()

        t.add('python', 1)
        t.add('ada', 2)
        t.add('perl', 3)
        t.add('pascal', 4)
        t.add('php', 5)

        result = list(t.keys())
        self.assertIn('python', result)
        self.assertIn('ada', result)
        self.assertIn('perl', result)
        self.assertIn('pascal', result)
        self.assertIn('php', result)


    def testValuesShouldReturnAllValuesAlreadyAddedToTheTrie(self):
        t = Trie()

        t.add('python', 1)
        t.add('ada', 2)
        t.add('perl', 3)
        t.add('pascal', 4)
        t.add('php', 5)

        result = list(t.values())
        self.assertIn(1, result)
        self.assertIn(2, result)
        self.assertIn(3, result)
        self.assertIn(4, result)
        self.assertIn(5, result)

    def test_iter_should_not_return_non_matches(self):

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
        expected = [
            Result(start=0, end=1, string='he', output=Output('he', 'he')),
            Result(start=3, end=5, string='she', output=Output('she', 'she')),
            Result(start=4, end=5, string='he', output=Output('he', 'he')),
            Result(start=7, end=8, string='hi', output=Output('hi', 'hi')),
            Result(start=7, end=9, string='him', output=Output('him', 'him')),
            Result(start=7, end=11, string='himan', output=Output('himan', 'himan')),
            Result(start=9, end=11, string='man', output=Output('man', 'man'))
        ]

        assert expected == result

    def test_iter_vs_scan(self):
        def get_test_automaton():
            words = "( AND ) OR".split()
            t = Trie()
            for w in words:
                t.add(w, w)
            t.make_automaton()
            return t

        test_string = '((l-a + AND l-b) OR (l -c+))'

        t = get_test_automaton()
        result = list(t.iter(test_string))
        expected = [
            Result(0, 0, '(', Output('(', '(')),
            Result(1, 1, '(', Output('(', '(')),
            Result(8, 10, 'AND', Output('AND', 'AND')),
            Result(15, 15, ')', Output(')', ')')),
            Result(17, 18, 'OR', Output('OR', 'OR')),
            Result(20, 20, '(', Output('(', '(')),
            Result(26, 26, ')', Output(')', ')')),
            Result(27, 27, ')', Output(')', ')'))
        ]
        assert expected == result

        result = list(t.scan(test_string))
        expected = [
            Result(0, 0, '(', Output('(', '(')),
            Result(1, 1, '(', Output('(', '(')),
            Result(2, 7, 'l-a + ', None),
            Result(8, 10, 'AND', Output('AND', 'AND')),
            Result(11, 14, ' l-b', None),
            Result(15, 15, ')', Output(')', ')')),
            Result(16, 16, ' ', None),
            Result(17, 18, 'OR', Output('OR', 'OR')),
            Result(19, 19, ' ', None),
            Result(20, 20, '(', Output('(', '(')),
            Result(21, 25, 'l -c+', None),
            Result(26, 26, ')', Output(')', ')')),
            Result(27, 27, ')', Output(')', ')'))
        ]
        assert expected == result

    def test_scan_with_unmatched(self):
        def get_test_automaton():
            words = "( AND ) OR".split()
            t = Trie()
            for w in words:
                t.add(w, w)
            t.make_automaton()
            return t

        test_string = '((l-a + AND l-b) OR an (l -c+))'

        t = get_test_automaton()
        result = list(t.scan(test_string))
        assert test_string == ''.join(r.string for r in result)

    def test_iter_with_unmatched_simple(self):
        t = Trie()
        t.add('AND', 'AND')
        t.make_automaton()
        test_string = 'AND  an a and'
        result = list(t.iter(test_string))
        assert 'ANDand' == ''.join(r.string for r in result)

    def test_iter_with_unmatched_simple2(self):
        t = Trie()
        t.add('AND', 'AND')
        t.make_automaton()
        test_string = 'AND  an a and'
        result = list(t.iter(test_string))
        assert 'ANDand' == ''.join(r.string for r in result)

