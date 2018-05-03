# -*- coding: utf-8 -*-
"""
Aho-Corasick string search algorithm.

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

from collections import deque
from collections import OrderedDict
import logging

logger = logging.getLogger(__name__)


def logger_debug(*args):
    return logger.debug(' '.join(isinstance(a, str) and a or repr(a) for a in args))

# uncomment for local debug logging
# import sys
# logging.basicConfig(stream=sys.stdout)
# logger.setLevel(logging.DEBUG)


# used to distinguish from None
nil = object()


class Trie(object):
    """
    A Trie and Aho-Corasick automaton. This behaves more or less like a mapping of
    key->value. This is the main entry point.
    """

    def __init__(self, ignore_case=True):
        """
        Initialize a new Trie.

        If `ignore_case` is True, searches in the Trie will be case insensitive.
        """
        self.root = TrieNode('')
        self.ignore_case = ignore_case

        # set of any unique character in the trie, updated on each addition
        # we keep track of the set of chars added to the trie to build the automaton
        # these are needed to created the first level children failure links
        self._known_chars = set()

        # Flag set to True once a Trie has been converted to an Aho-Corasick automaton
        self._converted = False

    def add(self, key, value=None, priority=0):
        """
        Add a new (key string, value) pair to the trie. If the key already exists in
        the Trie, its value is replaced with the provided value.
        A key is any unicode string.
        """
        if self._converted:
            raise Exception('This Trie has been converted to an Aho-Corasick '
                            'automaton and cannot be further modified.')
        if not key:
            return

        stored_key = self.ignore_case and key.lower() or key

        # we keep track of the set of chars added to the trie to build the automaton
        # these are needed to created the first level children failure links
        self._known_chars.update(stored_key)

        node = self.root
        for char in stored_key:
            try:
                node = node.children[char]
            except KeyError:
                child = TrieNode(char)
                node.children[char] = child
                node = child

        # we always store the original key, not a possibly lowercased version
        node.output = Output(key, value, priority)

    def __get_node(self, key):
        """
        Return a node for this key or None if the trie does not contain the key.
        Private function retrieving a final node of trie for given key.
        """
        key = self.ignore_case and key.lower() or key
        node = self.root
        for char in key:
            try:
                node = node.children[char]
            except KeyError:
                return None
        return node

    def get(self, key, default=nil):
        """
        Return the Output tuple associated with a `key`.
        If there is no such key in the Trie, return the default value (other
        than nil): if default is not given or nil, raise a KeyError exception.
        """
        node = self.__get_node(key)
        output = nil
        if node:
            output = node.output

        if output is nil:
            if default is nil:
                raise KeyError(key)
            else:
                return default
        else:
            return output

    def keys(self):
        """
        Yield all keys stored in this trie.
        """
        return (key for key, _ in self.items())

    def values(self):
        """
        Yield all values associated with keys stored in this trie.
        """
        return (value for _, value in self.items())

    def items(self):
        """
        Yield tuple of all (key, value) stored in this trie.
        """
        items = []

        def walk(node, key):
            """
            Walk the trie, depth first.
            """
            key = key + node.char
            if node.output is not nil:
                items.append((node.output.key, node.output.value))

            for child in node.children.values():
                if child is not node:
                    walk(child, key)

        walk(self.root, key='')

        return iter(items)

    def exists(self, key):
        """
        Return True if the key is present in this trie.
        """
        # TODO: add __contains__ magic for this
        node = self.__get_node(key)
        if node:
            return bool(node.output != nil)
        return False

    def is_prefix(self, key):
        """
        Return True if key is a prefix of any existing key in the trie.
        """
        return (self.__get_node(key) is not None)

    def make_automaton(self):
        """
        Convert this trie to an Aho-Corasick automaton.
        Note that this is an error to add new keys to a Trie once it has been
        converted to an Automaton.
        """
        queue = deque()
        queue_append = queue.append
        queue_popleft = queue.popleft

        # 1. create root children for each known items range (e.g. all unique
        # characters from all the added keys), failing to root.
        # And build a queue of these
        for char in self._known_chars:
            if char in self.root.children:
                node = self.root.children[char]
                # e.g. f(s) = 0, Aho-Corasick-wise
                node.fail = self.root
                queue_append(node)
            else:
                self.root.children[char] = self.root

        # 2. using the queue of all possible top level items/chars, walk the trie and
        # add failure links to nodes as needed
        while queue:
            current_node = queue_popleft()
            for node in current_node.children.values():
                queue_append(node)
                state = current_node.fail
                while node.char not in state.children:
                    state = state.fail
                node.fail = state.children.get(node.char, self.root)

        # Mark the trie as converted so it cannot be modified anymore
        self._converted = True

    def iter(self, string):
        """
        Yield Result objects for matched strings by performing the Aho-Corasick search procedure.

        The Result start and end positions in the searched string are such that the
        matched string is "search_string[start:end+1]". And the start is computed
        from the end_index collected by the Aho-Corasick search procedure such that
        "start=end_index - n + 1" where n is the length of a matched key.

        The Result.output is an Output object for a matched key.

        For example:
        >>> a = Trie()
        >>> a.add('BCDEF')
        >>> a.add('CDE')
        >>> a.add('DEFGH')
        >>> a.add('EFGH')
        >>> a.add('KL')
        >>> a.make_automaton()
        >>> string = 'abcdefghijklm'
        >>> results = Result.sort(a.iter(string))

        >>> expected = [
        ...     Result(1, 5, 'bcdef', Output('BCDEF')),
        ...     Result(2, 4, 'cde', Output('CDE')),
        ...     Result(3, 7, 'defgh', Output('DEFGH')),
        ...     Result(4, 7, 'efgh', Output('EFGH')),
        ...     Result(10, 11, 'kl', Output('KL')),
        ... ]
        >>> results == expected
        True

        >>> list(a.iter('')) == []
        True

        >>> list(a.iter(' ')) == []
        True
        """
        if not string:
            return

        # keep a copy for results
        original_string = string
        string = self.ignore_case and string.lower() or string

        known_chars = self._known_chars
        state = self.root
        for end, char in enumerate(string):
            if char not in known_chars:
                state = self.root
                continue

            # search for a matching character in the children, starting at root
            while char not in state.children:
                state = state.fail
            # we have a matching starting character
            state = state.children.get(char, self.root)
            match = state
            while match is not nil:
                if match.output is not nil:
                    # TODO: this could be precomputed or cached
                    n = len(match.output.key)
                    start = end - n + 1
                    yield Result(start, end, original_string[start:end + 1], match.output)
                match = match.fail

    def scan(self, string):
        """
        Scan a string for matched and unmatched sub-sequences and yield non-
        overlapping Result objects performing a modified Aho-Corasick search
        procedure:

        - return both matched and unmatched sub-sequences.
        - do not return matches with positions that are contained or overlap with
          another match:
          - discard smaller matches contained in a larger match.
          - when there is overlap (but not containment), the matches are sorted by
            start and biggest length and then:
             - we return the largest match of two overlaping matches
             - if they have the same length, keep the match starting the earliest and
               return the non-overlapping portion of the other discarded match as a
               non-match.

        Each Result contains the start and end position, the corresponding string and
        an Output object (with original key and any associated associated value). The
        string and key are in their original case even if the automaton has the
        `ignore_case` attribute.

        For example:
        >>> a = Trie()
        >>> a.add('BCDEF')
        >>> a.add('CDE')
        >>> a.add('DEFGH')
        >>> a.add('EFGH')
        >>> a.add('KL')
        >>> a.make_automaton()
        >>> string = 'abcdefghijkl'
        >>> results = list(a.scan(string))

        >>> expected = [
        ...     Result(start=0, end=0, string='a', output=None),
        ...     Result(start=1, end=5, string='bcdef', output=Output('BCDEF')),
        ...     Result(start=6, end=9, string='ghij', output=None),
        ...     Result(start=10, end=11, string='kl', output=Output('KL')),
        ... ]

        >>> results == expected
        True
        """
        results = self.iter(string)
        results = filter_overlapping(results)
        results = add_unmatched(string, results)
        return results


class TrieNode(object):
    """
    Node of the Trie/Aho-Corasick automaton.
    """
    __slots__ = ['char', 'output', 'fail', 'children']

    def __init__(self, char, output=nil):
        # character of a key string added to the Trie
        self.char = char

        # an output function (in the Aho-Corasick meaning) for this node: this is an
        # Output object that contains the original key string and any additional
        # value data associated to that key. Or "nil" for a node that is not a
        # terminal leave for a key. It will be returned with a match.
        self.output = output

        # failure link used by the Aho-Corasick automaton and its search procedure
        self.fail = nil

        # children of this node as a mapping of char->node
        self.children = {}

    def __repr__(self):
        if self.output is not nil:
            return 'TrieNode(%r, %r)' % (self.char, self.output)
        else:
            return 'TrieNode(%r)' % self.char


class Output(object):
    """
    An Output is used to track a key added to the Trie as a TrieNode and any
    arbitrary value object corresponding to that key.

    - `key` is the original key unmodified unicode string.
    - `value` is the associated value for this key as provided when adding this key.
    - `priority` is an optional priority for this key used to disambiguate overalpping matches.
    """
    __slots__ = 'key', 'value', 'priority'

    def __init__(self, key, value=None, priority=0):
        self.key = key
        self.value = value
        self.priority = priority

    def __repr__(self):
        return self.__class__.__name__ + '(%(key)r, %(value)r, %(priority)r)' % self.as_dict()

    def __eq__(self, other):
        return (
            isinstance(other, Output)
            and self.key == other.key
            and self.value == other.value
            and self.priority == other.priority)

    def __hash__(self):
        return hash((self.key, self.value, self.priority,))

    def as_dict(self):
        return OrderedDict([(s, getattr(self, s)) for s in self.__slots__])


class Result(object):
    """
    A Result is used to track the result of a search with its start and end as
    index position in the original string and other attributes:

    - `start` and `end` are zero-based index in the original string S such that
         S[start:end+1] will yield `string`.
    - `string` is the sub-string from the original searched string for this Result.
    - `output` is the Output object for a matched string and is a marker that this is a
       matched string. None otherwise for a Result for unmatched text.
    """

    __slots__ = 'start', 'end', 'string', 'output'

    def __init__(self, start, end, string='', output=None):
        self.start = start
        self.end = end
        self.string = string
        self.output = output

    def __repr__(self):
        return self.__class__.__name__ + '(%(start)r, %(end)r, %(string)r, %(output)r)' % self.as_dict()

    def as_dict(self):
        return OrderedDict([(s, getattr(self, s)) for s in self.__slots__])

    def __len__(self):
        return self.end + 1 - self.start

    def __eq__(self, other):
        return isinstance(other, Result) and (
            self.start == other.start and
            self.end == other.end and
            self.string == other.string and
            self.output == other.output
        )

    def __hash__(self):
        tup = self.start, self.end, self.string, self.output
        return hash(tup)

    @property
    def priority(self):
        return getattr(self.output, 'priority', 0)

    def is_after(self, other):
        """
        Return True if this result is after the other result.

        For example:
        >>> Result(1, 2).is_after(Result(5, 6))
        False
        >>> Result(5, 6).is_after(Result(5, 6))
        False
        >>> Result(2, 3).is_after(Result(1, 2))
        False
        >>> Result(5, 6).is_after(Result(3, 4))
        True
        """
        return self.start > other.end

    def is_before(self, other):
        return self.end < other.start

    def __contains__(self, other):
        """
        Return True if this result contains the other result.

        For example:
        >>> Result(5, 7) in Result(5, 7)
        True
        >>> Result(6, 8) in Result(5, 7)
        False
        >>> Result(6, 6) in Result(4, 8)
        True
        >>> Result(3, 9) in Result(4, 8)
        False
        >>> Result(4, 8) in Result(3, 9)
        True
        """
        return self.start <= other.start and other.end <= self.end

    def overlap(self, other):
        """
        Return True if this result and the other result overlap.

        For example:
        >>> Result(1, 2).overlap(Result(5, 6))
        False
        >>> Result(5, 6).overlap(Result(5, 6))
        True
        >>> Result(4, 5).overlap(Result(5, 6))
        True
        >>> Result(4, 5).overlap(Result(5, 7))
        True
        >>> Result(4, 5).overlap(Result(6, 7))
        False
        """
        start = self.start
        end = self.end
        return (start <= other.start <= end) or (start <= other.end <= end)

    @classmethod
    def sort(cls, results):
        """
        Return a new sorted sequence of results given a sequence of results. The
        primary sort is on start and the secondary sort is on longer lengths.
        Therefore if two results have the same start, the longer result will sort
        first.

        For example:
        >>> results = [Result(0, 0), Result(5, 5), Result(1, 1), Result(2, 4), Result(2, 5)]
        >>> expected = [Result(0, 0), Result(1, 1), Result(2, 5), Result(2, 4), Result(5, 5)]
        >>> expected == Result.sort(results)
        True
        """
        key = lambda s: (s.start, -len(s),)
        return sorted(results, key=key)


def filter_overlapping(results):
    """
    Return a new list from an iterable of `results` discarding contained and
    overlaping Results using these rules:

    - skip a result fully contained in another result.
    - keep the biggest, left-most result of two overlapping results and skip the other

    For example:
    >>> results = [
    ...     Result(0, 0, 'a'),
    ...     Result(1, 5, 'bcdef'),
    ...     Result(2, 4, 'cde'),
    ...     Result(3, 7, 'defgh'),
    ...     Result(4, 7, 'efgh'),
    ...     Result(8, 9, 'ij'),
    ...     Result(10, 13, 'klmn'),
    ...     Result(11, 15, 'lmnop'),
    ...     Result(16, 16, 'q'),
    ... ]

    >>> expected = [
    ...     Result(0, 0, 'a'),
    ...     Result(1, 5, 'bcdef'),
    ...     Result(8, 9, 'ij'),
    ...     Result(11, 15, 'lmnop'),
    ...     Result(16, 16, 'q'),
    ... ]

    >>> filtered = list(filter_overlapping(results))
    >>> filtered == expected
    True
    """
    results = Result.sort(results)

    # compare pair of results in the sorted sequence: current and next
    i = 0
    while i < len(results) - 1:
        j = i + 1
        while j < len(results):
            curr_res = results[i]
            next_res = results[j]

            logger_debug('curr_res, i, next_res, j:', curr_res, i, next_res, j)
            # disjoint results: break, there is nothing to do
            if next_res.is_after(curr_res):
                logger_debug('  break to next', curr_res)
                break

            # contained result: discard the contained result
            if next_res in curr_res:
                logger_debug('  del next_res contained:', next_res)
                del results[j]
                continue

            # overlap: keep the biggest result and skip the smallest overlapping results
            # in case of length tie: keep the left most
            if curr_res.overlap(next_res):
                if curr_res.priority < next_res.priority:
                    logger_debug('  del next_res lower priority:', next_res)
                    del results[j]
                    continue
                elif curr_res.priority > next_res.priority:
                    logger_debug('  del curr_res lower priority:', curr_res)
                    del results[i]
                    break
                else:
                    if len(curr_res) >= len(next_res):
                        logger_debug('  del next_res smaller overlap:', next_res)
                        del results[j]
                        continue
                    else:
                        logger_debug('  del curr_res smaller overlap:', curr_res)
                        del results[i]
                        break
            j += 1
        i += 1
    return results


def add_unmatched(string, results):
    """
    Yield Result object from the original `string` and the search `results` iterable
    of non-overlapping matched substring Result object. New unmatched Results are
    added to the stream for unmatched parts.

    For example:
    >>> string ='abcdefghijklmn'
    >>> results = [
    ...   Result(2, 3, 'cd'),
    ...   Result(7, 7, 'h', None),
    ...   Result(9, 10, 'jk', None),
    ... ]
    >>> expected = [
    ...   Result(0, 1, 'ab'),
    ...   Result(2, 3, 'cd'),
    ...   Result(4, 6, 'efg'),
    ...   Result(7, 7, 'h'),
    ...   Result(8, 8, 'i'),
    ...   Result(9, 10, 'jk'),
    ...   Result(11, 13, 'lmn')
    ... ]
    >>> expected == list(add_unmatched(string, results))
    True

    >>> string ='abc2'
    >>> results = [
    ...   Result(0, 2, 'abc'),
    ... ]
    >>> expected = [
    ...   Result(0, 2, 'abc'),
    ...   Result(3, 3, '2', None),
    ... ]
    >>> expected == list(add_unmatched(string, results))
    True

    """
    string_pos = 0
    for result in Result.sort(results):
        if result.start > string_pos:
            start = string_pos
            end = result.start - 1
            yield Result(start, end, string[start:end + 1])
        yield result
        string_pos = result.end + 1

    len_string = len(string)
    if string_pos < len_string:
        start = string_pos
        end = len_string - 1
        yield Result(start, end, string[start:end + 1])
