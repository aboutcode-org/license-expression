#
# license-expression is a free software tool from nexB Inc. and others.
# Visit https://github.com/nexB/license-expression for support and download.
#
# Copyright (c) 2017 nexB Inc. and others. All rights reserved.
# http://nexb.com and http://aboutcode.org
#
# This software is licensed under the Apache License version 2.0.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.


"""
This module defines a mini language to parse, validate, simplify, normalize and
compare license expressions using a boolean logic engine.

This supports SPDX license expressions and also accepts other license naming
conventions and license identifiers aliases to recognize and normalize licenses.

Using boolean logic, license expressions can be tested for equality, containment,
equivalence and can be normalized or simplified.

The main entry point is the Licensing object.
"""


from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function

# Python 2 and 3 support
try:
    # Python 2
    unicode
    str = unicode
except NameError:
    # Python 3
    unicode = str

import collections
from functools import total_ordering
import itertools
import re
import string

import boolean
from boolean import Expression as LicenseExpression

# note these may not all be used here but are imported here to avoid leaking
# boolean.py constants to callers
from boolean.boolean import PARSE_ERRORS
from boolean.boolean import PARSE_INVALID_EXPRESSION
from boolean.boolean import PARSE_INVALID_NESTING
from boolean.boolean import PARSE_UNBALANCED_CLOSING_PARENS
from boolean.boolean import PARSE_UNKNOWN_TOKEN
from boolean.boolean import ParseError

from license_expression._pyahocorasick import Trie as Scanner


# append new error code to PARSE_ERRORS
PARSE_EXPRESSION_NOT_UNICODE = max(PARSE_ERRORS) + 1
PARSE_ERRORS[PARSE_EXPRESSION_NOT_UNICODE] = 'Expression string must be unicode.'


class ExpressionError(Exception):
    pass


# Used for tokenizing
Keyword = collections.namedtuple('Keyword', 'value type')

# id for "with" token which is not a proper boolean symbol but an expression symbol
TOKEN_WITH = 10

# actual keyword types
_KEYWORDS = [
    Keyword('and', boolean.TOKEN_AND),
    Keyword('or', boolean.TOKEN_OR),
    Keyword('(', boolean.TOKEN_LPAR),
    Keyword(')', boolean.TOKEN_RPAR),
    Keyword('with', TOKEN_WITH),
]

KEYWORDS = tuple(kw.value for kw in _KEYWORDS)

_valid_key = re.compile('^[A-Za-z0-9\+\-\_\.\:]*$', re.IGNORECASE).match

def is_valid_key(k, _keywords=KEYWORDS):
    return _valid_key(k) and k.lower() not in _keywords


def validate_symbols(symbols, _keywords=KEYWORDS):
    """
    Return a tuple of (`warnings`, `errors`) given a list of `symbols` LicenseSymbol
    objects. LicenseSymbol are updated in place ass needed with side-effects.

    - warnings is a list of validation warnings messages (possibly empty if there
      were no warnings).
    - errors is a list of validation error messages (possibly empty if there were no
      errors).

    Keys, names and aliases are cleaned and validated for uniqueness.
    """

    # collection used for checking unicity and correctness
    seen_keys = set()
    seen_names = set()
    seen_aliases = {}
    seen_exceptions = set()

    # collections to accumulate invalid data and build error messages at the end
    not_symbol_classes = []
    invalid_keys = set()
    dupe_keys = set()
    dupe_names = set()
    dupe_exceptions = set()
    dupe_aliases = collections.defaultdict(list)
    invalid_names_as_kw = set()
    invalid_keys_as_kw = set()
    invalid_alias_as_kw = set()
    symbol_not_known = set()

    # warning
    warning_dupe_aliases = set()

    for symbol in symbols:
        if not isinstance(symbol, LicenseSymbol):
            not_symbol_classes.append(symbol)
            continue

        key = symbol.key
        if not is_valid_key(key):
            invalid_keys.add(key)

        key = key.strip()
        keyl = key.lower()

        # ensure keys are unique
        if keyl in seen_keys:
            dupe_keys.add(key)

        # key cannot be an expression keyword
        if keyl in _keywords:
            invalid_keys_as_kw.add(key)

        name = symbol.name
        if not name or not name.strip():
            # use the key (not lowercased) as a default if there is no name
            name = key

        # normalize spaces
        name = ' '.join(name.split())
        namel = name.lower()
        # ensure names are unique
        if namel in seen_names:
            dupe_names.add(name)
        seen_names.add(namel)

        # name cannot be an expression keyword
        if namel in _keywords:
            invalid_names_as_kw.add(name)

        # keep a set of unique seen keys
        seen_keys.add(keyl)

        aliases = symbol.aliases or []
        initial_alias_len = len(aliases)

        # always normalize aliases for spaces and case. keep uniques only
        aliases = set([' '.join(alias.lower().strip().split()) for alias in symbol.aliases])
        # remove empties
        aliases = set(a for a in aliases if a)

        # issue a warning when there are duplicated or empty aliases
        if len(aliases) != initial_alias_len:
            warning_dupe_aliases.add(key)

        # always use a lowercase key as an alias
        aliases.add(keyl)

        # make hashable
        aliases = tuple(sorted(aliases))

        for alias in aliases:
            # note that we do not treat as an error the presence of a duplicated
            # alias pointing to the same key

            # ensure that a possibly duplicated alias does not point to another key
            aliased_key = seen_aliases.get(alias)
            if aliased_key and aliased_key != keyl:
                dupe_aliases[alias].append(key)

            # an alias cannot be an expression keyword
            if alias in _keywords:
                invalid_alias_as_kw.add(alias)

            seen_aliases[alias] = keyl

        if isinstance(symbol, ExceptionSymbol):
            if keyl in seen_exceptions:
                dupe_exceptions.add(keyl)
            else:
                seen_exceptions.add(keyl)

        # make sure to mark the symbol as known
        if not symbol.known:
            symbol_not_known.add(keyl)

    # build warning and error messages from invalid data
    errors = []
    for ind in sorted(not_symbol_classes):
        errors.append('Invalid license reference object missing a key, name, '
                      'aliases or exception attribute: %(ind)s.' % locals())

    for invak in sorted(invalid_keys):
        errors.append('Invalid license key. Can only contain ASCII letters '
                      'and digits and ".+_-": %(invak)s.' % locals())

    for dupe in sorted(dupe_keys):
        errors.append('Invalid duplicated license key: %(dupe)s.' % locals())

    for nm in sorted(dupe_names):
        errors.append('Invalid duplicated license name: %(nm)s.' % locals())

    for dalias, dkeys in sorted(dupe_aliases.items()):
        dkeys = ', '.join(dkeys)
        errors.append('Invalid duplicated alias pointing to different seen_keys: '
                      '%(dalias)s to keys: %(dkeys)s.' % locals())

    for dupe in sorted(dupe_exceptions):
        errors.append('Invalid duplicated license exception key: %(dupe)s.' % locals())

    for ikw in sorted(invalid_keys_as_kw):
        errors.append('Invalid key: cannot be an expression keyword: %(ikw)s.' % locals())

    for ikw in sorted(invalid_names_as_kw):
        errors.append('Invalid name: cannot be an expression keyword: %(ikw)r.' % locals())

    for ikw in sorted(invalid_alias_as_kw):
        errors.append('Invalid alias: cannot be an expression keyword: %(ikw)r.' % locals())

    for us in sorted(symbol_not_known):
        errors.append('Invalid symbol: is not marked as a known symbol: %(us)r.' % locals())

    warnings = []
    for dupeal in sorted(dupe_aliases):
        errors.append('Duplicated or empty aliases ignored for license key: %(dupeal)r.' % locals())

    return warnings, errors


class Renderable(object):
    """
    An interface for renderable objects.
    """
    def render(self, template='{key}'):
        """
        Return a formatted string rendering for this expression using the `template`
        format string to render each symbol. The variables available are `key` and
        `name` and a custom template can be provided to handle custom HTML rendering
        or similar.

        For symbols that hold multiple licenses (e.g. a WITH statement) the template
        is applied to each symbol individually.
        """
        return NotImplementedError


class BaseSymbol(Renderable, boolean.Symbol):
    """
    A base class for all symbols.
    """


@total_ordering
class LicenseSymbol(BaseSymbol):
    """
    A LicenseSymbol represents a license as used in a license expression.
    """
    def __init__(self, key, name=None, aliases=tuple(), known=True):

        if not key:
            raise ExpressionError('LicenseSymbol key cannot be empty: %(key)r' % locals())

        if not isinstance(key, str):
            raise ExpressionError('LicenseSymbol key must be a unicode string: %(key)r' % locals())

        key = key.strip()
        self.original_key = original_key = key

        if not key:
            raise ExpressionError('LicenseSymbol key cannot be blank: %(original_key)r' % locals())

        # normalize for spaces and make lowercase
        key = ' '.join(key.split())
        self.key = key.lower()

        self.original_name = original_name = name
        if name:
            if not isinstance(name, str):
                raise ExpressionError('LicenseSymbol name must be a unicode string '
                                      'when provided: %(name)r' % locals())
            names = name.strip()
            if not names:
                raise ExpressionError('LicenseSymbol name cannot be blank '
                                      'when provided: %(original_name)r' % locals())
            # normalize for spaces
            self.name = ' '.join(names.split())
        else:
            self.name = self.original_key

        self.aliases = aliases and tuple(aliases) or tuple()
        self.known = known

        # super only know about a single "obj" object.
        super(LicenseSymbol, self).__init__(self.key)

    def get_literals(self):
        return [self]

    def get_symbols(self):
        return [self]

    def render(self, template='{key}'):
        return template.format(**self.__dict__)

    def __hash__(self, *args, **kwargs):
        return hash(self.key)

    def __eq__(self, other):
        return self is other  or (isinstance(other, self.__class__) and self.key == other.key)

    __nonzero__ = __bool__ = lambda s: True

    def __str__(self):
        return self.key

    def __repr__(self):
        cls = self.__class__.__name__
        key = self.key
        name = self.original_name and ('name=%r, ' % self.name) or ''
        aliases = self.aliases and ('aliases=%(a)r, ' % {'a': self.aliases}) or ''
        known = self.known
        return '%(cls)s(key=%(key)r, %(name)s%(aliases)sknown=%(known)r)' % locals()


@total_ordering
class ExceptionSymbol(LicenseSymbol):
    """
    An ExceptionSymbol represents a license exception as used in a license expression.
    """


@total_ordering
class LicenseWithExceptionSymbol(BaseSymbol):
    """
    A LicenseWithExceptionSymbol represents a license "with" an exception as used in
    a license expression. It holds two LicenseSymbols objects: one of the license
    proper and one for the exception and deals with the specifics of resolution,
    validation and representation.
    """
    def __init__(self, license_symbol, exception_symbol):
        if not isinstance(license_symbol, LicenseSymbol):
            raise ExpressionError('LicenseWithExceptionSymbol license_symbol '
                                  'must be a LicenseSymbol: %(license_symbol)r' % locals())

        if not isinstance(exception_symbol, ExceptionSymbol):
            raise ExpressionError('LicenseWithExceptionSymbol exception_symbol '
                                  'must be a ExceptionSymbol: %(exception_symbol)r' % locals())

        self.license_symbol = license_symbol
        self.exception_symbol = exception_symbol
        super(LicenseWithExceptionSymbol, self).__init__(str(self))

    def get_literals(self):
        return [self.license_symbol, self.exception_symbol]

    def get_symbols(self):
        return [self]

    def render(self, template='{key}'):
        lic = self.license_symbol.render(template)
        exc = self.exception_symbol.render(template)
        return '%(lic)s WITH %(exc)s' % locals()

    @property
    def known(self):
        return self.license_symbol.known and  self.exception_symbol.known

    def __hash__(self, *args, **kwargs):
        return hash((self.license_symbol, self.exception_symbol,))

    def __eq__(self, other):
        return self is other  or (
                isinstance(other, self.__class__) 
            and self.license_symbol == other.license_symbol
            and self.exception_symbol == other.exception_symbol)

    __nonzero__ = __bool__ = lambda s: True

    def __str__(self):
        lkey = self.license_symbol.key
        ekey = self.exception_symbol.key
        return '%(lkey)s WITH %(ekey)s' % locals()

    def __repr__(self):

        data = dict(cls=self.__class__.__name__)
        data.update(self.__dict__)
        return '%(cls)s(license_symbol=%(license_symbol)r, exception_symbol=%(exception_symbol)r)' % data


class RenderableFunction(Renderable):

    def render(self, template='{key}'):
        args = self.args
        if len(args) == 1:
            sym = args[0]
            if isinstance(sym, Renderable):
                sym = sym.render(template)
            else:
                # FIXME: CAN THIS REALLY HAPPEN?
                sym = str(sym)
            if self.isliteral:
                rendered = '%s%s' % (self.operator, sym)
            else:
                # NB: the operators str already has a leading and trailing space
                rendered = '%s(%s)' % (self.operator, sym)
            return rendered

        args_str = []
        for arg in args:
            if isinstance(arg, Renderable):
                rendered = arg.render(template)
            else:
                # FIXME: CAN THIS REALLY HAPPEN?
                rendered = str(arg)

            if arg.isliteral:
                args_str.append(rendered)
            else:
                args_str.append('(%s)' % rendered)

        return self.operator.join(args_str)


class AND(RenderableFunction, boolean.AND):
    """
    Custom representation for the AND operator to uppercase.
    """
    def __init__(self, *args):
        super(AND, self).__init__(*args)
        self.operator = ' AND '


class OR(RenderableFunction, boolean.OR):
    """
    Custom representation for the OR operator to uppercase.
    """
    def __init__(self, *args):
        super(OR, self).__init__(*args)
        self.operator = ' OR '


class Licensing(boolean.BooleanAlgebra):
    """
    Define a mini language to parse, validate and compare license expressions.

    For example:

    >>> l = Licensing()
    >>> expr = l.parse(" GPL-2.0 or LGPL 2.1 and mit ")
    >>> expected = 'GPL-2.0 OR (LGPL 2.1 AND mit)'
    >>> assert expected == expr.render('{name}')

    >>> expected = [
    ...   LicenseSymbol('GPL-2.0', known=False),
    ...   LicenseSymbol('LGPL 2.1', known=False),
    ...   LicenseSymbol('mit', known=False)
    ... ]
    >>> assert expected == l.get_license_symbols(expr)
    """
    def __init__(self, symbols=tuple(), quiet=True):
        """
        Initialize a Licensing with an optional `license_refs` list of
        LicenseRef-like objects (with the same attributes as a LicenseRef namedtuple)s.
        If provided and the list is invalid, raise a ValueError.
        """
        super(Licensing, self).__init__(Symbol_class=LicenseSymbol, AND_class=AND, OR_class=OR)

        # FIXME: this should be instead a super class of all symbols
        self.LicenseSymbol = self.Symbol

        # list of known symbol used for parsing and resolution:
        self.known_symbols = symbols

        if symbols:
            warns, errors = validate_symbols(symbols)
            if warns and not quiet:
                for w in warns:
                    print(w)
            if errors and not quiet:
                for e in errors:
                    print(e)

            if errors:
                raise ValueError('\n'.join(warns + errors))

        # Aho-Corasick automaton-based Scanner used for expression tokenizing
        self.scanner = None

    def build(self, expression, simplify=False):
        """
        Returns an expression from an expression or a string.
        Optionally simplifies the expression if simplify is True.
        Possibly return the expression as-is if this is not a string or an expression.
        """
        expression = self.parse(expression)
        if expression is not None and simplify:
            expression = expression.simplify()
        return expression

    def is_equivalent(self, expression1, expression2):
        """
        Return True if both `expressions` LicenseExpression are equivalent.
        Expressions are either a string or a LicenseExpression object.
        If a string is provided, it will be parsed and simplified.
        """
        ex1 = self.build(expression1, simplify=True)
        ex2 = self.build(expression2, simplify=True)
        if isinstance(ex1, LicenseExpression) and isinstance(ex2, LicenseExpression):
            return ex1 == ex2

    def contains(self, expression1, expression2):
        """
        Return True if expression1 contains expression2.
        Expressions are either a string or a LicenseExpression object.
        If a string is provided, it will be parsed and simplified.
        """
        ex1 = self.build(expression1, simplify=True)
        ex2 = self.build(expression2, simplify=True)
        if isinstance(ex1, LicenseExpression) and isinstance(ex2, LicenseExpression):
            return ex2 in ex1

    def get_license_symbols(self, expression, unique=True):
        """
        Return a list of LicenseSymbol objects used in an expression in
        the same order as they first appear in the expression tree.

        `expression` is either a string or a LicenseExpression object.
        If a string is provided, it will be parsed.

        If `unique` is True only return unique symbols.

        For example:
        >>> l = Licensing()
        >>> expected = [
        ...   LicenseSymbol('GPL-2.0', known=False),
        ...   LicenseSymbol('LGPL-2.1+', known=False)
        ... ]
        >>> result = l.get_license_symbols('GPL-2.0 or LGPL-2.1+')
        >>> assert expected == result
        """
        expression = self.build(expression)
        if not isinstance(expression, LicenseExpression):
            return []
        symbols = expression.get_literals()
        if unique:
            symbols = ordered_unique(symbols)
        return symbols

    def primary_license(self, expression):
        """
        Return the left-most license key (or a "key with exception") of an expression
        or None. `expression` is either a string or a LicenseExpression object. If a
        string is provided, it will be parsed but not simplified.
        """
        # FIXME: we should return the left most full SYMBOL including WITH expression
        # NOT the left most bare symbol!!!!
        raise NotImplementedError
        symbols = self.get_license_symbols(expression)
        if symbols:
            return str(symbols[0])

    def license_keys(self, expression):
        """
        Return a list of unique licenses keys used in an expression in the same
        order as they first appear in the expression.

        `expression` is either a string or a LicenseExpression object.
        If a string is provided, it will be parsed.

        For example:
        >>> l = Licensing()
        >>> expr = " GPL-2.0 and mit or later with blabla and mit or LGPL 2.1 and mit and mit or later with GPL-2.0"
        >>> expected = ['gpl-2.0', 'mit', 'later', 'blabla', 'lgpl 2.1']
        >>> assert expected == l.license_keys(expr)
        """
        return ordered_unique([ls.key for ls in self.get_license_symbols(expression)])

    def unknown_keys(self, expression):
        """
        Return a list of unknown license or exception keys for an `expression`.
        """
        return [ls.key for ls in self.get_license_symbols(expression) if not ls.known]

    def parse(self, expression, simplify=False):
        """
        Return a new license LicenseExpression object by parsing a license expression
        string. Check that the expression syntax is valid and raise an Exception,
        ExpressionError or ParseError on errors.
        Return None for empty expressions.

        If `symbols` were provided at Licensing creation time, each license and
        exceptions is recognized from the known licensing symbols. Unknown symbols
        have the `known` flag set to False. Call the`unknown_keys` method to get
        unknown license keys.

        If `simplify` is True the returned expression is simplified in a form
        suitable for comparison.

        For example:
        >>> expression = 'EPL 1.0 and Apache 1.1 OR GPL 2.0 with Classpath expection'
        >>> parsed = Licensing().parse(expression)
        >>> expected = '(EPL 1.0 AND Apache 1.1) OR GPL 2.0 WITH Classpath expection'
        >>> assert expected == parsed.render(template='{name}')
        """
        if expression is None:
            return

        expr_types = str, LicenseExpression
        if not isinstance(expression, expr_types):
            raise ExpressionError('expression must be one of ''%(expr_types)r types and not: ' % locals() + repr(type(expression)))

        if isinstance(expression, str):
            if not expression or not expression.strip():
                return
            try:
                # this will raise a ParseError on errors
                tokens = list(self.tokenize(expression))
                expression = super(Licensing, self).parse(tokens)
            except TypeError as e:
                raise
                # raise ExpressionError('Invalid expression syntax: ' + repr(e))

        if not isinstance(expression, LicenseExpression):
            raise ExpressionError('expression must be a string or an Expression.')

        if simplify:
            expression = expression.simplify()

        return expression

    def tokenize(self, expression):
        """
        Return an iterable of 3-tuple describing each token given an expression
        unicode string. see boolean.BooleanAlgreba.tokenize() for details.

        This 3-tuple contains (token, token string, position):
        - token: either a Symbol instance or one of TOKEN_* token types..
        - token string: the original token unicode string.
        - position: some simple object describing the starting position of the
          original token string in the `expr` string. It can be an int for a
          character offset, or a tuple of starting (row/line, column).
        """
        scanner = self.get_scanner()

        # scan with an automaton, recognize whole symbols+keywords or only keywords
        results = scanner.scan(expression)
        results = strip_and_skip_spaces(results)
        result_groups = group_symbols(results)
        for group in result_groups:
            if len(group) == 1:
                # a single token
                result = group[0]
                pos = result.start
                token_string = result.string
                output = result.output
                if output:
                    val = output.value
                    if isinstance(val, Keyword):
                        # keyword
                        token = val.type
                        if token == TOKEN_WITH:
                            raise ParseError(token_type=TOKEN_WITH,
                                             token_string=result.string,
                                             position=result.start,
                                             error_code=PARSE_INVALID_EXPRESSION)
                    elif isinstance(val, BaseSymbol):
                        # known symbol
                        token = val
                    else:
                        # this should not be possible by design
                        raise Exception('Licensing.tokenize is internally confused...')
                else:
                    # unknown symbol
                    token = LicenseSymbol(result.string, known=False)

            else:
                assert len(group) == 3
                # this is a A with B seq of three results
                licres, _ , excres = group
                pos = licres.start
                token_string = ' '.join([t.string for t in group])

                # known or unknown symbol
                loutput = licres.output
                license_symbol = loutput and loutput.value or LicenseSymbol(licres.string, known=False)
                # known or unknown symbol
                eoutput = excres.output
                exception_symbol = eoutput and eoutput.value or ExceptionSymbol(excres.string, known=False)
                token = LicenseWithExceptionSymbol(license_symbol, exception_symbol)

            yield token, token_string, pos

    def get_scanner(self):
        """
        Return a scanner either cached and created as needed. If symbols were
        provided, the scanner will recognize known symbols when tokenizing
        expressions. Otherwise, only keywords are recognized and license symbols is
        anything in between keywords.
        """
        if self.scanner is not None:
            return self.scanner

        self.scanner = scanner = Scanner(ignore_case=True)
        for keyword in _KEYWORDS:
            scanner.add(keyword.value, keyword)

        # only build a basic keyword-only scanner if we have known_symbols
        if not self.known_symbols:
            scanner.make_automaton()
            return scanner

        # self.known_symbols has been created at Licensing initialization time and is
        # already validated and trusted here
        for symbol in self.known_symbols:
            # always use the key even if there are no aliases.
            scanner.add(symbol.key, symbol)
            for alias in symbol.aliases:
                # normalize spaces in aliases
                if alias:
                    alias = ' '.join(alias.split())
                if alias:
                    scanner.add(alias, symbol)

        scanner.make_automaton()
        return scanner


def ordered_unique(seq):
    """
    Return unique items in a sequence seq preserving the original order.
    """
    if not seq:
        return []
    uniques = []
    for item in seq:
        if item in uniques:
            continue
        uniques.append(item)
    return uniques


def ngrams(sequence, ngram_len):
    """
    Given a sequence or iterable, return an iterator of all the subsequences of
    `ngram_len` items as tuples. Buffers at most `ngram_len` iterable items. The
    returned tuples contains `ngram_len` items or less when the len of the original
    sequence is smaller than `ngram_len`.

    For example:
    >>> list(ngrams([1,2,3,4,5], 2))
    [(1, 2), (2, 3), (3, 4), (4, 5)]
    >>> list(ngrams([1,2,3,4], 2))
    [(1, 2), (2, 3), (3, 4)]
    >>> list(ngrams([1,2,3], 2))
    [(1, 2), (2, 3)]
    >>> list(ngrams([1,2], 2))
    [(1, 2)]
    >>> list(ngrams([1], 2))
    [(1,)]
    """
    ngram = collections.deque()
    ngram_popleft = ngram.popleft
    ngram_append = ngram.append
    for item in sequence:
        if len(ngram) == ngram_len:
            yield tuple(ngram)
            ngram_popleft()
        ngram_append(item)

    if ngram:
        yield tuple(ngram)


def is_symbol(result):
    return result.output and isinstance(result.output.value, BaseSymbol) or not result.output


def is_keyword(result):
    return result.output and isinstance(result.output.value, Keyword)


def is_with_keyword(result):
    return is_keyword(result) and result.output.value.type == TOKEN_WITH


def strip_and_skip_spaces(results):
    """
    Yield results given a sequence of Result skipping whitespace-only results
    """
    for result in results:
        if result.string.strip():
            yield result


def group_symbols(results):
    """
    Yield tuples of (Result) given a sequence of Result such that a symbol-with-
    symbol subsequence is grouped in a tuple and that other results are the single
    member of a tuple.
    """
    # if n-1, n, n+1 is sym, with, sym: yield this as a group
    # if n-1, n, n+1 is n=with and not n-1 and n+1 are sym: raise an Error
    # otherwise: yield single result as a group

    results = list(results)
    ngram_len = 3
    if len(results) < ngram_len:
        for tk in results:
            yield (tk,)
        return

    # check for "A with B" in any subsequence of three results and group these
    result_ngrams = list(ngrams(results, ngram_len))
    result_ngrams_len = len(result_ngrams)

    skip_ngrams = 0
    for i, (res1, res2, res3) in enumerate(result_ngrams, 1):
        # skip possible ngrams corresponding to results grouped previously
        if skip_ngrams:
            skip_ngrams -= 1
            continue

        is_with_subexpression = all((is_symbol(res1), is_with_keyword(res2), is_symbol(res3)))
        if is_with_subexpression:
            # The res1, res2 and res3 form a construct such as "GPL 2.0 with CLASSPATH".
            # Therefore we re-join the three results and yield this as a single group
            yield (res1, res2, res3)
            # and skip the next two ngram's since we consumed them alright in our joined result
            skip_ngrams = ngram_len - 1
        else:
            # Here we have regular result: we just reyield the first result.
            # And if this the last ngram we also yield the second and third results
            yield (res1,)
            if i == result_ngrams_len:
                yield (res2,)
                yield (res3,)
                break
