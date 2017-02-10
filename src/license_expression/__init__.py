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
from copy import copy
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
from boolean.boolean import PARSE_INVALID_SYMBOL_SEQUENCE
from boolean.boolean import PARSE_UNBALANCED_CLOSING_PARENS
from boolean.boolean import PARSE_UNKNOWN_TOKEN
from boolean.boolean import ParseError
from boolean.boolean import TOKEN_SYMBOL

from license_expression._pyahocorasick import Trie as Scanner


# append new error codes to PARSE_ERRORS by monkey patching
PARSE_EXPRESSION_NOT_UNICODE = 100
if PARSE_EXPRESSION_NOT_UNICODE not in PARSE_ERRORS:
    PARSE_ERRORS[PARSE_EXPRESSION_NOT_UNICODE] = 'Expression string must be unicode.'

PARSE_INVALID_EXCEPTION_SYMBOL_USAGE = 101
if PARSE_INVALID_EXCEPTION_SYMBOL_USAGE not in PARSE_ERRORS:
    PARSE_ERRORS[PARSE_INVALID_EXCEPTION_SYMBOL_USAGE] = (
        'A license exception symbol can only be used as an exception '
        'in a "WITH exception" statement.')

PARSE_INVALID_SYMBOL_USAGE_AS_EXCEPTION = 102
if PARSE_INVALID_SYMBOL_USAGE_AS_EXCEPTION not in PARSE_ERRORS:
    PARSE_ERRORS[PARSE_INVALID_SYMBOL_USAGE_AS_EXCEPTION] = (
        'A plain license symbol cannot be used as an exception '
        'in a "WITH symbol" statement.')


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
    >>> assert expected == l.license_symbols(expr)

    >>> symbols = ['GPL-2.0+', 'Classpath', 'BSD']
    >>> l = Licensing(symbols)
    >>> expr = l.parse("GPL-2.0+ with Classpath or (bsd)")
    >>> expected = 'gpl-2.0+ WITH classpath OR bsd'
    >>> assert expected == expr.render('{key}')

    >>> expected = [
    ...   LicenseSymbol('GPL-2.0+', known=True),
    ...   ExceptionSymbol('Classpath', known=True),
    ...   LicenseSymbol('BSD', known=True)
    ... ]
    >>> assert expected == l.license_symbols(expr)
    """
    def __init__(self, symbols=tuple(), strict=False, quiet=True):
        """
        Initialize a Licensing with an optional `symbols` sequence of LicenseSymbol
        or license key strings. If provided and this list data is invalid, raise a
        ValueError.

        If `strict` is True, expressions will be validated against this lits of
        symbols for correctness. In particular if you provided only a list of plain
        strings and not proper ExceptionSymbol for license exception then this will
        tigger an expcetion when an expression is parsed. Otherwise, the list is just
        used as a helper to recognize proper license keys in an expression.
        """
        super(Licensing, self).__init__(Symbol_class=LicenseSymbol, AND_class=AND, OR_class=OR)

        # FIXME: this should be instead a super class of all symbols
        self.LicenseSymbol = self.Symbol


        # True if we will strictly validate the symbol type (e.g. excption or not)
        # using the symbols list.
        self.strict = strict

        if symbols:
            symbols = as_symbols(symbols)
            warns, errors = validate_symbols(symbols)
            if warns and not quiet:
                for w in warns:
                    print(w)
            if errors and not quiet:
                for e in errors:
                    print(e)

            if errors:
                raise ValueError('\n'.join(warns + errors))

        # list of known symbol used for parsing and resolution:
        self.known_symbols = symbols

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

    def license_symbols(self, expression, unique=True, decompose=True):
        """
        Return a list of LicenseSymbol objects used in an expression in
        the same order as they first appear in the expression tree.

        `expression` is either a string or a LicenseExpression object.
        If a string is provided, it will be parsed.

        If `unique` is True only return unique symbols.

        If `decompose` is True then composite LicenseWithExceptionSymbol instance are
        not returned directly but their underlying license and expection symbols are
        retruned instead.

        For example:
        >>> l = Licensing()
        >>> expected = [
        ...   LicenseSymbol('GPL-2.0', known=False),
        ...   LicenseSymbol('LGPL-2.1+', known=False)
        ... ]
        >>> result = l.license_symbols('GPL-2.0 or LGPL-2.1+')
        >>> assert expected == result
        """
        expression = self.build(expression)
        if not isinstance(expression, LicenseExpression):
            return []

        symbols = (s for s in expression.get_literals() if isinstance(s, BaseSymbol))
        if decompose:
            symbols = itertools.chain.from_iterable(s.decompose() for s in symbols)
        if unique:
            symbols = ordered_unique(symbols)
        return list(symbols)

    def primary_license_symbol(self, expression, decompose=True):
        """
        Return the left-most license symbol of an expression or None.

        If `decompose` is True, only the left-hand license symbol of a decomposed
        LicenseWithExceptionSymbol symbol will be returned if this is the left most
        member. Otherwise a composite LicenseWithExceptionSymbol is returned in this
        case.
        """
        symbols = self.license_symbols(expression, decompose=decompose)
        if symbols:
            return symbols[0]

    def primary_license_key(self, expression):
        """
        Return the left-most license key of an expression or None. The underlying
        symbols are decomposed.
        """
        prim = self.primary_license_symbol(expression, decompose=True)
        if prim:
            return prim.key

    def license_keys(self, expression, unique=True):
        """
        Return a list of licenses keys used in an expression in the same order as
        they first appear in the expression.

        For example:
        >>> l = Licensing()
        >>> expr = ' GPL-2.0 and mit or later with blabla and mit or LGPL 2.1 and mit and mit or later with GPL-2.0'
        >>> expected = ['gpl-2.0', 'mit', 'later', 'blabla', 'lgpl 2.1']
        >>> assert expected == l.license_keys(expr)
        """
        symbols = self.license_symbols(expression, unique=False, decompose=True)
        return self._keys(symbols, unique)

    def _keys(self, symbols, unique=True):
        keys = [ls.key for ls in symbols]
        # note: we only apply this on bare keys strings as we can have the same
        # symbol used as symbol or exception if we are not in strict mode
        if unique:
            keys = ordered_unique(keys)
        return keys

    def unknown_license_symbols(self, expression, unique=True):
        """
        Return a list of unknown licenses symbols used in an expression in the same
        order as they first appear in the expression.
        """
        return [ls for ls in self.license_symbols(expression, unique=unique, decompose=True) if not ls.known]

    def unknown_license_keys(self, expression, unique=True):
        """
        Return a list of unknown licenses keys used in an expression in the same
        order as they first appear in the expression.

        `expression` is either a string or a LicenseExpression object.
        If a string is provided, it will be parsed.

        If `unique` is True only return unique keys.
        """
        symbols = self.unknown_license_symbols(expression, unique=False)
        return self._keys(symbols, unique)

    def parse(self, expression, simplify=False):
        """
        Return a new license LicenseExpression object by parsing a license expression
        string. Check that the expression syntax is valid and raise an Exception,
        ExpressionError or ParseError on errors.
        Return None for empty expressions.

        If `symbols` were provided at Licensing creation time, each license and
        exceptions is recognized from the known licensing symbols. Unknown symbols
        have the `known` flag set to False. Call the`unknown_license_keys` method to get
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
            if isinstance(expression, bytes):
                try:
                    expression = unicode(expression)
                except:
                    ext = type(expression)
                    raise ExpressionError('expression must be one of %(expr_types)r types and not: %(ext)r' % locals())
            else:
                ext = type(expression)
                raise ExpressionError('expression must be one of %(expr_types)r types and not: %(ext)r' % locals())

        if isinstance(expression, str):
            if not expression or not expression.strip():
                return
            try:
                # this will raise a ParseError on errors
                tokens = list(self.tokenize(expression))
                expression = super(Licensing, self).parse(tokens)
            except TypeError as e:
                raise
                return
                import traceback
                msg = 'Invalid expression syntax: ' + repr(e) + '\n' + traceback.format_exc()
                raise ExpressionError(msg)

        if not isinstance(expression, LicenseExpression):
            raise ExpressionError('expression must be a LicenseExpression once parsed.')

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
        strict = self.strict
        scanner = self.get_scanner()
        # scan with an automaton, recognize whole symbols+keywords or only keywords
        results = scanner.scan(expression)
        results = strip_and_skip_spaces(results)
        result_groups = group_results_for_with_subexpression(results)
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
                        # WITH is not known from the boolean parser as a proper
                        # boolean element so we handle validation ourselves: by
                        # design a single group cannot be a single 'WITH' keyword:
                        # this is an error that we catch and raise here.
                        if token == TOKEN_WITH:
                            raise ParseError(token_type=TOKEN_WITH,
                                             token_string=result.string,
                                             position=result.start,
                                             error_code=PARSE_INVALID_EXPRESSION)

                    elif isinstance(val, LicenseSymbol):
                        if strict and isinstance(val, ExceptionSymbol):
                            raise ParseError(token_type=TOKEN_SYMBOL,
                                             token_string=result.string,
                                             position=result.start,
                                             error_code=PARSE_INVALID_EXCEPTION_SYMBOL_USAGE)

                        # known symbol: create a new copy for sanity and always as a
                        # LicenseSymbol. The strict check above handled possible
                        # errors before.
                        token = LicenseSymbol.from_symbol(val)
                    else:
                        # this should not be possible by design
                        raise Exception('Licensing.tokenize is internally confused...')
                else:
                    # unknown symbol
                    token = LicenseSymbol(result.string, known=False)

            else:
                if len(group) != 3:
                    raise Exception(repr(group))

                assert len(group) == 3
                # this is a A with B seq of three results
                lic_res, _WITH , exc_res = group
                pos = lic_res.start
                token_string = ' '.join([t.string for t in group])

                # known or unknown symbol
                lic_out = lic_res.output
                lic_sym = lic_out and lic_out.value or LicenseSymbol(lic_res.string, known=False)

                if strict and not isinstance(lic_sym, LicenseSymbol):
                    raise ParseError(token_type=TOKEN_SYMBOL,
                                     token_string=lic_res.string,
                                     position=lic_res.start,
                                     error_code=PARSE_INVALID_EXCEPTION_SYMBOL_USAGE)

                lic_sym = LicenseSymbol.from_symbol(lic_sym)

                # known or unknown symbol
                exc_out = exc_res.output
                exc_sym = exc_out and exc_out.value or ExceptionSymbol(exc_res.string, known=False)

                if strict and not isinstance(lic_sym, ExceptionSymbol):
                    raise ParseError(token_type=TOKEN_SYMBOL,
                                     token_string=exc_res.string,
                                     position=exc_res.start,
                                     error_code=PARSE_INVALID_SYMBOL_USAGE_AS_EXCEPTION)

                exc_sym = ExceptionSymbol.from_symbol(exc_sym)

                token = LicenseWithExceptionSymbol(lic_sym, exc_sym)

            yield token, token_string, pos

    def get_scanner(self):
        """
        Return a scanner either cached or created as needed. If symbols were provided
        when this Licensing was created, the scanner will recognize known symbols
        when tokenizing expressions. Otherwise, only keywords are recognized and
        license symbols is anything in between keywords.
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
                # normalize spaces in aliases. The Scanner will lowercase since we
                # created with ignore_case=True
                if alias:
                    alias = ' '.join(alias.split())
                if alias:
                    scanner.add(alias, symbol)

        scanner.make_automaton()
        return scanner


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

    @classmethod
    def from_symbol(cls, symbol):
        """
        Return a new symbol from that provided symbol.
        """
        raise NotImplementedError

    def decompose(self):
        """
        Yield the underlying symbols of this symbol.
        """
        raise NotImplementedError


#FIXME: we need to implment comparison!!!!
@total_ordering
class LicenseSymbol(BaseSymbol):
    """
    A LicenseSymbol represents a license as used in a license expression.
    """
    def __init__(self, key, name=None, aliases=tuple(), known=True):
        if not key:
            raise ExpressionError(
                'LicenseSymbol key cannot be empty: %(key)r' % locals())

        if not isinstance(key, str):
            if isinstance(key, bytes):
                try:
                    key = unicode(key)
                except:
                    raise ExpressionError(
                        'LicenseSymbol key must be a unicode string: %(key)r' % locals())
            else:
                raise ExpressionError(
                    'LicenseSymbol key must be a unicode string: %(key)r' % locals())

        key = key.strip()

        if not key:
            raise ExpressionError(
                'LicenseSymbol key cannot be blank: %(original_key)r' % locals())

        self.original_key = original_key = key

        # normalize for spaces and make lowercase
        key = ' '.join(key.split())
        self.key = key.lower()

        self.original_name = original_name = name
        if name:
            if not isinstance(name, str):
                if isinstance(name, bytes):
                    try:
                        name = unicode(name)
                    except:
                        raise ExpressionError(
                            'LicenseSymbol name must be a unicode string when provided: '
                            '%(original_name)r' % locals())
                else:
                    raise ExpressionError(
                        'LicenseSymbol name must be a unicode string when provided: '
                        '%(original_name)r' % locals())
            names = name.strip()
            if not names:
                raise ExpressionError(
                    'LicenseSymbol name cannot be blank when provided: '
                    '%(original_name)r' % locals())
            # normalize for spaces
            self.name = ' '.join(names.split())
        else:
            self.name = self.original_key

        self.aliases = aliases and tuple(aliases) or tuple()
        self.known = known

        # super only know about a single "obj" object.
        super(LicenseSymbol, self).__init__(self.key)

    @classmethod
    def from_symbol(cls, symbol):
        assert isinstance(symbol, LicenseSymbol)
        new_symbol = cls(key=symbol.key, name=symbol.name,
                         aliases=symbol.aliases, known=symbol.known)
        new_symbol.original_key = symbol.original_key
        new_symbol.original_name = symbol.original_name
        return new_symbol

    def decompose(self):
        """
        Return an iterable the underlying symbols for this symbol
        """
        yield self

    def render(self, template='{key}'):
        return template.format(**self.__dict__)

    def __hash__(self, *args, **kwargs):
        return hash(self.key)

    def __eq__(self, other):
        return self is other or (isinstance(other, self.__class__) and self.key == other.key)

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


#FIXME: we need to implment comparison!!!!
@total_ordering
class ExceptionSymbol(LicenseSymbol):
    """
    An ExceptionSymbol represents a license exception as used in a license expression.
    """


#FIXME: we need to implment comparison!!!!
@total_ordering
class LicenseWithExceptionSymbol(BaseSymbol):
    """
    A LicenseWithExceptionSymbol represents a license "with" an exception as used in
    a license expression. It holds two LicenseSymbols objects: one for the left-hand
    license proper and one for the right-hand exception to this license and deals
    with the specifics of resolution, validation and representation.
    """
    def __init__(self, license_symbol, exception_symbol):
        if not isinstance(license_symbol, LicenseSymbol):
            raise ExpressionError(
                'license_symbol must be a LicenseSymbol: %(license_symbol)r' % locals())

        if not isinstance(exception_symbol, ExceptionSymbol):
            raise ExpressionError(
                'exception_symbol must be a ExceptionSymbol: %(exception_symbol)r' % locals())

        self.license_symbol = license_symbol
        self.exception_symbol = exception_symbol
        super(LicenseWithExceptionSymbol, self).__init__(str(self))

    @classmethod
    def from_symbol(cls, symbol):
        assert isinstance(symbol, LicenseWithExceptionSymbol)
        return cls(LicenseSymbol.from_symbol(symbol.license_symbol),
                   ExceptionSymbol.from_symbol(symbol.exception_symbol))

    def decompose(self):
        yield self.license_symbol
        yield self.exception_symbol

    def render(self, template='{key}'):
        lic = self.license_symbol.render(template)
        exc = self.exception_symbol.render(template)
        return '%(lic)s WITH %(exc)s' % locals()

    @property
    def known(self):
        return self.license_symbol.known and self.exception_symbol.known

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
    # derived from the __str__ code in boolean.py
    def render(self, template='{key}'):
        expression_args = self.args
        if len(expression_args) == 1:
            sym = expression_args[0]
            if isinstance(sym, Renderable):
                sym = sym.render(template)
            else:
                # FIXME: CAN THIS REALLY HAPPEN since we only have symbols, or and AND?
                sym = str(sym)
            if self.isliteral:
                rendered = '%s%s' % (self.operator, sym)
            else:
                # NB: the operator str already has a leading and trailing space
                rendered = '%s(%s)' % (self.operator, sym)
            return rendered

        rendered_items = []
        rendered_items_append = rendered_items.append
        for arg in expression_args:
            if isinstance(arg, Renderable):
                rendered = arg.render(template)
            else:
                # FIXME: CAN THIS REALLY HAPPEN since we only have symbols, or and AND?
                rendered = str(arg)

            if arg.isliteral:
                rendered_items_append(rendered)
            else:
                rendered_items_append('(%s)' % rendered)

        return self.operator.join(rendered_items)


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


def strip_and_skip_spaces(results):
    """
    Yield results given a sequence of Result skipping whitespace-only results
    """
    for result in results:
        if result.string.strip():
            yield result


def group_results_for_with_subexpression(results):
    """
    Yield tuples of (Result) given a sequence of Result such that all symbol-with-
    symbol subsequences of three results are grouped in a tuple and that other
    results are the single res in a tuple.
    """

    # if n-1 is sym, n is with and n+1 is sym: yield this as a group for a with exp
    # otherwise: yield each single result as a group

    results = list(results)

    # check three contiguous result from scanning at a time
    triple_len = 3

    # shortcut if there are no grouping possible
    if len(results) < triple_len:
        for res in results:
            yield (res,)
        return

    # accumulate three contiguous results
    triple = collections.deque()
    triple_popleft = triple.popleft
    triple_clear = triple.clear
    tripple_append = triple.append

    for res in results:
        if len(triple) == triple_len:
            if is_with_subexpression(triple):
                yield tuple(triple)
                triple_clear()
            else:
                prev_res = triple_popleft()
                yield (prev_res,)
        tripple_append(res)

    # end remainders
    if triple:
        if len(triple) == triple_len and is_with_subexpression(triple):
            yield tuple(triple)
        else:
            for res in triple:
                yield (res,)


def is_symbol(result):
    # either the output value is a known sym, por we have no output for unknown sym
    return (result.output and isinstance(result.output.value, LicenseSymbol)) or not result.output


def is_with_keyword(result):
    return (result.output
            and isinstance(result.output.value, Keyword)
            and result.output.value.type == TOKEN_WITH)


def is_with_subexpression(results):
    lic, wit, exc = results
    return (is_symbol(lic) and is_with_keyword(wit) and is_symbol(exc))


def as_symbols(symbols):
    """
    Return a tuple of LicenseSymbol from a sequence of `symbols` or strings. If an
    item is a string, then it will create a LicenseSymbol for it. If this is not a
    string it must be a LicenseSymbol type. It will raise a ValueError expection if
    an item is neither a string or LicenseSymbol.
    """
    if not symbols:
        return symbols
    new_symbols = []
    new_symbols_append = new_symbols.append
    for symbol in symbols:
        if not symbol:
            continue
        if isinstance(symbol, bytes):
            try:
                symbol = unicode(symbol)
            except:
                raise ValueError('%(symbol)r is not a unicode string or a LicenseSymbol instance.' % locals())

        if isinstance(symbol, unicode):
            if symbol.strip():
                new_symbols_append(LicenseSymbol(symbol))
        elif isinstance(symbol, LicenseSymbol):
            new_symbols_append(symbol)
        else:
            raise ValueError('%(symbol)r is not a unicode string or a LicenseSymbol instance.' % locals())
    return tuple(new_symbols)


_valid_key = re.compile('^[A-Za-z0-9\+\-\_\.\:]*$', re.IGNORECASE).match


def is_valid_key(k, _keywords=KEYWORDS):
    return _valid_key(k) and k.lower() not in _keywords


def validate_symbols(symbols, validate_keys=False, _keywords=KEYWORDS):
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
        if validate_keys and not is_valid_key(key):
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
