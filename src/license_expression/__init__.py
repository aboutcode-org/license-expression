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
from copy import deepcopy
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

PARSE_INVALID_EXCEPTION = 101
if PARSE_INVALID_EXCEPTION not in PARSE_ERRORS:
    PARSE_ERRORS[PARSE_INVALID_EXCEPTION] = (
        'A license exception symbol can only be used as an exception '
        'in a "WITH exception" statement.')

PARSE_INVALID_SYMBOL_AS_EXCEPTION = 102
if PARSE_INVALID_SYMBOL_AS_EXCEPTION not in PARSE_ERRORS:
    PARSE_ERRORS[PARSE_INVALID_SYMBOL_AS_EXCEPTION] = (
        'A plain license symbol cannot be used as an exception '
        'in a "WITH symbol" statement.')

PARSE_INVALID_SYMBOL = 103
if PARSE_INVALID_SYMBOL not in PARSE_ERRORS:
    PARSE_ERRORS[PARSE_INVALID_SYMBOL] = (
        'A proper license symbol is needed.')


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
    >>> assert expected == expr.render('{original_key}')

    >>> expected = [
    ...   LicenseSymbol('GPL-2.0'),
    ...   LicenseSymbol('LGPL 2.1'),
    ...   LicenseSymbol('mit')
    ... ]
    >>> assert expected == l.license_symbols(expr)

    >>> symbols = ['GPL-2.0+', 'Classpath', 'BSD']
    >>> l = Licensing(symbols)
    >>> expr = l.parse("GPL-2.0+ with Classpath or (bsd)")
    >>> expected = 'gpl-2.0+ WITH classpath OR bsd'
    >>> assert expected == expr.render('{key}')

    >>> expected = [
    ...   LicenseSymbol('GPL-2.0+'),
    ...   LicenseSymbol('Classpath', is_exception=True),
    ...   LicenseSymbol('BSD')
    ... ]
    >>> assert expected == l.license_symbols(expr)
    """
    def __init__(self, symbols=tuple(), quiet=True):
        """
        Initialize a Licensing with an optional `symbols` sequence of LicenseSymbol
        or license key strings. If provided and this list data is invalid, raise a
        ValueError.

        If `strict` is True, expressions will be validated against this list of
        symbols for correctness. In particular if you provided only a list of plain
        strings and not symbols with `is_exception` set to True for license
        exceptions then this will raise an Exception when an with such symbols
        expression is parsed. Otherwise, the list is just used as a helper to
        recognize proper license keys in an expression.
        """
        super(Licensing, self).__init__(Symbol_class=LicenseSymbol, AND_class=AND, OR_class=OR)

        # FIXME: this should be instead a super class of all symbols
        self.LicenseSymbol = self.Symbol

        if symbols:
            symbols = tuple(as_symbols(symbols))
            warns, errors = validate_symbols(symbols)
            if warns and not quiet:
                for w in warns:
                    print(w)
            if errors and not quiet:
                for e in errors:
                    print(e)

            if errors:
                raise ValueError('\n'.join(warns + errors))

        # mapping of known symbol used for parsing and resolution as (key, symbol)
        self.known_symbols = {symbol.key: symbol for symbol in symbols}

        # Aho-Corasick automaton-based Scanners used for expression tokenizing: This
        # is a resolving scanner that recognizes symbols and is available when
        # parsing with `resolve=True` IF and only if symbols were provided. If not,
        # the basic scanner is used instead.
        self.resolving_scanner = None

        # This is a non-resolving scanner used when parsing with `resolve=False` or
        # all the times if symbols were NOT provided
        self.basic_scanner = None

    def is_equivalent(self, expression1, expression2):
        """
        Return True if both `expressions` LicenseExpression are equivalent.
        """
        if not (isinstance(expression1, LicenseExpression)
            and isinstance(expression2, LicenseExpression)):
            raise TypeError('expressions must be LicenseExpression objects: %(expression1)r, %(expression2)r' % locals())
        ex1 = expression1.simplify()
        ex2 = expression2.simplify()
        return ex1 == ex2

    def contains(self, expression1, expression2):
        """
        Return True if expression1 contains expression2.
        Expressions are either a string or a LicenseExpression object.
        If a string is provided, it will be parsed and simplified.
        """
        if not (isinstance(expression1, LicenseExpression)
            and isinstance(expression2, LicenseExpression)):
            raise TypeError('expressions must be LicenseExpression objects: %(expression1)r, %(expression2)r' % locals())
        ex1 = expression1.simplify()
        ex2 = expression2.simplify()
        return ex2 in ex1

    def license_symbols(self, expression, unique=True, decompose=True):
        """
        Return a list of LicenseSymbol objects used in an expression in
        the same order as they first appear in the expression tree.

        `expression` is either a string or a LicenseExpression object.
        If a string is provided, it will be parsed.

        If `unique` is True only return unique symbols.

        If `decompose` is True then composite LicenseWithExceptionSymbol instance are
        not returned directly but their underlying license and exception symbols are
        retruned instead.

        For example:
        >>> l = Licensing()
        >>> expected = [
        ...   LicenseSymbol('GPL-2.0'),
        ...   LicenseSymbol('LGPL-2.1+')
        ... ]
        >>> result = l.license_symbols(l.parse('GPL-2.0 or LGPL-2.1+'))
        >>> assert expected == result
        """
        if not isinstance(expression, LicenseExpression):
            raise TypeError('expression must be LicenseExpression object and not: %(expression)r' % locals())

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
        >>> assert expected == l.license_keys(l.parse(expr))
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
        return [ls for ls in self.license_symbols(expression, unique=unique, decompose=True)
                if not ls.key in self.known_symbols]

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

    def parse(self, expression, resolve=True, strict=False):
        """
        Return a new license LicenseExpression object by parsing a license expression
        string. Check that the expression syntax is valid and raise an Exception,
        ExpressionError or ParseError on errors. Return None for empty expressions.

        If `resolve` is True and `symbols` were provided at Licensing creation time,
        each license and exception is recognized from these known licensing symbols.
        If `resolve` is False or `symbols` were not provided at Licensing creation
        time, then symbols are not resolved to known symbols and anything between two
        keywords is considered as a symbol.

        Call the `unknown_license_keys` or `unknown_license_symbols` methods to get
        unknown license keys or symbols found in a parsed LicenseExpression.

        If `strict` is True, additional exceptions will be raised:
         - if a symbol is not resolved.
         - in a expression such as "XXX with ZZZ" if the XXX symbol has
           `is_expection` set to True or the YYY symbol has `is_expection` set to
           False.

        For example:
        >>> expression = 'EPL 1.0 and Apache 1.1 OR GPL 2.0 with Classpath exception'
        >>> parsed = Licensing().parse(expression)
        >>> expected = '(EPL 1.0 AND Apache 1.1) OR GPL 2.0 WITH Classpath exception'
        >>> assert expected == parsed.render(template='{original_key}')
        """
        if expression is None:
            return

        if isinstance(expression, LicenseExpression):
            return expression

        if isinstance(expression, bytes):
            try:
                expression = unicode(expression)
            except:
                ext = type(expression)
                raise ExpressionError('expression must be a string and not: %(ext)r' % locals())

        if not isinstance(expression, str):
            ext = type(expression)
            raise ExpressionError('expression must be a string and not: %(ext)r' % locals())

        if not expression or not expression.strip():
            return
        try:
            # this will raise a ParseError on errors
            tokens = list(self.tokenize(expression, resolve, strict))
            expression = super(Licensing, self).parse(tokens)
        except TypeError as e:
            import traceback
            msg = 'Invalid expression syntax: ' + repr(e) + '\n' + traceback.format_exc()
            raise ExpressionError(msg)

        if not isinstance(expression, LicenseExpression):
            raise ExpressionError('expression must be a LicenseExpression once parsed.')

        return expression

    def tokenize(self, expression, resolve=True, strict=False):
        """
        Return an iterable of 3-tuple describing each token given an expression
        unicode string. See boolean.BooleanAlgreba.tokenize() for API details.

        This 3-tuple contains these items: (token, token string, position):
        - token: either a Symbol instance or one of TOKEN_* token types..
        - token string: the original token unicode string.
        - position: some simple object describing the starting position of the
          original token string in the `expr` string. It can be an int for a
          character offset, or a tuple of starting (row/line, column).

        If `resolve` is True and `symbols` were provided at Licensing creation time,
        each license and exception is recognized from these known licensing symbols.
        If `resolve` is False or `symbols` were not provided at Licensing creation
        time, then symbols are not resolved to known symbols and anything between two
        keywords is considered as a symbol.

        If `strict` is True, additional exceptions will be raised:
         - if a symbol is not resolved.
         - in a expression such as "XXX with ZZZ" if the XXX symbol has
           `is_expection` set to True or the YYY symbol has `is_expection` set to
           False.
        """
        if resolve:
            scanner = self.get_resolving_scanner()
        else:
            scanner = self.get_basic_scanner()

        # scan with an automaton, recognize whole symbols+keywords or only keywords
        results = scanner.scan(expression)
        results = strip_and_skip_spaces(results)
        result_groups = group_results_for_with_subexpression(results)
        result_groups = list(result_groups)
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
                        if strict and not val.is_exception:
                            raise ParseError(token_type=TOKEN_SYMBOL,
                                             token_string=result.string,
                                             position=result.start,
                                             error_code=PARSE_INVALID_EXCEPTION)

                        # known symbol: The strict check above handled possible errors before.
                        token = val
                    else:
                        # this should not be possible by design
                        raise Exception('Licensing.tokenize is internally confused...')
                else:
                    # unknown symbol
                    token = LicenseSymbol(result.string)

            else:
                if len(group) != 3:
                    raise Exception(repr(group))

                assert len(group) == 3
                # this is a A with B seq of three results
                lic_res, _WITH , exc_res = group
                pos = lic_res.start
                token_string = ' '.join([t.string for t in group])

                # licenses
                lic_out = lic_res.output
                lic_sym = lic_out and lic_out.value or LicenseSymbol(lic_res.string, is_exception=False)
                if not isinstance(lic_sym, LicenseSymbol):
                    raise ParseError(
                        TOKEN_SYMBOL, lic_res.string, lic_res.start, PARSE_INVALID_SYMBOL)

                if strict and lic_sym.is_exception:
                    raise ParseError(
                        TOKEN_SYMBOL, lic_res.string, lic_res.start, PARSE_INVALID_EXCEPTION)

                # exception
                exc_out = exc_res.output
                exc_sym = exc_out and exc_out.value or LicenseSymbol(exc_res.string, is_exception=True)
                if not isinstance(exc_sym, LicenseSymbol):
                    raise ParseError(
                        TOKEN_SYMBOL, exc_res.string, exc_res.start, PARSE_INVALID_SYMBOL)

                if strict and not exc_sym.is_exception:
                    raise ParseError(
                        TOKEN_SYMBOL, exc_res.string, exc_res.start, PARSE_INVALID_SYMBOL_AS_EXCEPTION)

                token = LicenseWithExceptionSymbol(lic_sym, exc_sym, strict)

            yield token, token_string, pos

    def get_basic_scanner(self):
        """
        Return a basic scanner either cached or created as needed. This scanner does
        not recognize known symbols when tokenizing expressions. Only keywords are
        recognized and a license symbol is anything in between two keywords.
        """
        if self.basic_scanner is not None:
            return self.basic_scanner

        self.basic_scanner = scanner = Scanner(ignore_case=True)
        for keyword in _KEYWORDS:
            scanner.add(keyword.value, keyword)
        scanner.make_automaton()
        return scanner

    def get_resolving_scanner(self):
        """
        Return a resolving scanner either cached or created as needed. If symbols
        were provided when this Licensing was created, the resolving_scanner will
        recognize known symbols when tokenizing expressions. Otherwise, only keywords
        are recognized and license symbols is anything in between keywords.
        """
        if self.resolving_scanner is not None:
            return self.resolving_scanner

        # only use a basic keyword-only scanner if we have known_symbols
        if not self.known_symbols:
            self.resolving_scanner = self.get_basic_scanner()
            return self.resolving_scanner

        self.resolving_scanner = scanner = Scanner(ignore_case=True)
        for keyword in _KEYWORDS:
            scanner.add(keyword.value, keyword)

        # only build a basic keyword-only resolving_scanner if we have known_symbols
        if not self.known_symbols:
            scanner.make_automaton()
            return scanner

        # self.known_symbols has been created at Licensing initialization time and is
        # already validated and trusted here
        for key, symbol in self.known_symbols.items():
            # always use the key even if there are no aliases.
            scanner.add(key, symbol)
            aliases = getattr(symbol, 'aliases', [])
            for alias in aliases:
                # normalize spaces for each alias. The Scanner will lowercase them
                # since we created it with ignore_case=True
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
        `original_key` and any other attribute that was attached to a license symbol
        instance and a custom template can be provided to handle custom HTML
        rendering or similar.

        For symbols that hold multiple licenses (e.g. a WITH statement) the template
        is applied to each symbol individually.
        """
        return NotImplementedError


class BaseSymbol(Renderable, boolean.Symbol):
    """
    A base class for all symbols.
    """

    def decompose(self):
        """
        Yield the underlying symbols of this symbol.
        """
        raise NotImplementedError


#FIXME: we need to implement comparison!!!!
@total_ordering
class LicenseSymbol(BaseSymbol):
    """
    A LicenseSymbol represents a license as used in a license expression.
    """
    def __init__(self, key, aliases=tuple(), is_exception=False, *args, **kwargs):
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

        # normalize for spaces
        key = ' '.join(key.split())

        # kept as a space-normalized version of the original key, but not lowercased
        self.original_key = key

        # key is always lowercased
        self.key = key.lower()

        if aliases and not isinstance(aliases, (list, tuple,)):
            raise TypeError('aliases must be a sequence.')
        self.aliases = aliases and tuple(aliases) or tuple()
        self.is_exception = is_exception

        # super only know about a single "obj" object.
        super(LicenseSymbol, self).__init__(self.key)

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
        return (self is other
            or (isinstance(other, self.__class__) and self.key == other.key)
            or (self.symbol_like(other) and self.key == other.key))

    __nonzero__ = __bool__ = lambda s: True

    def __str__(self):
        return self.key

    def __repr__(self):
        cls = self.__class__.__name__
        key = self.key
        aliases = self.aliases and (', aliases=%(a)r' % {'a': self.aliases}) or ''
        is_exception = self.is_exception
        return '%(cls)s(key=%(key)r, is_exception=%(is_exception)r%(aliases)s)' % locals()

    @classmethod
    def symbol_like(cls, symbol):
        """
        Return True if `symbol` is a symbol-like object with its essential attributes.
        """
        return hasattr(symbol, 'key') and hasattr(symbol, 'is_exception') and hasattr(symbol, '__dict__')


#FIXME: we need to implement comparison!!!!
@total_ordering
class LicenseSymbolLike(LicenseSymbol):
    """
    A LicenseSymbolLike object wraps a symbol-like object to expose a LicenseSymbol
    behavior.
    """
    def __init__(self, symbol_like, *args, **kwargs):
        if not self.symbol_like(symbol_like):
            raise ExpressionError(
                'Not a symbol-like object: %(symbol_like)r' % locals())

        self.wrapped = symbol_like
        super(LicenseSymbol, self).__init__(self.key)

    @property
    def key(self):
        return self.wrapped.key

    @property
    def is_exception(self):
        return self.wrapped.is_exception

    @property
    def aliases(self):
        return getattr(self.wrapped, 'aliases', tuple())


#FIXME: we need to implement comparison!!!!
@total_ordering
class LicenseWithExceptionSymbol(BaseSymbol):
    """
    A LicenseWithExceptionSymbol represents a license "with" an exception as used in
    a license expression. It holds two LicenseSymbols objects: one for the left-hand
    license proper and one for the right-hand exception to this license and deals
    with the specifics of resolution, validation and representation.
    """
    def __init__(self, license_symbol, exception_symbol, strict=False, *args, **kwargs):
        """
        Initialize a new LicenseWithExceptionSymbol from a `license_symbol` and a
        `exception_symbol` symbol-like objects.

        Raise a ExpressionError exception if strict is True and either:
        - license_symbol.is_exception is True
        - exception_symbol.is_exception is not True
        """
        if not LicenseSymbol.symbol_like(license_symbol):
            raise ExpressionError(
                'license_symbol must be a LicenseSymbol-like object: %(license_symbol)r' % locals())

        if strict and license_symbol.is_exception:
            raise ExpressionError(
                'license_symbol cannot be an exception with "is_exception" set to True: %(license_symbol)r' % locals())

        if not LicenseSymbol.symbol_like(exception_symbol):
            raise ExpressionError(
                'exception_symbol must be a LicenseSymbol-like object: %(exception_symbol)r' % locals())

        if strict and not exception_symbol.is_exception:
            raise ExpressionError(
                'exception_symbol must be an exception with "is_exception" set to True: %(exception_symbol)r' % locals())

        self.license_symbol = license_symbol
        self.exception_symbol = exception_symbol
        super(LicenseWithExceptionSymbol, self).__init__(str(self))

    def decompose(self):
        yield self.license_symbol
        yield self.exception_symbol

    def render(self, template='{key}'):
        lic = self.license_symbol.render(template)
        exc = self.exception_symbol.render(template)
        return '%(lic)s WITH %(exc)s' % locals()

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
        """
        Render an expression as a string, recursively applying the string `template`
        to every symbols and operators.
        """
        expression_args = self.args
        if len(expression_args) == 1:
            # a bare symbol
            sym = expression_args[0]
            if isinstance(sym, Renderable):
                sym = sym.render(template)

            elif LicenseSymbol.symbol_like(sym) and hasattr(sym, '__dict__'):
                # this is not a renderable symbol so it must be some symbol-like type
                # it must be an object with a __dict__
                sym = template.format(**sym.__dict__)

            else:
                print('WARNING: symbol is not renderable: using plain string representation.')
                # FIXME: CAN THIS REALLY HAPPEN since we only have symbols, OR, AND?
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
                # recurse
                rendered = arg.render(template)

            elif LicenseSymbol.symbol_like(arg) and hasattr(arg, '__dict__'):
                # this is not a renderable symbol so it must be some symbol-like type
                # it must be an object with a __dict__
                rendered = template.format(**arg.__dict__)

            else:
                print('WARNING: object in expression is not renderable: falling back to plain string representation: %(arg)r.')
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
    # either the output value is a known sym, or we have no output for unknown sym
    return result.output and isinstance(result.output.value, LicenseSymbol) or not result.output


def is_with_keyword(result):
    return (result.output
            and isinstance(result.output.value, Keyword)
            and result.output.value.type == TOKEN_WITH)


def is_with_subexpression(results):
    lic, wit, exc = results
    return (is_symbol(lic) and is_with_keyword(wit) and is_symbol(exc))


def as_symbols(symbols):
    """
    Return an iterable of LicenseSymbol objects from a sequence of `symbols` or
    strings. If an item is a string, then create a new LicenseSymbol for it using the
    string as key. If this is not a string it must be a LicenseSymbol-like type. It
    will raise a TypeError expection if an item is neither a string or LicenseSymbol-
    like.
    """
    if symbols:
        for symbol in symbols:
            if not symbol:
                continue
            if isinstance(symbol, bytes):
                try:
                    symbol = unicode(symbol)
                except:
                    raise TypeError('%(symbol)r is not a unicode string.' % locals())

            if isinstance(symbol, unicode):
                if symbol.strip():
                    yield LicenseSymbol(symbol)

            elif isinstance(symbol, LicenseSymbol):
                yield symbol

            elif LicenseSymbol.symbol_like(symbol):
                yield LicenseSymbolLike(symbol)

            else:
                raise TypeError('%(symbol)r is not a unicode string '
                                'or a LicenseSymbol-like instance.' % locals())


def validate_symbols(symbols, validate_keys=False, _keywords=KEYWORDS):
    """
    Return a tuple of (`warnings`, `errors`) given a sequence of `symbols`
    LicenseSymbol-like objects.

    - warnings is a list of validation warnings messages (possibly empty if there
      were no warnings).
    - errors is a list of validation error messages (possibly empty if there were no
      errors).

    Keys and aliases are cleaned and validated for uniqueness.
    """

    # collection used for checking unicity and correctness
    seen_keys = set()
    seen_aliases = {}
    seen_exceptions = set()

    # collections to accumulate invalid data and build error messages at the end
    not_symbol_classes = []
    dupe_keys = set()
    dupe_exceptions = set()
    dupe_aliases = collections.defaultdict(list)
    invalid_keys_as_kw = set()
    invalid_alias_as_kw = set()

    # warning
    warning_dupe_aliases = set()

    for symbol in symbols:
        if not isinstance(symbol, LicenseSymbol):
            not_symbol_classes.append(symbol)
            continue

        key = symbol.key
        key = key.strip()
        keyl = key.lower()

        # ensure keys are unique
        if keyl in seen_keys:
            dupe_keys.add(key)

        # key cannot be an expression keyword
        if keyl in _keywords:
            invalid_keys_as_kw.add(key)

        # keep a set of unique seen keys
        seen_keys.add(keyl)

        # aliases is an optional attribute
        aliases = getattr(symbol, 'aliases', [])
        initial_alias_len = len(aliases)

        # always normalize aliases for spaces and case
        aliases = set([' '.join(alias.lower().strip().split()) for alias in aliases])
        # KEEP UNIQUES, remove empties
        aliases = set(a for a in aliases if a)

        # issue a warning when there are duplicated or empty aliases
        if len(aliases) != initial_alias_len:
            warning_dupe_aliases.add(key)

        # always add a lowercase key as an alias
        aliases.add(keyl)

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

        if symbol.is_exception:
            if keyl in seen_exceptions:
                dupe_exceptions.add(keyl)
            else:
                seen_exceptions.add(keyl)

    # build warning and error messages from invalid data
    errors = []
    for ind in sorted(not_symbol_classes):
        errors.append('Invalid item: not a LicenseSymbol object: %(ind)s.' % locals())

    for dupe in sorted(dupe_keys):
        errors.append('Invalid duplicated license key: %(dupe)s.' % locals())

    for dalias, dkeys in sorted(dupe_aliases.items()):
        dkeys = ', '.join(dkeys)
        errors.append('Invalid duplicated alias pointing to different keys: '
                      '%(dalias)s to keys: %(dkeys)s.' % locals())

    for dupe in sorted(dupe_exceptions):
        errors.append('Invalid duplicated license exception key: %(dupe)s.' % locals())

    for ikw in sorted(invalid_keys_as_kw):
        errors.append('Invalid key: a key cannot be an expression keyword: %(ikw)s.' % locals())

    for ikw in sorted(invalid_alias_as_kw):
        errors.append('Invalid alias: an alias cannot be an expression keyword: %(ikw)r.' % locals())

    warnings = []
    for dupeal in sorted(dupe_aliases):
        errors.append('Duplicated or empty aliases ignored for license key: %(dupeal)r.' % locals())

    return warnings, errors
