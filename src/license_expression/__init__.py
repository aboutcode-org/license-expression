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
    str = unicode  # NOQA
except NameError:
    # Python 3
    unicode = str  # NOQA

from collections import defaultdict
from collections import deque
from collections import namedtuple
from collections import OrderedDict
from copy import copy
from copy import deepcopy
from functools import total_ordering
import itertools
import logging
from pprint import pprint
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
from boolean.boolean import TOKEN_AND
from boolean.boolean import TOKEN_OR
from boolean.boolean import TOKEN_LPAR
from boolean.boolean import TOKEN_RPAR

from license_expression._pyahocorasick import Trie as Scanner
from license_expression._pyahocorasick import Token

TRACE = False

logger = logging.getLogger(__name__)


def logger_debug(*args):
    pass


if TRACE:

    def logger_debug(*args):
        return logger.debug(' '.join(isinstance(a, str) and a or repr(a) for a in args))

    import sys
    logging.basicConfig(stream=sys.stdout)
    logger.setLevel(logging.DEBUG)

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
Keyword = namedtuple('Keyword', 'value type')
Keyword.__len__ = lambda self: len(self.value)

# id for "with" token which is not a proper boolean symbol but an expression symbol
TOKEN_WITH = 10

# keyword types that include operators and parens

KW_LPAR = Keyword('(', TOKEN_LPAR)
KW_RPAR = Keyword(')', TOKEN_RPAR)
KW_AND = Keyword('and', TOKEN_AND)
KW_OR = Keyword('or', TOKEN_OR)
KW_WITH = Keyword('with', TOKEN_WITH)

KEYWORDS = (KW_AND, KW_OR, KW_LPAR, KW_RPAR, KW_WITH,)
KEYWORDS_STRINGS = set(kw.value for kw in KEYWORDS)

# mapping of lowercase operator strings to an operator object
OPERATORS = {'and': KW_AND, 'or': KW_OR, 'with': KW_WITH}


class Licensing(boolean.BooleanAlgebra):
    """
    Define a mini language to parse, validate and compare license expressions.

    For example:

    >>> l = Licensing()
    >>> expr = l.parse(" GPL-2.0 or LGPL-2.1 and mit ")
    >>> expected = 'GPL-2.0 OR (LGPL-2.1 AND mit)'
    >>> assert expected == expr.render('{symbol.key}')

    >>> expected = [
    ...   LicenseSymbol('GPL-2.0'),
    ...   LicenseSymbol('LGPL-2.1'),
    ...   LicenseSymbol('mit')
    ... ]
    >>> assert expected == l.license_symbols(expr)

    >>> symbols = ['GPL-2.0+', 'Classpath', 'BSD']
    >>> l = Licensing(symbols)
    >>> expression = 'GPL-2.0+ with Classpath or (bsd)'
    >>> parsed = l.parse(expression)
    >>> expected = 'GPL-2.0+ WITH Classpath OR BSD'
    >>> assert expected == parsed.render('{symbol.key}')

    >>> expected = [
    ...   LicenseSymbol('GPL-2.0+'),
    ...   LicenseSymbol('Classpath'),
    ...   LicenseSymbol('BSD')
    ... ]
    >>> assert expected == l.license_symbols(parsed)
    >>> assert expected == l.license_symbols(expression)
    """

    def __init__(self, symbols=tuple(), quiet=True):
        """
        Initialize a Licensing with an optional `symbols` sequence of LicenseSymbol
        or LicenseSymbol-like objects or license key strings. If provided and this
        list data is invalid, raise a ValueError.
        """
        super(Licensing, self).__init__(Symbol_class=LicenseSymbol, AND_class=AND, OR_class=OR)

        # FIXME: this should be instead a super class of all symbols
        self.LicenseSymbol = self.Symbol

        symbols = symbols or tuple()

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

        # mapping of known symbol key to symbol for reference
        self.known_symbols = {symbol.key: symbol for symbol in symbols}

        # mapping of lowercase key and aliaes to symbol used to resolve symbols
        self.symbol_by_key = get_symbols_by_key(symbols)

        # Aho-Corasick automaton-based Scanner used for expression tokenizing
        self.scanner = None

    def is_equivalent(self, expression1, expression2, **kwargs):
        """
        Return True if both `expressions` LicenseExpression are equivalent.
        If a string is provided, it will be parsed and simplified.
        Extra kwargs are passed down to the parse() function.
        """
        ex1 = self._parse_and_simplify(expression1, **kwargs)
        ex2 = self._parse_and_simplify(expression2, **kwargs)
        return ex1 == ex2

    def contains(self, expression1, expression2, **kwargs):
        """
        Return True if `expression1` contains `expression2`.
        Expressions are either a string or a LicenseExpression object.
        If a string is provided, it will be parsed and simplified.

        Extra kwargs are passed down to the parse() function.
        """
        ex1 = self._parse_and_simplify(expression1, **kwargs)
        ex2 = self._parse_and_simplify(expression2, **kwargs)
        return ex2 in ex1

    def _parse_and_simplify(self, expression, **kwargs):
        expression = self.parse(expression, **kwargs)
        if expression is None:
            return None

        if not isinstance(expression, LicenseExpression):
            raise TypeError('expressions must be LicenseExpression objects: %(expression1)r, %(expression2)r' % locals())
        return expression.simplify()

    def license_symbols(self, expression, unique=True, decompose=True, **kwargs):
        """
        Return a list of LicenseSymbol objects used in an expression in
        the same order as they first appear in the expression tree.

        `expression` is either a string or a LicenseExpression object.
        If a string is provided, it will be parsed.

        If `unique` is True only return unique symbols.

        If `decompose` is True then composite LicenseWithExceptionSymbol instance are
        not returned directly but their underlying license and exception symbols are
        retruned instead.

        Extra kwargs are passed down to the parse() function.

        For example:
        >>> l = Licensing()
        >>> expected = [
        ...   LicenseSymbol('GPL-2.0'),
        ...   LicenseSymbol('LGPL-2.1+')
        ... ]
        >>> result = l.license_symbols(l.parse('GPL-2.0 or LGPL-2.1+'))
        >>> assert expected == result
        """
        expression = self.parse(expression, **kwargs)
        if expression is None:
            return []
        symbols = (s for s in expression.get_literals() if isinstance(s, BaseSymbol))
        if decompose:
            symbols = itertools.chain.from_iterable(s.decompose() for s in symbols)
        if unique:
            symbols = ordered_unique(symbols)
        return list(symbols)

    def primary_license_symbol(self, expression, decompose=True, **kwargs):
        """
        Return the left-most license symbol of an `expression` or None.
        `expression` is either a string or a LicenseExpression object.

        If `decompose` is True, only the left-hand license symbol of a decomposed
        LicenseWithExceptionSymbol symbol will be returned if this is the left most
        member. Otherwise a composite LicenseWithExceptionSymbol is returned in this
        case.

        Extra kwargs are passed down to the parse() function.
        """
        symbols = self.license_symbols(expression, decompose=decompose, **kwargs)
        if symbols:
            return symbols[0]

    def primary_license_key(self, expression, **kwargs):
        """
        Return the left-most license key of an `expression` or None. The underlying
        symbols are decomposed.
        `expression` is either a string or a LicenseExpression object.

        Extra kwargs are passed down to the parse() function.
       """
        prim = self.primary_license_symbol(expression, decompose=True, **kwargs)
        if prim:
            return prim.key

    def license_keys(self, expression, unique=True, **kwargs):
        """
        Return a list of licenses keys used in an expression in the same order as
        they first appear in the expression.
        `expression` is either a string or a LicenseExpression object.

        Extra kwargs are passed down to the parse() function.

        For example:
        >>> l = Licensing()
        >>> expr = ' GPL-2.0 and mit+ with blabla and mit or LGPL-2.1 and mit and mit+ with GPL-2.0'
        >>> expected = ['GPL-2.0', 'mit+', 'blabla', 'mit', 'LGPL-2.1']
        >>> assert expected == l.license_keys(l.parse(expr))
        """
        symbols = self.license_symbols(expression, unique=False, decompose=True, **kwargs)
        return self._keys(symbols, unique)

    def _keys(self, symbols, unique=True):
        keys = [ls.key for ls in symbols]
        # note: we only apply this on bare keys strings as we can have the same
        # symbol used as symbol or exception if we are not in strict mode
        if unique:
            keys = ordered_unique(keys)
        return keys

    def unknown_license_symbols(self, expression, unique=True, **kwargs):
        """
        Return a list of unknown licenses symbols used in an `expression` in the same
        order as they first appear in the `expression`.
        `expression` is either a string or a LicenseExpression object.

        Extra kwargs are passed down to the parse() function.
        """
        return [ls for ls in self.license_symbols(expression, unique=unique, decompose=True, **kwargs)
                if not ls.key in self.known_symbols]

    def unknown_license_keys(self, expression, unique=True, **kwargs):
        """
        Return a list of unknown licenses keys used in an `expression` in the same
        order as they first appear in the `expression`.

        `expression` is either a string or a LicenseExpression object.
        If a string is provided, it will be parsed.

        If `unique` is True only return unique keys.

        Extra kwargs are passed down to the parse() function.
        """
        symbols = self.unknown_license_symbols(expression, unique=False, **kwargs)
        return self._keys(symbols, unique)

    def parse(self, expression, validate=False, strict=False, **kwargs):
        """
        Return a new license LicenseExpression object by parsing a license expression
        string. Check that the expression syntax is valid and raise an Exception,
        ExpressionError or ParseError on errors. Return None for empty expressions.
        `expression` is either a string or a LicenseExpression object. If this is a
        LicenseExpression it is retruned as-is.

        Symbols are always recognized from known symbols if `symbols` were provided
        Licensing creation time: each license and exception is recognized from known
        license keys (and from aliases for a symbol if available).

        If `validate` is True and a symbol is unknown, an ExpressionError error
        is raised with a message listing the unknown license keys.

        If `validate` is False, no error is triggered.

        You can call the `unknown_license_keys` or `unknown_license_symbols` methods
        to get unknown license keys or symbols found in a parsed LicenseExpression.

        If `strict` is True, additional exceptions will be raised if in a expression
        such as "XXX with ZZZ" if the XXX symbol has `is_exception` set to True or
        the YYY symbol has `is_exception` set to False.

        For example:
        >>> expression = 'EPL-1.0 and Apache-1.1 OR GPL-2.0 with Classpath-exception'
        >>> parsed = Licensing().parse(expression)
        >>> expected = '(EPL-1.0 AND Apache-1.1) OR GPL-2.0 WITH Classpath-exception'
        >>> assert expected == parsed.render(template='{symbol.key}')
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
            tokens = list(self.tokenize(expression, strict=strict))
            expression = super(Licensing, self).parse(tokens)
        except TypeError as e:
            msg = 'Invalid expression syntax: ' + repr(e)
            raise ExpressionError(msg)

        if not isinstance(expression, LicenseExpression):
            raise ExpressionError('expression must be a LicenseExpression once parsed.')

        if validate:
            unknown_keys = self.unknown_license_keys(expression, unique=True)
            if unknown_keys:
                msg = 'Unknown license key(s): {}'.format(', '.join(unknown_keys))
                raise ExpressionError(msg)

        return expression

    def tokenize(self, expression, strict=False):
        """
        Return an iterable of 3-tuple describing each token given an expression
        unicode string. See boolean.BooleanAlgreba.tokenize() for API details.

        This 3-tuple contains these items: (token, token string, position):
        - token: either a Symbol instance or one of TOKEN_* token types..
        - token string: the original token unicode string.
        - position: some simple object describing the starting position of the
          original token string in the `expr` string. It can be an int for a
          character offset, or a tuple of starting (row/line, column).

        If `strict` is True, additional exceptions will be raised in a expression
        such as "XXX with ZZZ" if the XXX symbol has is_exception` set to True or the
        ZZZ symbol has `is_exception` set to False.
        """

#         if self.known_symbols:
        if TRACE:
            logger_debug('tokenize, using known_symbols')
        # scan with an automaton, recognize whole symbols+keywords or only keywords
        scanner = self.get_scanner()
        tokens = scanner.scan(expression)
#         else:
#             if TRACE:
#                 logger_debug('tokenize, using plain splitter')
#             tokens = splitter(expression)

        tokens = list(tokens)
        if TRACE:
            logger_debug('tokenize: tokens')
            pprint(tokens)

        # Assign symbol for unknown tokens
        tokens = list(build_symbols_from_unmatched_tokens(tokens))
        if TRACE:
            logger_debug('tokenize: token with symbols')
            pprint(tokens)

        # skip whitespace-only tokens
        tokens = [t for t in tokens if t.string and t.string.strip()]
        if TRACE:
            logger_debug('tokenize: token NO spaces')
            pprint(tokens)

        # group Symbols or operators tokens separated only by spaces
        # attempt to look this token_group of symbols in a table.
        # use symbol if available
        # otherwise ....?

        token_groups = build_token_groups_for_with_subexpression(tokens)

        if TRACE:
            token_groups = list(token_groups)
            logger_debug('tokenize: token_groups')
            pprint(token_groups)

        for token_group in token_groups:
            len_group = len(token_group)

            if not len_group:
                # This should never happen
                continue

            if len_group == 1:
                # a single token
                result = token_group[0]
                pos = result.start
                token_string = result.string
                val = result.value
                if val:
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
                        if strict and val.is_exception:
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
                    token = LicenseSymbol(result.string)

            else:
                if len_group != 3:
                    # this should never happen
                    string = ' '.join([tok.string for tok in token_group])
                    start = token_group[0].start
                    raise ParseError(
                        TOKEN_SYMBOL, string, start, PARSE_INVALID_EXPRESSION)

                # this is a A with B seq of three tokens
                lic_token, WITH , exc_token = token_group
                pos = lic_token.start
                WITHs = WITH.string.strip()
                token_string = ' '.join([lic_token.string, WITHs, exc_token.string])

                # licenses
                lic_sym = lic_token.value

                # this should not happen
                if lic_sym and not isinstance(lic_sym, LicenseSymbol):
                    raise ParseError(TOKEN_SYMBOL, lic_token.string, lic_token.start,
                                     PARSE_INVALID_SYMBOL)

                if not lic_sym:
                    lic_sym = LicenseSymbol(lic_token.string, is_exception=False)

                if not isinstance(lic_sym, LicenseSymbol):
                    raise ParseError(TOKEN_SYMBOL, lic_token.string, lic_token.start,
                                     PARSE_INVALID_SYMBOL)

                if strict and lic_sym.is_exception:
                    raise ParseError(TOKEN_SYMBOL, lic_token.string, lic_token.start,
                                     PARSE_INVALID_EXCEPTION)

                # exception
                exc_sym = exc_token.value

                # this should not happen
                if exc_sym and not isinstance(exc_sym, LicenseSymbol):
                    raise ParseError(TOKEN_SYMBOL, lic_sym.string, lic_sym.start,
                                     PARSE_INVALID_SYMBOL)
                if exc_sym:
                    exc_sym = copy(exc_sym)

                if not exc_sym:
                    exc_sym = LicenseSymbol(exc_token.string)

                if not isinstance(exc_sym, LicenseSymbol):
                    raise ParseError(TOKEN_SYMBOL, exc_token.string, exc_token.start,
                                     PARSE_INVALID_SYMBOL)

                if strict and self.known_symbols and not exc_sym.is_exception:
                    raise ParseError(TOKEN_SYMBOL, exc_token.string, exc_token.start,
                                     PARSE_INVALID_SYMBOL_AS_EXCEPTION)

                token = LicenseWithExceptionSymbol(lic_sym, exc_sym, strict)

            yield token, token_string, pos

    def get_scanner(self):
        """
        Return a scanner either cached or created as needed. If symbols were provided
        when this Licensing object was created, the scanner will recognize known
        symbols when tokenizing expressions. Otherwise, only keywords are recognized
        and a license symbol is anything in between keywords.
        """
        if self.scanner is not None:
            return self.scanner

        self.scanner = scanner = Scanner()

        for keyword in KEYWORDS:
            scanner.add(keyword.value, keyword)

        # self.known_symbols has been created at Licensing initialization time and is
        # already validated and trusted here
        for key, symbol in self.known_symbols.items():
            # always use the key even if there are no aliases.
            scanner.add(key, symbol)
            aliases = getattr(symbol, 'aliases', [])
            for alias in aliases:
                # normalize spaces for each alias. The Scanner will lowercase them
                if alias:
                    alias = ' '.join(alias.split())
                    scanner.add(alias, symbol)

        scanner.make_automaton()
        return scanner


def get_symbols_by_key(symbols):
    """
    Return a mapping of key->symbol given an iterable of symbols
    """
    by_key = {}
    for symbol in symbols:
        by_key[symbol.key.lower()] = symbol
        aliases = getattr(symbol, 'aliases', [])
        for alias in aliases:
            if alias:
                alias = ' '.join(alias.split())
            if alias:
                by_key[alias.lower()] = symbol
    return by_key


class Renderable(object):
    """
    An interface for renderable objects.
    """

    def render(self, template='{symbol.key}', *args, **kwargs):
        """
        Return a formatted string rendering for this expression using the `template`
        format string to render each symbol. The variable available are `symbol.key`
        and any other attribute that was attached to a license symbol instance and a
        custom template can be provided to handle custom HTML rendering or similar.

        For symbols that hold multiple licenses (e.g. a WITH statement) the template
        is applied to each symbol individually.

        Note that when render() is called the *args and **kwargs are propagated
        recursively to any Renderable object render() method.
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

    def __contains__(self, other):
        """
        Test if expr is contained in this symbol.
        """
        if not isinstance(other, BaseSymbol):
            return False
        if self == other:
            return True

        return any(mine == other for mine in self.decompose())


# validate license keys
is_valid_license_key = re.compile(r'^[-\w\s\.\+]+$', re.UNICODE).match


#FIXME: we need to implement comparison!!!!
@total_ordering
class LicenseSymbol(BaseSymbol):
    """
    A LicenseSymbol represents a license as used in a license expression.
    """

    def __init__(self, key, aliases=tuple(), is_exception=False, *args, **kwargs):
        if not key:
            raise ExpressionError(
                'A license key cannot be empty: %(key)r' % locals())

        if not isinstance(key, str):
            if isinstance(key, bytes):
                try:
                    key = unicode(key)
                except:
                    raise ExpressionError(
                        'A license key must be a unicode string: %(key)r' % locals())
            else:
                raise ExpressionError(
                    'A license key must be a unicode string: %(key)r' % locals())

        key = key.strip()

        if not key:
            raise ExpressionError(
                'A license key cannot be blank: "%(key)s"' % locals())

        # note: key can contain spaces
        if not is_valid_license_key(key):
            raise ExpressionError(
                'Invalid license key: the valid characters are: letters and numbers, '
                'underscore, dot or hyphen signs and spaces: "%(key)s"' % locals())

        # normalize for spaces
        key = ' '.join(key.split())

        if key.lower() in KEYWORDS_STRINGS:
            raise ExpressionError(
                'Invalid license key: a key cannot be a reserved keyword: "or", "and" or "with: "%(key)s"' % locals())

        self.key = key

        if aliases and not isinstance(aliases, (list, tuple,)):
            raise TypeError('License aliases must be a sequence.')
        self.aliases = aliases and tuple(aliases) or tuple()
        self.is_exception = is_exception

        # super only know about a single "obj" object.
        super(LicenseSymbol, self).__init__(self.key)

    def decompose(self):
        """
        Return an iterable of the underlying symbols for this symbol.
        """
        yield self

    def __hash__(self, *args, **kwargs):
        return hash((self.key, self.is_exception))

    def __eq__(self, other):
        if self is other:
            return True
        if not (isinstance(other, self.__class__) or self.symbol_like(other)):
            return False
        return self.key == other.key and self.is_exception == other.is_exception

    def __ne__(self, other):
        if self is other:
            return False
        if not (isinstance(other, self.__class__) or self.symbol_like(other)):
            return True
        return (self.key != other.key or self.is_exception != other.is_exception)

    def __lt__(self, other):
        if isinstance(
            other, (LicenseSymbol, LicenseWithExceptionSymbol, LicenseSymbolLike)):
            return str(self) < str(other)
        else:
            return NotImplemented

    __nonzero__ = __bool__ = lambda s: True

    def render(self, template='{symbol.key}', *args, **kwargs):
        return template.format(symbol=self)

    def __str__(self):
        return self.key

    def __len__(self):
        return len(self.key)

    def __repr__(self):
        cls = self.__class__.__name__
        key = self.key
        aliases = self.aliases and ('aliases=%(a)r, ' % {'a': self.aliases}) or ''
        is_exception = self.is_exception
        return '%(cls)s(%(key)r, %(aliases)sis_exception=%(is_exception)r)' % locals()

    def __copy__(self):
        return LicenseSymbol(self.key, tuple(self.aliases), self.is_exception)

    @classmethod
    def symbol_like(cls, symbol):
        """
        Return True if `symbol` is a symbol-like object with its essential attributes.
        """
        return hasattr(symbol, 'key') and hasattr(symbol, 'is_exception')


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
        super(LicenseSymbolLike, self).__init__(self.wrapped.key, *args, **kwargs)

        self.is_exception = self.wrapped.is_exception
        self.aliases = getattr(self.wrapped, 'aliases', tuple())

        # can we delegate rendering to a render method of the wrapped object?
        # we can if we have a .render() callable on the wrapped object.
        self._render = None
        renderer = getattr(symbol_like, 'render', None)
        if callable(renderer):
            self._render = renderer

    def __copy__(self):
        return LicenseSymbolLike(symbol_like=self.wrapped)

    def render(self, template='{symbol.key}', *args, **kwargs):
        if self._render:
            return self._render(template, *args, **kwargs)
        return super(LicenseSymbolLike, self).render(template, *args, **kwargs)

    __nonzero__ = __bool__ = lambda s: True

    def __hash__(self, *args, **kwargs):
        return hash((self.key, self.is_exception))

    def __eq__(self, other):
        if self is other:
            return True
        if not (isinstance(other, self.__class__) or self.symbol_like(other)):
            return False
        return self.key == other.key and self.is_exception == other.is_exception

    def __ne__(self, other):
        if self is other:
            return False
        if not (isinstance(other, self.__class__) or self.symbol_like(other)):
            return True
        return (self.key != other.key or self.is_exception != other.is_exception)

    def __lt__(self, other):
        if isinstance(
            other, (LicenseSymbol, LicenseWithExceptionSymbol, LicenseSymbolLike)):
            return str(self) < str(other)
        else:
            return NotImplemented


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

    def __copy__(self):
        return LicenseWithExceptionSymbol(copy(self.license_symbol), copy(self.exception_symbol))

    def decompose(self):
        yield self.license_symbol
        yield self.exception_symbol

    def render(self, template='{symbol.key}', *args, **kwargs):
        lic = self.license_symbol.render(template, *args, **kwargs)
        exc = self.exception_symbol.render(template, *args, **kwargs)
        return '%(lic)s WITH %(exc)s' % locals()

    def __hash__(self, *args, **kwargs):
        return hash((self.license_symbol, self.exception_symbol,))

    def __eq__(self, other):
        if self is other:
            return True
        if not isinstance(other, self.__class__):
            return False
        return (self.license_symbol == other.license_symbol
            and self.exception_symbol == other.exception_symbol)

    def __ne__(self, other):
        if self is other:
            return False
        if not isinstance(other, self.__class__):
            return True
        return not (self.license_symbol == other.license_symbol
            and self.exception_symbol == other.exception_symbol)

    def __lt__(self, other):
        if isinstance(
            other, (LicenseSymbol, LicenseWithExceptionSymbol, LicenseSymbolLike)):
            return str(self) < str(other)
        else:
            return NotImplemented

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

    def render(self, template='{symbol.key}', *args, **kwargs):
        """
        Render an expression as a string, recursively applying the string `template`
        to every symbols and operators.
        """
        expression_args = self.args
        if len(expression_args) == 1:
            # a bare symbol
            sym = expression_args[0]
            if isinstance(sym, Renderable):
                sym = sym.render(template, *args, **kwargs)

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
                rendered = arg.render(template, *args, **kwargs)

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


def build_symbols_from_unmatched_tokens(tokens):
    """
    Yield Token given a sequence of Token replacing unmatched contiguous Tokens
    by a single token with a LicenseSymbol.
    """
    tokens = list(tokens)

    unmatched = deque()

    def build_token_with_symbol():
        """
        Build and return a new Token from accumulated unmatched tokens or None.
        """
        if not unmatched:
            return
        # strip trailing spaces
        trailing_spaces = []
        while unmatched and not unmatched[-1].string.strip():
            trailing_spaces.append(unmatched.pop())

        if unmatched:
            string = ' '.join(t.string for t in unmatched if t.string.strip())
            start = unmatched[0].start
            end = unmatched[-1].end
            toksym = LicenseSymbol(string)
            unmatched.clear()
            yield Token(start, end, string, toksym)

        for ts in trailing_spaces:
            yield ts

    for tok in tokens:
        if tok.value:
            for symtok in build_token_with_symbol():
                yield symtok
            yield tok
        else:
            if not unmatched and not tok.string.strip():
                # skip leading spaces
                yield tok
            else:
                unmatched.append(tok)

    # end remainders
    for symtok in build_token_with_symbol():
        yield symtok


def build_token_groups_for_with_subexpression(tokens):
    """
    Yield tuples of Token given a sequence of Token such that:
     - all symbol-with-symbol sequences of 3 tokens are grouped in a three-tuple
     - other tokens are a single token wrapped in a tuple.
    """

    # if n-1 is sym, n is with and n+1 is sym: yield this as a group for a with
    # exp otherwise: yield each single token as a group

    tokens = list(tokens)

    # check three contiguous token from scanning at a time
    triple_len = 3

    # shortcut if there are no grouping possible
    if len(tokens) < triple_len:
        for tok in tokens:
            yield (tok,)
        return

    # accumulate three contiguous tokens
    triple = deque()
    triple_popleft = triple.popleft
    triple_clear = triple.clear
    tripple_append = triple.append

    for tok in tokens:
        if len(triple) == triple_len:
            if is_with_subexpression(triple):
                yield tuple(triple)
                triple_clear()
            else:
                prev_tok = triple_popleft()
                yield (prev_tok,)
        tripple_append(tok)

    # end remainders
    if triple:
        if len(triple) == triple_len and is_with_subexpression(triple):
            yield tuple(triple)
        else:
            for tok in triple:
                yield (tok,)


def is_with_subexpression(tokens_tripple):
    """
    Return True if a Token tripple is a WITH license sub-expression.
    """
    lic, wit, exc = tokens_tripple
    return (isinstance(lic.value, LicenseSymbol)
        and wit.value == KW_WITH
        and isinstance(exc.value, LicenseSymbol)
    )


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


def validate_symbols(symbols, validate_keys=False):
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
    dupe_aliases = defaultdict(list)
    invalid_keys_as_kw = set()
    invalid_alias_as_kw = defaultdict(list)

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
        if keyl in KEYWORDS_STRINGS:
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
            if alias in KEYWORDS_STRINGS:
                invalid_alias_as_kw[key].append(alias)

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
        errors.append('Invalid duplicated alias pointing to multiple keys: '
                      '%(dalias)s point to keys: %(dkeys)s.' % locals())

    for ikey, ialiases in sorted(invalid_alias_as_kw.items()):
        ialiases = ', '.join(ialiases)
        errors.append('Invalid aliases: an alias cannot be an expression keyword. '
                      'key: "%(ikey)s", aliases: %(ialiases)s.' % locals())

    for dupe in sorted(dupe_exceptions):
        errors.append('Invalid duplicated license exception key: %(dupe)s.' % locals())

    for ikw in sorted(invalid_keys_as_kw):
        errors.append('Invalid key: a key cannot be an expression keyword: %(ikw)s.' % locals())

    warnings = []
    for dupeal in sorted(dupe_aliases):
        errors.append('Duplicated or empty aliases ignored for license key: %(dupeal)r.' % locals())

    return warnings, errors


_tokenizer = re.compile('''
    (?P<symbol>[^\s\(\)]+)
     |
    (?P<space>\s+)
     |
    (?P<lpar>\()
     |
    (?P<rpar>\))
    ''',
    re.VERBOSE | re.MULTILINE | re.UNICODE
)


def splitter(expression):
    """
    Return an iterable of Tokens describing each token given an expression
    unicode string.

    The split is done on spaces and parens. Anything else is either a token or a
    symbol.
    """
    if not expression:
        return

    if not isinstance(expression, str):
        raise ParseError(error_code=PARSE_EXPRESSION_NOT_UNICODE)

    for match in _tokenizer.finditer(expression):
        if not match:
            continue
        # set start and end as string indexes
        start, end = match.span()
        end = end - 1
        match_getter = match.groupdict().get

        space = match_getter('space')
        if space:
            yield Token(start, end, space, None)

        lpar = match_getter('lpar')
        if lpar:
            yield Token(start, end, lpar, KW_LPAR)

        rpar = match_getter('rpar')
        if rpar:
            yield Token(start, end, rpar, KW_RPAR)

        operator_or_sym = match_getter('symbol')
        if not operator_or_sym:
            continue

        operator = OPERATORS.get(operator_or_sym.lower())
        if operator:
            yield Token(start, end, operator_or_sym, operator)
        else:
            sym = LicenseSymbol(key=operator_or_sym)
            yield Token(start, end, operator_or_sym, sym)
