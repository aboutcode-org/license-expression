#
# license-expression is a free software tool from nexB Inc. and others.
# Visit https://github.com/nexB/license-expression for support and download.
#
# Copyright (c) 2016 nexB Inc. and others. All rights reserved.
# http://nexb.com  and http://aboutcode.org
#
# The license-expression software is licensed under the Apache License version 2.0.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.


"""
Parse, validate and compare license expressions using SPDX-like conventions.
You can use SPDX license indentifiers or other license keys (such as in AboutCode).
You can also reason using boolean logic about license expressions, test containment,
equivalence, normalize or simplify the expressions.
"""

from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function

import collections
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

# append new error code to PARSE_ERRORS
PARSE_EXPRESSION_NOT_UNICODE = max(PARSE_ERRORS) + 1
PARSE_ERRORS[PARSE_EXPRESSION_NOT_UNICODE] = 'Expression string must be unicode.'


"""
This module defines a mini language to parse, validate and compare license
expressions. The main entry point is the Licensing object.
"""


class ExpressionError(Exception):
    pass


class LicenseSymbol(boolean.Symbol):
    """
    A license symbol as used in an expression.
    """
    def __init__(self, obj):
        if not obj:
            raise ExpressionError('LicenseSymbol value cannot be empty.')

        if not isinstance(obj, unicode):
            raise ExpressionError('LicenseSymbol value must be unicode.')

        # normalize spaces
        obj = obj.strip()
        obj = ' '.join(obj.split())

        super(LicenseSymbol, self).__init__(obj)
        self.original_value = obj
        # True if the value was successfully resolved
        self.resolved = False

    def resolve(self, licenses=None):
        """
        Resolve the license key for this license symbol using  the `licenses`
        mapping of license symbols to normalized license key.

        Update self with the resolved value if resolution was successful.

        Resolution is based on lower cased, stripped and space-normalized values
        therefore the key of the `licenses` mapping must be lowercase, stripped
        and its spaces must be normalized.

        Also return the resolved value:
        - If `licenses` is not provided or empty, return the symbol value as-is.
        - If the value cannot be resolved, return None.

        For example the `licenses` mapping could be:
        {'mit license': 'mit ', 'apache software license': 'apache-2.0', ...}
        """
        if self.resolved or not licenses:
            return self.obj

        resolved = licenses.get(self.obj.lower(), None)
        if resolved:
            self.resolved = True
            self.obj = resolved
        return resolved


class AND(boolean.AND):
    def __init__(self, *args):
        super(AND, self).__init__(*args)
        self.operator = ' AND '


class OR(boolean.OR):
    def __init__(self, *args):
        super(OR, self).__init__(*args)
        self.operator = ' OR '


class Licensing(boolean.BooleanAlgebra):
    """
    Define a mini language to parse, validate and compare license expressions.

    For example:

    >>> l = Licensing()
    >>> expr = l.parse(" GPL-2.0 or LGPL 2.1 and mit ")
    >>> str(expr)
    'GPL-2.0 OR (LGPL 2.1 AND mit)'
    >>> l.license_symbols(expr)
    [LicenseSymbol('GPL-2.0'), LicenseSymbol('LGPL 2.1'), LicenseSymbol('mit')]
    >>> str(expr)
    'GPL-2.0 OR (LGPL 2.1 AND mit)'
    >>> print(expr.pretty())
    OR(
      LicenseSymbol('GPL-2.0'),
      AND(
        LicenseSymbol('LGPL 2.1'),
        LicenseSymbol('mit')
      )
    )
    >>> expr2 = l.parse(" GPL-2.0 or (mit and LGPL 2.1) ")
    >>> expr2.simplify() == expr.simplify()
    True
    >>> expr3 = l.parse("mit and LGPL 2.1")
    >>> expr3 in expr2
    True

    Expression can be parsed from a string::
        >>> l = Licensing()
        >>> expr = l.parse(" GPL-2.0 or LGPL 2.1 and mit ")
        >>> sorted(l.license_symbols(expr))
        [LicenseSymbol('GPL-2.0'), LicenseSymbol('LGPL 2.1'), LicenseSymbol('mit')]
        >>> str(expr)
        'GPL-2.0 OR (LGPL 2.1 AND mit)'
        >>> print(expr.pretty())
        OR(
          LicenseSymbol('GPL-2.0'),
          AND(
            LicenseSymbol('LGPL 2.1'),
            LicenseSymbol('mit')
          )
        )

    Validated where license keys are resolved::
        >>> licenses = {'the gnu gpl 20': 'GPL-2.0', 'gpl-2.0': 'GPL-2.0', 'lgpl-2.1': 'LGPL-2.1'}
        >>> l = Licensing(licenses=licenses)
        >>> expr = l.parse("The GNU GPL 20 or LGPL-2.1 and mit")
        >>> str(expr)
        'The GNU GPL 20 OR (LGPL-2.1 AND mit)'
        >>> expr = l.resolve(expr)
        >>> str(expr)
        'GPL-2.0 OR (LGPL-2.1 AND mit)'
        >>> l.unknown_symbols(expr)
        [LicenseSymbol('mit')]

    Simplified::
        >>> expr2 = l.parse(" GPL-2.0 or (mit and LGPL 2.1) or bsd Or GPL-2.0  or (mit and LGPL 2.1)")
        >>> str(expr2.simplify())
        'GPL-2.0 OR bsd OR (LGPL 2.1 AND mit)'

    Compared::
        >>> expr1 = l.parse(" GPL-2.0 or (LGPL 2.1 and mit) ")
        >>> expr2 = l.parse(" (mit and LGPL 2.1)  or GPL-2.0 ")
        >>> l.is_equivalent(expr1, expr2)
        True
        >>> expr1.simplify() == expr2.simplify()
        True
        >>> expr3 = l.parse(" GPL-2.0 or mit or LGPL 2.1")
        >>> l.is_equivalent(expr2, expr3)
        False
        >>> expr4 = l.parse("mit and LGPL 2.1")
        >>> expr4.simplify() in expr2.simplify()
        True
        >>> l.contains(expr2, expr4)
        True

    Or built from Python expressions, using bitwise operators on Licensing objects::
        >>> licensing = Licensing()
        >>> AND = licensing.AND
        >>> OR = licensing.OR
        >>> LicenseSymbol = licensing.LicenseSymbol
        >>> expr1 = LicenseSymbol('GPL-2.0') | (LicenseSymbol('mit') & LicenseSymbol('LGPL 2.1'))
        >>> expr2 = licensing.parse(" GPL-2.0 or (mit and LGPL 2.1) ")
        >>> licensing.is_equivalent(expr1, expr2)
        True
    """
    def __init__(self, licenses=None):
        """
        Initialize a Licensing with an optional mapping of reference `licenses`.

        `licenses` is a mapping of unicode string license symbol values to a
        license key.
        """
        super(Licensing, self).__init__(Symbol_class=LicenseSymbol,
                                        AND_class=AND, OR_class=OR)
        self.LicenseSymbol = self.Symbol
        self.licenses = licenses or None

    def parse(self, expression, resolve=False, simplify=False):
        """
        Return a new license Expression object by parsing a license expression
        string. Check that the expression is valid.
        Raise ExpressionError or ParseError on errors.

        If `resolve` is True also attempt to resolve each license against the
        Licensing.licenses and replace the license symbols accordingly.

        If `simplify` is True the return expression is simplified to form
        suitable for comparison.

        For example:

        >>> ex = '''
        ... EPL 1.0 AND Apache 1.1 AND Apache 2.0 AND BSD-Modified AND CPL 1.0 AND
        ... ICU Composite License AND JPEG License AND JDOM License AND LGPL 2.0 AND
        ... MIT Open Group AND MPL 1.1 AND SAX-PD AND Unicode Inc License Agreement
        ... AND W3C Software Notice and License AND W3C Documentation License'''

        >>> L = Licensing()
        >>> p = L.parse(ex)
        >>> expected = ('EPL 1.0 AND Apache 1.1 AND Apache 2.0 AND BSD-Modified '
        ... 'AND CPL 1.0 AND ICU Composite License AND JPEG License '
        ... 'AND JDOM License AND LGPL 2.0 AND MIT Open Group AND MPL 1.1 '
        ... 'AND SAX-PD AND Unicode Inc License Agreement '
        ... 'AND W3C Software Notice AND License AND W3C Documentation License')

        >>> assert expected == unicode(p)
        """
        try:
            return self._parse(expression, resolve, simplify)
        except Exception as e:
            if not isinstance(e, (ExpressionError, ParseError)):
                raise ExpressionError('Invalid expression.')
            else:
                raise e

    def _parse(self, expression, resolve=False, simplify=False):
        if expression is None:
            return expression

        if isinstance(expression, basestring):
            if not expression or not expression.strip():
                return expression

            if not isinstance(expression, unicode):
                try:
                    expression = unicode(expression)
                except UnicodeDecodeError:
                    raise ParseError(error_code=PARSE_EXPRESSION_NOT_UNICODE)

            try:
                # this will raise a ParseError on errors
                expression = super(Licensing, self).parse(expression, simplify)
            except TypeError:
                raise ExpressionError('Invalid expression syntax.')

        if not isinstance(expression, LicenseExpression):
            raise ExpressionError('Expression must be a string or an expression.')

        if resolve:
            expression = self.resolve(expression)
            unknown_symbols = self.unknown_symbols(expression)
            if unknown_symbols:
                msg = 'Unknown license key(s): {}'.format(', '.join(ls.obj for ls in unknown_symbols))
                raise ExpressionError(msg)

        return expression

    def resolve(self, expression):
        """
        Return expression with LicenseSymbols resolved based on self.licenses
        """
        if isinstance(expression, LicenseExpression):
            for license_symbol in expression.get_symbols():
                license_symbol.resolve(self.licenses or None)
        return expression

    def unknown_symbols(self, expression):
        """
        Return a list of unknown LicenseSymbols found in the expression.
        A symbol is unknown if it is not resolvable.
        The expression symbols are resolved in-place.
        """
        if isinstance(expression, LicenseExpression):
            expression = self.resolve(expression)
            unknown_symbols = sorted(k for k in expression.symbols if not k.resolved)
            return unknown_symbols
        return []

    def unparse(self, expression):
        """
        Return an expression string from an expression string or
        LicenseExpression object.
        `expression` is either a string or a LicenseExpression object.
        If a string is provided, it will be parsed.
        """
        return str(self.build(expression))

    def build(self, expression, simplify=False):
        """
        Returns an expression from an expression or a string.
        Optionally simplifies the expression if simplify is True.
        """
        if isinstance(expression, basestring) and expression.strip():
            expression = self.parse(expression)
            if simplify:
                expression = expression.simplify()
        return expression

    def is_equivalent(self, expression1, expression2):
        """
        Return True if both expressions are equivalent.
        Expressions are either a string or a LicenseExpression object.
        If a string is provided, it will be parsed.
        """
        return self.build(expression1, simplify=True) == self.build(expression2, simplify=True)

    def contains(self, expression1, expression2):
        """
        Return True if expression1 contains expression2.
        Expressions are either a string or a LicenseExpression object.
        If a string is provided, it will be parsed.
        """
        return self.build(expression2, simplify=True) in self.build(expression1, simplify=True)

    def primary_license_key(self, expression):
        """
        Return the left-most license KEY of an expression or None.
        `expression` is either a string or a LicenseExpression object.
        If a string is provided, it will be parsed.

        For example:
        >>> l = Licensing()
        >>> expr = " GPL-2.0 and mit or LGPL 2.1 and mit "
        >>> l.primary_license_key(expr)
        u'GPL-2.0'
        """
        expression = self.build(expression)
        if not isinstance(expression, LicenseExpression):
            return
        license_symbol = self.license_symbols(expression)
        if license_symbol:
            return license_symbol[0].obj

    def license_keys(self, expression):
        """
        Return a list of unique licenses keys used in an expression in the same
        order as they first appear in the expression.

        `expression` is either a string or a LicenseExpression object.
        If a string is provided, it will be parsed.

        For example:
        >>> l = Licensing()
        >>> expr = " GPL-2.0 and mit or LGPL 2.1 and mit "
        >>> l.license_keys(expr)
        ['GPL-2.0', 'mit', 'LGPL 2.1']
        """
        expression = self.build(expression)
        if not isinstance(expression, LicenseExpression):
            return []
        return [str(ls.obj) for ls in self.license_symbols(expression)]

    def license_symbols(self, expression):
        """
        Return a list of unique LicenseSymbol objects used in an expression in
        the same order as they first appear in the expression.

        `expression` is either a string or a LicenseExpression object.
        If a string is provided, it will be parsed.

        For example:
        >>> l = Licensing()
        >>> l.license_symbols(" GPL-2.0 and mit or LGPL 2.1 and mit ")
        [LicenseSymbol('GPL-2.0'), LicenseSymbol('mit'), LicenseSymbol('LGPL 2.1')]
        """
        expression = self.build(expression)
        if not isinstance(expression, LicenseExpression):
            return []
        return unique(expression.get_symbols())

    def tokenize(self, expression):
        """
        Return an iterable of 3-tuple describing each token given an expression
        unicode string.
        Derived from the original boolean.py tokenize() method.
        """
        if not expression:
            return

        if not isinstance(expression, unicode):
            raise ParseError(error_code=PARSE_EXPRESSION_NOT_UNICODE)

        # mapping of lowercase token strings to a token type id
        TOKENS = {
            'and': boolean.TOKEN_AND,
            'or': boolean.TOKEN_OR,
            '(': boolean.TOKEN_LPAR,
            ')': boolean.TOKEN_RPAR,
        }

        # valid tokens and license characters
        license_char = lambda c: (c.isalnum() or c in '.:_-+')

        length = len(expression)
        position = 0
        symbol_parts = collections.deque()
        symbol_pos = 0
        while position < length:
            token = expression[position]

            # license symbols start with a letter
            symbol_start = license_char(token)
            if symbol_start:
                position += 1
                while position < length:
                    char = expression[position]
                    if license_char(char):
                        position += 1
                        token += char
                    else:
                        break
                position -= 1

            try:
                token_type = TOKENS[token.lower()]
                if symbol_parts:
                    # yield any symbol parts accumulated so far
                    yield boolean.TOKEN_SYMBOL, ' '.join(symbol_parts), symbol_pos
                    symbol_parts.clear()
                    symbol_pos = 0
                yield token_type, token, position

            except KeyError:
                if symbol_start:
                    if not symbol_parts:
                        # only increment symbol position on the first part
                        symbol_pos = position
                    # accumulate symbol parts
                    symbol_parts.append(token)
                elif token not in string.whitespace:
                    raise ParseError(token_string=token, position=position,
                                     error_code=PARSE_UNKNOWN_TOKEN)

            position += 1

        # last symbol if any
        if symbol_parts:
            yield boolean.TOKEN_SYMBOL, ' '.join(symbol_parts), symbol_pos


def unique(seq):
    """
    Return unique items in a sequence seq preserving the original order.
    """
    if not seq:
        return []
    seen = set()
    uniques = []
    for item in seq:
        if item in seen:
            continue
        uniques.append(item)
        seen.add(item)
    return uniques
