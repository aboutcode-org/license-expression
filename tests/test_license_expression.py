# license-expression is a free software tool from nexB Inc. and others.
# Visit https://github.com/nexB/license-expression for support and download.
#
# Copyright (c) 2017 nexB Inc. and others. All rights reserved.
# http://nexb.com  and http://aboutcode.org
#
# This software is licensed under the Apache License version 2.0.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.


from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import sys
from unittest import TestCase

from boolean.boolean import TOKEN_AND
from boolean.boolean import TOKEN_LPAR
from boolean.boolean import TOKEN_OR
from boolean.boolean import TOKEN_RPAR
from boolean.boolean import PARSE_UNBALANCED_CLOSING_PARENS
from boolean.boolean import PARSE_INVALID_SYMBOL_SEQUENCE

from license_expression import validate_symbols
from license_expression import Licensing
from license_expression import LicenseExpression
from license_expression import ParseError
from license_expression import ExpressionError
from license_expression import PARSE_INVALID_EXPRESSION
from license_expression import PARSE_INVALID_NESTING
from license_expression import LicenseSymbol
from license_expression import ExceptionSymbol
from license_expression import TOKEN_WITH
from license_expression import LicenseWithExceptionSymbol


class LicenseSymbolTest(TestCase):

    def test_LicenseSymbol(self):
        sym1 = LicenseSymbol('mit', 'MIT', ['MIT license'], known=True)
        assert sym1 == sym1
        assert 'mit' == sym1.key
        assert 'MIT' == sym1.name
        assert ('MIT license',) == sym1.aliases
        assert sym1.known

        sym2 = LicenseSymbol('mit', 'MIT', ['MIT license'], known=True)
        assert 'mit' == sym2.key
        assert 'MIT' == sym2.name
        assert ('MIT license',) == sym2.aliases
        assert sym2.known
        assert sym1 == sym2
        assert sym1 is not sym2

        sym2 = ExceptionSymbol('mit', 'MIT', ['MIT license'], known=True)
        assert 'mit' == sym2.key
        assert 'MIT' == sym2.name
        assert ('MIT license',) == sym2.aliases
        assert sym2.known
        assert sym1 != sym2

        sym2 = LicenseSymbol('mit', 'MIT', ['MIT license'], known=False)
        assert 'mit' == sym2.key
        assert 'MIT' == sym2.name
        assert ('MIT license',) == sym2.aliases
        assert not sym2.known
        assert sym1 != sym2


class LicensingTokenizeTest(TestCase):

    def test_tokenize_plain1(self):
        licensing = Licensing()
        expected = [
            (TOKEN_LPAR, '(', 1),
            (LicenseSymbol(key='mit', known=False), u' mit ', 2),
            (TOKEN_RPAR, ')', 7),
            (TOKEN_AND, 'and', 9),
            (LicenseSymbol(key='gpl', known=False), u' gpl', 12)
        ]
        assert expected == list(licensing.tokenize(' ( mit ) and gpl'))

    def test_tokenize_plain2(self):
        licensing = Licensing()
        expected = [
            (TOKEN_LPAR, '(', 0),
            (LicenseSymbol(key='mit', known=False), 'mit ', 1),
            (TOKEN_AND, 'and', 5),
            (LicenseSymbol(key='gpl', known=False), ' gpl', 8),
            (TOKEN_RPAR, ')', 12)
        ]
        assert expected == list(licensing.tokenize('(mit and gpl)'))

    def test_tokenize_plain3(self):
        licensing = Licensing()
        expected = [
            (LicenseSymbol(key='mit', known=False), 'mit ', 0),
            (TOKEN_AND, 'AND', 4),
            (LicenseSymbol(key='gpl', known=False), ' gpl ', 7),
            (TOKEN_OR, 'or', 12),
            (LicenseSymbol(key='gpl', known=False), ' gpl', 14)
        ]
        assert expected == list(licensing.tokenize('mit AND gpl or gpl'))

    def test_tokenize_plain4(self):
        licensing = Licensing()
        expected = [
            (TOKEN_LPAR, '(', 0),
            (TOKEN_LPAR, '(', 1),
            (LicenseSymbol(key='l-a +', known=False), 'l-a + ', 2),
            (TOKEN_AND, 'AND', 8),
            (LicenseSymbol(key='l-b', known=False), ' l-b', 11),
            (TOKEN_RPAR, ')', 15),
            (TOKEN_OR, 'OR', 17),
            (TOKEN_LPAR, '(', 20),
            (LicenseSymbol(key='l -c+', known=False), 'l -c+', 21),
            (TOKEN_RPAR, ')', 26),
            (TOKEN_RPAR, ')', 27)
        ]
        assert expected == list(licensing.tokenize('((l-a + AND l-b) OR (l -c+))'))

    def test_tokenize_plain5(self):
        licensing = Licensing()
        expected = [
            (TOKEN_LPAR, '(', 0),
            (TOKEN_LPAR, '(', 1),
            (LicenseSymbol(key='l-a +', known=False), 'l-a + ', 2),
            (TOKEN_AND, 'AND', 8),
            (LicenseSymbol(key='l-b', known=False), ' l-b', 11),
            (TOKEN_RPAR, ')', 15),
            (TOKEN_OR, 'OR', 17),
            (TOKEN_LPAR, '(', 20),
            (LicenseSymbol(key='l -c+', known=False), 'l -c+', 21),
            (TOKEN_RPAR, ')', 26),
            (TOKEN_RPAR, ')', 27),
            (TOKEN_AND, 'and', 29),
            (LicenseWithExceptionSymbol(
                license_symbol=LicenseSymbol(key='gpl', known=False),
                exception_symbol=ExceptionSymbol(key='classpath exception', known=False)),
             ' gpl  with  classpath exception', 32
            )
        ]
        assert expected == list(licensing.tokenize('((l-a + AND l-b) OR (l -c+)) and gpl with classpath exception'))

    def get_symbols(self):
        gpl_20 = LicenseSymbol('gpl-2.0', 'GPL-2.0', ['The GNU GPL 20'], known=True)
        gpl_20_plus = LicenseSymbol(
            'gpl-2.0+', 'GPL-2.0 or later',
            ['The GNU GPL 20 or later', 'GPL-2.0 or later', 'GPL v2.0 or later'], known=True)
        lgpl_21 = LicenseSymbol('lgpl-2.1', 'LGPL-2.1', ['LGPL v2.1'], known=True)
        mit = LicenseSymbol('mit', 'MIT', ['MIT license'], known=True)
        symbols = [gpl_20, gpl_20_plus, lgpl_21, mit]
        licensing = Licensing(symbols)
        return gpl_20, gpl_20_plus, lgpl_21, mit, licensing

    def test_tokenize_1(self):
        gpl_20, _gpl_20_plus, lgpl_21, mit, licensing = self.get_symbols()
        result = licensing.tokenize('The GNU GPL 20 or LGPL-2.1 and mit')
        expected = [
            (gpl_20, 'The GNU GPL 20', 0),
            (TOKEN_OR, 'or', 15),
            (lgpl_21, 'LGPL-2.1', 18),
            (TOKEN_AND, 'and', 27),
            (mit, 'mit', 31)]
        assert expected == list(result)

    def test_tokenize_with_trailing_unknonw(self):
        gpl_20, _gpl_20_plus, lgpl_21, mit, licensing = self.get_symbols()
        result = licensing.tokenize('The GNU GPL 20 or LGPL-2.1 and mit2')
        expected = [
            (gpl_20, 'The GNU GPL 20', 0),
            (TOKEN_OR, 'or', 15),
            (lgpl_21, 'LGPL-2.1', 18),
            (TOKEN_AND, 'and', 27),
            (mit, 'mit', 31),
            (LicenseSymbol(key=u'2', known=False), u'2', 34)
        ]
        assert expected == list(result)

    def test_tokenize_3(self):
        gpl_20, gpl_20_plus, lgpl_21, mit, licensing = self.get_symbols()
        result = licensing.tokenize('The GNU GPL 20 or later or (LGPL-2.1 and mit) or The GNU GPL 20 or mit 123')
        expected = [
            (gpl_20_plus, 'The GNU GPL 20 or later', 0),
            (TOKEN_OR, 'or', 24),
            (TOKEN_LPAR, '(', 27),
            (lgpl_21, 'LGPL-2.1', 28),
            (TOKEN_AND, 'and', 37),
            (mit, 'mit', 41),
            (TOKEN_RPAR, ')', 44),
            (TOKEN_OR, 'or', 46),
            (gpl_20, 'The GNU GPL 20', 49),
            (TOKEN_OR, 'or', 64),
            (mit, 'mit', 67),
            (LicenseSymbol(key='123', aliases=(), known=False), ' 123', 70)
        ]
        assert expected == list(result)

    def test_tokenize_unknown_as_trailing_single_attached_character(self):
        symbols = [LicenseSymbol('mit', 'MIT', ['MIT license'])]
        l = Licensing(symbols)
        result = list(l.tokenize('mit2'))
        expected = [
            (LicenseSymbol(key='mit', name='MIT', aliases=('MIT license',), known=True), 'mit', 0),
            (LicenseSymbol(key='2', known=False), '2', 3),
        ]
        assert expected == result


class LicensingParseTest(TestCase):

    def test_parse_does_not_raise_error_for_empty_expression(self):
        licensing = Licensing()
        assert None == licensing.parse('')

    def test_parse(self):
        expression = ' ( (( gpl and bsd ) or lgpl)  and gpl-exception) '
        expected = '((gpl AND bsd) OR lgpl) AND gpl-exception'
        licensing = Licensing()
        self.assertEqual(expected, str(licensing.parse(expression)))

    def test_parse_raise_ParseError(self):
        expression = ' ( (( gpl and bsd ) or lgpl)  and gpl-exception)) '
        licensing = Licensing()
        try:
            licensing.parse(expression)
            self.fail('ParseError should be raised')
        except ParseError as pe:
            expected = {'error_code': PARSE_UNBALANCED_CLOSING_PARENS, 'position': 48, 'token_string': ')', 'token_type': TOKEN_RPAR}
            assert expected == _parse_error_as_dict(pe)

    def get_syms_and_licensing(self):
        a = LicenseSymbol('l-a', known=True)
        ap = LicenseSymbol('l-a+', 'L-a+', ['l-a +'], known=True)
        b = LicenseSymbol('l-b', known=True)
        c = LicenseSymbol('l-c', known=True)
        symbols = [a, ap, b, c]
        return a, ap, b, c, Licensing(symbols)

    def test_parse_license_expression1(self):
        a, _ap, _b, _c, licensing = self.get_syms_and_licensing()
        express_string = 'l-a'
        result = licensing.parse(express_string)
        assert express_string == str(result)
        expected = a
        assert expected == result
        assert [] == licensing.unknown_keys(result)

    def test_parse_license_expression_with_alias(self):
        _a, ap, _b, _c, licensing = self.get_syms_and_licensing()
        express_string = 'l-a +'
        result = licensing.parse(express_string)
        assert 'l-a+' == str(result)
        expected = ap
        assert expected == result
        assert [] == licensing.unknown_keys(result)

    def test_parse_license_expression3(self):
        _a, ap, _b, _c, licensing = self.get_syms_and_licensing()
        express_string = 'l-a+'
        result = licensing.parse(express_string)
        assert express_string == str(result)
        expected = ap
        assert expected == result
        assert [] == licensing.unknown_keys(result)

    def test_parse_license_expression4(self):
        _a, _ap, _b, _c, licensing = self.get_syms_and_licensing()
        express_string = '(l-a)'
        result = licensing.parse(express_string)
        assert 'l-a' == str(result)
        expected = LicenseSymbol(key=u'l-a', name=u'l-a', aliases=(), known=True)
        assert expected == result
        assert [] == licensing.unknown_keys(result)

    def test_parse_license_expression5(self):
        _a, ap, b, c, licensing = self.get_syms_and_licensing()
        express_string = '((l-a+ AND l-b) OR (l-c))'
        result = licensing.parse(express_string)
        assert '(l-a+ AND l-b) OR l-c' == str(result)
        expected = licensing.OR(licensing.AND(ap, b), c)
        assert expected == result
        assert [] == licensing.unknown_keys(result)

    def test_parse_license_expression6(self):
        a, _ap, b, _c, licensing = self.get_syms_and_licensing()
        express_string = 'l-a and l-b'
        result = licensing.parse(express_string)
        assert 'l-a AND l-b' == str(result)
        expected = licensing.AND(a, b)
        assert expected == result
        assert [] == licensing.unknown_keys(result)

    def test_parse_license_expression7(self):
        a, _ap, b, _c, licensing = self.get_syms_and_licensing()
        express_string = 'l-a or l-b'
        result = licensing.parse(express_string)
        assert 'l-a OR l-b' == str(result)
        expected = licensing.OR(a, b)
        assert expected == result
        assert [] == licensing.unknown_keys(result)

    def test_parse_license_expression8(self):
        a, _ap, b, c, licensing = self.get_syms_and_licensing()
        express_string = 'l-a and l-b OR l-c'
        result = licensing.parse(express_string)
        assert '(l-a AND l-b) OR l-c' == str(result)
        expected = licensing.OR(licensing.AND(a, b), c)
        assert expected == result
        assert [] == licensing.unknown_keys(result)

    def test_parse_license_expression8_twice(self):
        _a, _ap, _b, _c, licensing = self.get_syms_and_licensing()
        express_string = 'l-a and l-b OR l-c'
        result = licensing.parse(express_string)
        assert '(l-a AND l-b) OR l-c' == str(result)
        # there was some issues with reusing a Licensing
        result = licensing.parse(express_string)
        assert '(l-a AND l-b) OR l-c' == str(result)

    def test_parse_license_expression_with_trailing_space_plus(self):
        symbols = [
            LicenseSymbol('l-a', known=True),
            LicenseSymbol('l-a+', 'L-a+', ['l-a +'], known=True),
            LicenseSymbol('l-b', known=True),
            LicenseSymbol('l-c', known=True),
        ]
        licensing = Licensing(symbols)

        expresssion_str = 'l-a'
        result = licensing.parse(expresssion_str)
        assert expresssion_str == str(result)
        assert [] == licensing.unknown_keys(result)

        # plus sign is not attached to the symbol, but an alias
        expresssion_str = 'l-a +'
        result = licensing.parse(expresssion_str)
        assert 'l-a+' == str(result).lower()
        assert [] == licensing.unknown_keys(result)

        expresssion_str = '(l-a)'
        result = licensing.parse(expresssion_str)
        assert 'l-a' == str(result).lower()
        assert [] == licensing.unknown_keys(result)

        expresssion_str = '((l-a+ AND l-b) OR (l-c))'
        result = licensing.parse(expresssion_str)
        assert '(l-a+ AND l-b) OR l-c' == str(result)
        assert [] == licensing.unknown_keys(result)

        expresssion_str = 'l-a and l-b'
        result = licensing.parse(expresssion_str)
        assert 'l-a AND l-b' == str(result)
        assert [] == licensing.unknown_keys(result)

        expresssion_str = 'l-a or l-b'
        result = licensing.parse(expresssion_str)
        assert 'l-a OR l-b' == str(result)
        assert [] == licensing.unknown_keys(result)

        expresssion_str = 'l-a and l-b OR l-c'
        result = licensing.parse(expresssion_str)
        assert '(l-a AND l-b) OR l-c' == str(result)
        assert [] == licensing.unknown_keys(result)

    def test_parse_invalid_expression_raise_expression(self):
        licensing = Licensing()

        expr = 'wrong'
        licensing.parse(expr)

        expr = 'l-a AND none'
        licensing.parse(expr)

        expr = '(l-a + AND l-b'
        try:
            licensing.parse(expr)
            self.fail("Exception not raised when validating '%s'" % expr)
        except (ExpressionError, ParseError):
            pass

        expr = '(l-a + AND l-b))'
        try:
            licensing.parse(expr)
            self.fail("Exception not raised when validating '%s'" % expr)
        except (ExpressionError, ParseError):
            pass

        expr = 'l-a AND'
        try:
            licensing.parse(expr)
            self.fail("Exception not raised when validating '%s'" % expr)
        except (ExpressionError, ParseError):
            pass

        expr = 'OR l-a'
        try:
            licensing.parse(expr)
            self.fail("Exception not raised when validating '%s'" % expr)
        except (ExpressionError, ParseError):
            pass

        expr = '+ l-a'
        licensing.parse(expr)

    def test_parse_can_parse(self):
        licensing = Licensing()
        expr = licensing.parse(' GPL-2.0 or LGPL 2.1 and mit ')
        gpl2 = LicenseSymbol(key='gpl-2.0', name='GPL-2.0', known=False)
        lgpl = LicenseSymbol(key='lgpl 2.1', name='LGPL 2.1', known=False)
        mit = LicenseSymbol(key='mit', name='mit', known=False)
        expected = [gpl2, lgpl, mit]
        self.assertEqual(expected, licensing.get_license_symbols(expr))
        self.assertEqual('gpl-2.0 OR (lgpl 2.1 AND mit)', str(expr))

        expected = licensing.OR(gpl2, licensing.AND(lgpl, mit))
        assert expected == expr

    def test_parse_errors_catch_invalid_nesting(self):
        licensing = Licensing()
        try:
            licensing.parse('mit (and LGPL 2.1)')
            self.fail('Exception not raised')
        except ParseError as pe:
            expected = {'error_code': PARSE_INVALID_NESTING, 'position': 4, 'token_string': '(', 'token_type': TOKEN_LPAR}
            assert expected == _parse_error_as_dict(pe)

    def test_parse_errors_catch_invalid_expression_with_bare_and(self):
        licensing = Licensing()
        try:
            licensing.parse('and')
            self.fail('Exception not raised')
        except ParseError as pe:
            expected = {'error_code': PARSE_INVALID_EXPRESSION, 'position':-1, 'token_string': '', 'token_type': None}
            assert expected == _parse_error_as_dict(pe)

    def test_parse_errors_catch_invalid_expression_with_or_and_no_other(self):
        licensing = Licensing()
        try:
            licensing.parse('or that')
            self.fail('Exception not raised')
        except ParseError as pe:
            expected = {'error_code': PARSE_INVALID_EXPRESSION, 'position':-1, 'token_string': '', 'token_type': None}
            assert expected == _parse_error_as_dict(pe)

    def test_parse_errors_catch_invalid_expression_with_empty_parens(self):
        licensing = Licensing()
        try:
            licensing.parse('with ( )this')
            self.fail('Exception not raised')
        except ParseError as pe:
            expected = {'error_code': PARSE_INVALID_EXPRESSION, 'position': 0, 'token_string':  'with', 'token_type': TOKEN_WITH}
            assert expected == _parse_error_as_dict(pe)

    def test_parse_errors_catch_invalid_non_unicode_byte_strings(self):
        py2 = sys.version_info[0] == 2
        py3 = sys.version_info[0] == 3

        licensing = Licensing()

        if py2:
            extra_bytes = bytes(chr(0) + chr(12) + chr(255))
        if py3:
            extra_bytes = bytes(chr(0) + chr(12) + chr(255), encoding='utf-8')

        try:
            licensing.parse('mit (and LGPL 2.1)'.encode('utf-8') + extra_bytes)
            self.fail('Exception not raised')
        except ExpressionError as pe:
            assert str(pe).startswith('expression must be one of')

    def test_parse_errors_does_not_raise_error_on_plain_non_unicode_raw_string(self):
        # plain non-unicode string does not raise error
        licensing = Licensing()
        x = licensing.parse(r'mit and (LGPL 2.1)')
        self.assertTrue(isinstance(x, LicenseExpression))

    def test_parse_simplify_and_contain_and_equal(self):
        licensing = Licensing()

        expr = licensing.parse(' GPL-2.0 or LGPL 2.1 and mit ')

        expr2 = licensing.parse(' (mit and LGPL 2.1) or GPL-2.0 ')
        self.assertEqual(expr2.simplify(), expr.simplify())
        self.assertEqual(expr2, expr)

        expr3 = licensing.parse('mit and LGPL 2.1')
        self.assertTrue(expr3 in expr2)

    def test_parse_trailing_char_raise_exception(self):
        _gpl2, _gpl2plus, _lgpl, _mit, licensing = self.get_symbols_and_licensing()
        try:
            licensing.parse('The GNU GPL 20 or LGPL-2.1 and mit2')
        except ParseError as pe:
            expected = {'error_code': PARSE_INVALID_SYMBOL_SEQUENCE, 'position': 34,
                        'token_string': '2', 'token_type': LicenseSymbol('2', known=False)}
            assert expected == _parse_error_as_dict(pe)

    def test_parse_expression_with_trailing_unknown_should_raise_exception(self):
        gpl2, gpl2plus, lgpl, mit, licensing = self.get_symbols_and_licensing()
        unknown = LicenseSymbol(key='123', known=False)

        tokens = list(licensing.tokenize('The GNU GPL 20 or later or (LGPL-2.1 and mit) or The GNU GPL 20 or mit 123'))
        expected = [
            (gpl2plus, 'The GNU GPL 20 or later', 0),
            (TOKEN_OR, 'or', 24),
            (TOKEN_LPAR, '(', 27),
            (lgpl, 'LGPL-2.1', 28),
            (TOKEN_AND, 'and', 37),
            (mit, 'mit', 41),
            (TOKEN_RPAR, ')', 44),
            (TOKEN_OR, 'or', 46),
            (gpl2, 'The GNU GPL 20', 49),
            (TOKEN_OR, 'or', 64),
            (mit, 'mit', 67),
            (unknown, ' 123', 70)
        ]
        assert expected == tokens

        try:
            licensing.parse('The GNU GPL 20 or later or (LGPL-2.1 and mit) or The GNU GPL 20 or mit 123')
        except ParseError as pe:
            expected = {'error_code': PARSE_INVALID_SYMBOL_SEQUENCE, 'position': 70,
                        'token_string': ' 123', 'token_type': unknown}
            assert expected == _parse_error_as_dict(pe)

    def test_parse_expression_with_trailing_unknown_should_raise_exception2(self):
        _gpl2, _gpl2plus, _lgpl, _mit, licensing = self.get_symbols_and_licensing()
        unknown = LicenseSymbol(key='123', known=False)
        try:
            licensing.parse('The GNU GPL 20 or mit 123')
        except ParseError as pe:
            expected = {'error_code': PARSE_INVALID_SYMBOL_SEQUENCE, 'position': 21,
                        'token_string': ' 123', 'token_type': unknown}
            assert expected == _parse_error_as_dict(pe)

    def test_parse_expression_with_WITH(self):
        gpl2, gpl2plus, lgpl, mit, licensing = self.get_symbols_and_licensing()
        tokens = list(licensing.tokenize('The GNU GPL 20 or later or (LGPL-2.1 and mit) or The GNU GPL 20 or mit with 123'))
        expected = [
            (gpl2plus, u'The GNU GPL 20 or later', 0),
            (2, u'or', 24),
            (4, u'(', 27),
            (lgpl, u'LGPL-2.1', 28),
            (1, u'and', 37),
            (mit, u'mit', 41),
            (5, u')', 44),
            (2, u'or', 46),
            (gpl2, u'The GNU GPL 20', 49),
            (2, u'or', 64),
            (LicenseWithExceptionSymbol(mit, ExceptionSymbol(key=u'123', known=False)), u'mit with  123', 67)
        ]
        assert expected == tokens

        expr = licensing.parse('The GNU GPL 20 or later or (LGPL-2.1 and mit) or The GNU GPL 20 or mit with 123')
        expected = 'gpl-2.0+ OR (lgpl-2.1 AND mit) OR gpl-2.0 OR mit WITH 123'
        assert expected == str(expr)
        assert ['123'] == licensing.unknown_keys(expr)

    def test_parse_of_side_by_side_symbols_raise_exception(self):
        gpl2 = LicenseSymbol('gpl')
        l = Licensing([gpl2])
        try:
            l.parse('gpl mit')
            self.fail('ParseError not raised')
        except ParseError:
            pass

    def test_license_expression_is_equivalent(self):
        is_equivalent = Licensing().is_equivalent

        self.assertTrue(is_equivalent('mit AND gpl', 'mit AND gpl'))
        self.assertTrue(is_equivalent('mit AND gpl', 'gpl AND mit'))
        self.assertTrue(is_equivalent('mit AND gpl and apache', 'apache and gpl AND mit'))
        self.assertTrue(is_equivalent('mit AND (gpl AND apache)', '(mit AND gpl) AND apache'))

        # Real-case example of generated expression vs. stored expression:
        ex1 = '''Commercial
            AND apache-1.1 AND apache-2.0 AND aslr AND bsd-new
            AND cpl-1.0 AND epl-1.0
            AND ibm-icu AND ijg AND jdom AND lgpl-2.1
            AND mit-open-group AND mpl-1.1 AND sax-pd AND unicode AND w3c AND
            w3c-documentation'''

        ex2 = '''
            apache-1.1 AND apache-2.0 AND aslr AND bsd-new
            AND cpl-1.0 AND epl-1.0
            AND lgpl-2.1 AND ibm-icu AND ijg
            AND jdom AND mit-open-group
            AND mpl-1.1 AND Commercial AND sax-pd AND unicode
            AND w3c-documentation AND w3c'''

        self.assertTrue(is_equivalent(ex1, ex2))
        self.assertFalse(is_equivalent('mit AND gpl', 'mit OR gpl'))
        self.assertFalse(is_equivalent('mit AND gpl', 'gpl OR mit'))

    def test_validate_symbols(self):
        symbols = [
            LicenseSymbol('l-a'),
            LicenseSymbol('l-a+', 'L-a+', ['l-a +']),
            ExceptionSymbol('l-a+'),
            LicenseSymbol('l-b'),
            LicenseSymbol('l-c'),
        ]
        warnings, errors = validate_symbols(symbols)
        expectedw = []
        assert expectedw == warnings
        expectede = [
            'Invalid duplicated license key: l-a+.',
            'Invalid duplicated license name: l-a+.'
        ]
        assert expectede == errors

    def test_license_expression_license_keys(self):
        licensing = Licensing()
        self.assertEqual(['mit', 'gpl'], licensing.license_keys(' ( mit ) and gpl'))
        self.assertEqual(['mit', 'gpl'], licensing.license_keys('(mit and gpl)'))
        # these two are surprising for now: this is because the expression is a
        # logical expression so the order may be different on more complex expressions
        self.assertEqual(['mit', 'gpl'], licensing.license_keys('mit AND gpl or gpl'))
        self.assertEqual(['l-a +', 'l-b', 'l -c+'], licensing.license_keys('((l-a + AND l-b) OR (l -c+))'))

    def get_symbols_and_licensing(self):
        gpl2 = LicenseSymbol('gpl-2.0', 'GPL-2.0', ['The GNU GPL 20'])
        gpl2plus = LicenseSymbol('gpl-2.0+', 'GPL-2.0 or later', ['The GNU GPL 20 or later', 'GPL-2.0 or later', 'GPL v2.0 or later'])
        lgpl = LicenseSymbol('lgpl-2.1', 'LGPL-2.1', ['LGPL v2.1'])
        mit = LicenseSymbol('mit', 'MIT', ['MIT license'])
        symbols = [gpl2, gpl2plus, lgpl, mit]
        licensing = Licensing(symbols)
        return gpl2, gpl2plus, lgpl, mit, licensing

    def test_unknown_keys(self):
        _gpl2, _gpl2plus, _lgpl, _mit, licensing = self.get_symbols_and_licensing()
        expr = licensing.parse('The GNU GPL 20 or LGPL-2.1 and mit')
        expected = 'gpl-2.0 OR (lgpl-2.1 AND mit)'
        assert expected == str(expr)
        assert [] == licensing.unknown_keys(expr)

    def test_unknown_keys_with_trailing_char(self):
        gpl2, _gpl2plus, lgpl, mit, licensing = self.get_symbols_and_licensing()
        expr = licensing.parse('The GNU GPL 20 or LGPL-2.1 and mitand2')
        expected = [gpl2, lgpl, mit, LicenseSymbol(key='2', known=False)]
        assert expected == licensing.get_license_symbols(expr)
        assert ['2'] == licensing.unknown_keys(expr)

    def test_end_to_end(self):
        # these were formerly doctest portedd to actual real code tests here
        l = Licensing()
        expr = l.parse(' GPL-2.0 or LGPL 2.1 and mit ')
        expected = 'gpl-2.0 OR (lgpl 2.1 AND mit)'
        assert expected == str(expr)

        expected = [
            LicenseSymbol('GPL-2.0', known=False),
            LicenseSymbol('LGPL 2.1', known=False),
            LicenseSymbol('mit', known=False),
        ]
        assert expected == l.get_license_symbols(expr)

    def test_pretty(self):
        l = Licensing()
        expr = l.parse(' GPL-2.0 or LGPL 2.1 and mit ')

        expected = '''OR(
  LicenseSymbol('gpl-2.0'),
  AND(
    LicenseSymbol('lgpl 2.1'),
    LicenseSymbol('mit')
  )
)'''
        assert expected == expr.pretty()

    def test_simplify_and_contains(self):
        l = Licensing()

        expr = l.parse(' GPL-2.0 or LGPL 2.1 and mit ')
        expr2 = l.parse(' GPL-2.0 or (mit and LGPL 2.1) ')
        assert expr2.simplify() == expr.simplify()
        expr3 = l.parse('mit and LGPL 2.1')
        assert expr3 in expr2

    def test_simplify_and_equivalent_and_contains(self):
        l = Licensing()
        expr2 = l.parse(' GPL-2.0 or (mit and LGPL 2.1) or bsd Or GPL-2.0  or (mit and LGPL 2.1)')
        # note thats simplification does SORT the symbols such that they can
        # eventually be compared sequence-wise. This sorting is based on license key
        expected = 'bsd OR gpl-2.0 OR (lgpl 2.1 AND mit)'
        assert expected == str(expr2.simplify())

        # Two expressions can be compared for equivalence:
        expr1 = l.parse(' GPL-2.0 or (LGPL 2.1 and mit) ')
        assert 'gpl-2.0 OR (lgpl 2.1 AND mit)' == str(expr1)
        expr2 = l.parse(' (mit and LGPL 2.1)  or GPL-2.0 ')
        assert '(mit AND lgpl 2.1) OR gpl-2.0' == str(expr2)
        assert l.is_equivalent(expr1, expr2)

        assert 'gpl-2.0 OR (lgpl 2.1 AND mit)' == str(expr1.simplify())
        assert 'gpl-2.0 OR (lgpl 2.1 AND mit)' == str(expr2.simplify())
        assert expr1.simplify() == expr2.simplify()

        expr3 = l.parse(' GPL-2.0 or mit or LGPL 2.1')
        assert not l.is_equivalent(expr2, expr3)
        expr4 = l.parse('mit and LGPL 2.1')
        assert expr4.simplify() in expr2.simplify()

        assert l.contains(expr2, expr4)

    def test_create_from_python(self):
        # Expressions can be built from Python expressions, using bitwise operators
        # between Licensing objects, but use with caution. The behavior is not as
        # well specified that using text expression and parse

        licensing = Licensing()
        expr1 = (licensing.LicenseSymbol('GPL-2.0')
                 | (licensing.LicenseSymbol('mit')
                    & licensing.LicenseSymbol('LGPL 2.1')))
        expr2 = licensing.parse(' GPL-2.0 or (mit and LGPL 2.1) ')

        assert 'gpl-2.0 OR (lgpl 2.1 AND mit)' == str(expr1.simplify())
        assert 'gpl-2.0 OR (lgpl 2.1 AND mit)' == str(expr2.simplify())

        # WARNING: this is surprising and is due to some type wrapping happening in
        # .py
        assert not licensing.is_equivalent(expr1, expr2)

        a = licensing.OR(
            LicenseSymbol(key=u'gpl-2.0'),
            licensing.AND(LicenseSymbol(key=u'mit'),
                LicenseSymbol(key=u'lgpl 2.1')
                )
            )
        b = licensing.OR(
             LicenseSymbol(key=u'gpl-2.0'),
             licensing.AND(LicenseSymbol(key=u'mit'),
                 LicenseSymbol(key=u'lgpl 2.1')
                 )
            )
        assert a == b

    def test_get_license_symbols(self):
        l = Licensing()
        expected = [
            LicenseSymbol('GPL-2.0', known=False),
            LicenseSymbol('mit', known=False),
            LicenseSymbol('LGPL 2.1', known=False)
        ]
        assert expected == l.get_license_symbols(' GPL-2.0 and mit or LGPL 2.1 and mit ')

    def test_get_license_symbols2(self):
        l = Licensing()
        expected = [
            LicenseSymbol('GPL-2.0', known=False),
            LicenseSymbol('LATER', known=False),
            LicenseSymbol('mit', known=False),
            LicenseSymbol('LGPL 2.1+', known=False),
            LicenseSymbol('mit', known=False),
            ExceptionSymbol('Foo exception', known=False),
        ]
        expr = ' GPL-2.0 or LATER and mit or LGPL 2.1+ and mit with Foo exception '
        assert expected == l.get_license_symbols(expr, unique=False)

    def test_get_license_symbols3(self):
        l = Licensing()
        expected = [
            LicenseSymbol('mit', known=False),
            LicenseSymbol('LGPL 2.1+', known=False),
            ExceptionSymbol('Foo exception', known=False),
            LicenseSymbol('GPL-2.0', known=False),
            LicenseSymbol('LATER', known=False),
        ]
        expr = 'mit or LGPL 2.1+ and mit with Foo exception or GPL-2.0 or LATER '
        assert expected == l.get_license_symbols(expr)

    def test_get_license_symbols4(self):
        l = Licensing()
        expected = [
            LicenseSymbol('GPL-2.0', known=False),
            LicenseSymbol('LATER', known=False),
            ExceptionSymbol('big exception', known=False),
            LicenseSymbol('mit', known=False),
            LicenseSymbol('LGPL 2.1+', known=False),
            LicenseSymbol('later', known=False),
            LicenseSymbol('mit', known=False),
            LicenseSymbol('later', known=False),
            ExceptionSymbol('Foo exception', known=False),
        ]
        expr = (' GPL-2.0 or LATER with big exception and mit or '
                'LGPL 2.1+ or later and mit or later with Foo exception ')
        assert expected == l.get_license_symbols(expr, unique=False)

    def test_render_complex(self):
        licensing = Licensing()
        expression = '''
        EPL 1.0 AND Apache 1.1 AND Apache 2.0 AND BSD-Modified AND CPL 1.0 AND
        ICU Composite License AND JPEG License AND JDOM License AND LGPL 2.0 AND
        MIT Open Group AND MPL 1.1 AND SAX-PD AND Unicode Inc License Agreement
        AND W3C Software Notice and License AND W3C Documentation License'''

        result = licensing.parse(expression)
        expected = ('EPL 1.0 AND Apache 1.1 AND Apache 2.0 AND BSD-Modified '
        'AND CPL 1.0 AND ICU Composite License AND JPEG License '
        'AND JDOM License AND LGPL 2.0 AND MIT Open Group AND MPL 1.1 '
        'AND SAX-PD AND Unicode Inc License Agreement '
        'AND W3C Software Notice AND License AND W3C Documentation License')

        print(result.render('{name}'))
        assert expected == result.render('{name}')
        expectedkey = ('epl 1.0 AND apache 1.1 AND apache 2.0 AND bsd-modified '
        'AND cpl 1.0 AND icu composite license AND jpeg license AND jdom license '
        'AND lgpl 2.0 AND mit open group AND mpl 1.1 AND sax-pd AND '
        'unicode inc license agreement AND w3c software notice AND license '
        'AND w3c documentation license')
        assert expectedkey == result.render('{key}')

    def test_render_with(self):
        licensing = Licensing()
        expression = 'GPL 2.0 with Classpath 2.0 OR BSD-new'
        result = licensing.parse(expression)

        expected = 'GPL 2.0 WITH Classpath 2.0'
        assert expected == result.render('{name}')

        expected_html = '<a href="path/gpl 2.0">GPL 2.0</a> WITH <a href="path/classpath 2.0">Classpath 2.0</a>'
        assert expected_html == result.render('<a href="path/{key}">{name}</a>')

        expected = 'gpl 2.0 WITH classpath 2.0'
        assert expected == result.render('{key}')

    def test_parse_complex(self):
        licensing = Licensing()
        expression = ' GPL-2.0 or later with classpath Exception and mit or  LPL 2.1 and mit or later '
        result = licensing.parse(expression)
        # this may look weird, but we did not provide symbols hence in "or later",
        # "later" is treated as if it were a license
        expected = 'gpl-2.0 OR (later WITH classpath exception AND mit) OR (lpl 2.1 AND mit) OR later'
        assert expected == result.render('{key}')

        licensing = Licensing()
        expr = licensing.parse(" GPL-2.0 or LGPL 2.1 and mit ")
        expected = [
            LicenseSymbol('GPL-2.0', known=False),
            LicenseSymbol('LGPL 2.1', known=False),
            LicenseSymbol('mit', known=False)
        ]
        assert expected == sorted(licensing.get_license_symbols(expr))
        expected = 'GPL-2.0 OR (LGPL 2.1 AND mit)'
        assert expected == expr.render('{name}')

    def test_get_symbols_and_literals(self):
        raise Exception()

    def test_primary_key(self):
        l = Licensing()

        expr = " GPL-2.0 with classpath Exception and mit or LGPL 2.1 and mit or later "
        expected = 'GPL-2.0 WITH classpath Exception'
        assert expected == l.primary_license(expr)

        expr = " GPL-2.0 or later and mit or LGPL 2.1 and mit or later "
        expected = 'GPL-2.0 or later'
        assert expected == l.primary_license(expr)

        expr = " GPL-2.0 or later with classpath Exception and mit or LGPL 2.1 and mit or later "
        expected = 'GPL-2.0 or later WITH classpath Exception'
        assert expected == l.primary_license(expr)


def _parse_error_as_dict(pe):
    """
    Return a dict for a ParseError.
    """
    return dict(
        token_type=pe.token_type,
        token_string=pe.token_string,
        position=pe.position,
        error_code=pe.error_code,
    )
