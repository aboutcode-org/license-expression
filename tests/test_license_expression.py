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

from license_expression import TOKEN_WITH
from license_expression import PARSE_INVALID_EXPRESSION
from license_expression import PARSE_INVALID_NESTING

from license_expression import ExpressionError
from license_expression import Keyword
from license_expression import Licensing
from license_expression import LicenseExpression
from license_expression import LicenseSymbol
from license_expression import LicenseWithExceptionSymbol
from license_expression import ParseError
from license_expression import strip_and_skip_spaces
from license_expression import validate_symbols
from license_expression import group_results_for_with_subexpression


class LicenseSymbolTest(TestCase):

    def test_LicenseSymbol(self):
        sym1 = LicenseSymbol('MIT', ['MIT license'])
        assert sym1 == sym1
        assert 'mit' == sym1.key
        assert 'MIT' == sym1.original_key
        assert ('MIT license',) == sym1.aliases

        sym2 = LicenseSymbol('mit', ['MIT license'])
        assert 'mit' == sym2.key
        assert 'mit' == sym2.original_key
        assert ('MIT license',) == sym2.aliases
        assert not sym2.is_exception
        assert sym1 == sym2
        assert sym1 is not sym2

        sym3 = LicenseSymbol('mit', ['MIT license'], is_exception=True)
        assert 'mit' == sym3.key
        assert ('MIT license',) == sym3.aliases
        assert sym3.is_exception
        assert sym1 == sym3

        sym4 = LicenseSymbol('mit', ['MIT license'])
        assert 'mit' == sym4.key
        assert ('MIT license',) == sym4.aliases
        # symbol euqality is based ONLY on the key
        assert sym1 == sym4

        sym5 = LicenseWithExceptionSymbol(sym1, sym3)
        assert sym1 == sym5.license_symbol
        assert sym3 == sym5.exception_symbol

        sym6 = LicenseWithExceptionSymbol(sym4, sym3)
        # symbol euqality is based ONLY on the key
        assert sym5 == sym6


class LicensingTokenizeTest(TestCase):

    def test_tokenize_plain1(self):
        licensing = Licensing()
        expected = [
            (TOKEN_LPAR, '(', 1),
            (LicenseSymbol(key='mit'), u' mit ', 2),
            (TOKEN_RPAR, ')', 7),
            (TOKEN_AND, 'and', 9),
            (LicenseSymbol(key='gpl'), u' gpl', 12)
        ]
        assert expected == list(licensing.tokenize(' ( mit ) and gpl'))

    def test_tokenize_plain2(self):
        licensing = Licensing()
        expected = [
            (TOKEN_LPAR, '(', 0),
            (LicenseSymbol(key='mit'), 'mit ', 1),
            (TOKEN_AND, 'and', 5),
            (LicenseSymbol(key='gpl'), ' gpl', 8),
            (TOKEN_RPAR, ')', 12)
        ]
        assert expected == list(licensing.tokenize('(mit and gpl)'))

    def test_tokenize_plain3(self):
        licensing = Licensing()
        expected = [
            (LicenseSymbol(key='mit'), 'mit ', 0),
            (TOKEN_AND, 'AND', 4),
            (LicenseSymbol(key='gpl'), ' gpl ', 7),
            (TOKEN_OR, 'or', 12),
            (LicenseSymbol(key='gpl'), ' gpl', 14)
        ]
        assert expected == list(licensing.tokenize('mit AND gpl or gpl'))

    def test_tokenize_plain4(self):
        licensing = Licensing()
        expected = [
            (TOKEN_LPAR, '(', 0),
            (TOKEN_LPAR, '(', 1),
            (LicenseSymbol(key='l-a +'), 'l-a + ', 2),
            (TOKEN_AND, 'AND', 8),
            (LicenseSymbol(key='l-b'), ' l-b', 11),
            (TOKEN_RPAR, ')', 15),
            (TOKEN_OR, 'OR', 17),
            (TOKEN_LPAR, '(', 20),
            (LicenseSymbol(key='l -c+'), 'l -c+', 21),
            (TOKEN_RPAR, ')', 26),
            (TOKEN_RPAR, ')', 27)
        ]
        assert expected == list(licensing.tokenize('((l-a + AND l-b) OR (l -c+))'))

    def test_tokenize_plain5(self):
        licensing = Licensing()
        expected = [
            (TOKEN_LPAR, '(', 0),
            (TOKEN_LPAR, '(', 1),
            (LicenseSymbol(key='l-a +'), 'l-a + ', 2),
            (TOKEN_AND, 'AND', 8),
            (LicenseSymbol(key='l-b'), ' l-b', 11),
            (TOKEN_RPAR, ')', 15),
            (TOKEN_OR, 'OR', 17),
            (TOKEN_LPAR, '(', 20),
            (LicenseSymbol(key='l -c+'), 'l -c+', 21),
            (TOKEN_RPAR, ')', 26),
            (TOKEN_RPAR, ')', 27),
            (TOKEN_AND, 'and', 29),
            (LicenseWithExceptionSymbol(
                license_symbol=LicenseSymbol(key='gpl'),
                exception_symbol=LicenseSymbol(key='classpath exception', is_exception=True)),
             ' gpl  with  classpath exception', 32
            )
        ]
        assert expected == list(licensing.tokenize('((l-a + AND l-b) OR (l -c+)) and gpl with classpath exception'))

    def get_symbols(self):
        gpl_20 = LicenseSymbol('GPL-2.0', ['The GNU GPL 20'])
        gpl_20_plus = LicenseSymbol('gpl-2.0+',
            ['The GNU GPL 20 or later', 'GPL-2.0 or later', 'GPL v2.0 or later'])
        lgpl_21 = LicenseSymbol('LGPL-2.1', ['LGPL v2.1'])
        mit = LicenseSymbol('MIT', ['MIT license'])
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
            (LicenseSymbol(key=u'2'), u'2', 34)
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
            (LicenseSymbol(key='123', aliases=()), ' 123', 70)
        ]
        assert expected == list(result)

    def test_tokenize_unknown_as_trailing_single_attached_character(self):
        symbols = [LicenseSymbol('MIT', ['MIT license'])]
        l = Licensing(symbols)
        result = list(l.tokenize('mit2'))
        expected = [
            (LicenseSymbol(key='MIT', aliases=('MIT license',)), 'mit', 0),
            (LicenseSymbol(key='2'), '2', 3),
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
        a = LicenseSymbol('l-a')
        ap = LicenseSymbol('L-a+', ['l-a +'])
        b = LicenseSymbol('l-b')
        c = LicenseSymbol('l-c')
        symbols = [a, ap, b, c]
        return a, ap, b, c, Licensing(symbols)

    def test_parse_license_expression1(self):
        a, _ap, _b, _c, licensing = self.get_syms_and_licensing()
        express_string = 'l-a'
        result = licensing.parse(express_string)
        assert express_string == str(result)
        expected = a
        assert expected == result
        assert [] == licensing.unknown_license_keys(result)

    def test_parse_license_expression_with_alias(self):
        _a, ap, _b, _c, licensing = self.get_syms_and_licensing()
        express_string = 'l-a +'
        result = licensing.parse(express_string)
        assert 'l-a+' == str(result)
        expected = ap
        assert expected == result
        assert [] == licensing.unknown_license_keys(result)

    def test_parse_license_expression3(self):
        _a, ap, _b, _c, licensing = self.get_syms_and_licensing()
        express_string = 'l-a+'
        result = licensing.parse(express_string)
        assert express_string == str(result)
        expected = ap
        assert expected == result
        assert [] == licensing.unknown_license_keys(result)

    def test_parse_license_expression4(self):
        _a, _ap, _b, _c, licensing = self.get_syms_and_licensing()
        express_string = '(l-a)'
        result = licensing.parse(express_string)
        assert 'l-a' == str(result)
        expected = LicenseSymbol(key=u'l-a', aliases=())
        assert expected == result
        assert [] == licensing.unknown_license_keys(result)

    def test_parse_license_expression5(self):
        _a, ap, b, c, licensing = self.get_syms_and_licensing()
        express_string = '((l-a+ AND l-b) OR (l-c))'
        result = licensing.parse(express_string)
        assert '(l-a+ AND l-b) OR l-c' == str(result)
        expected = licensing.OR(licensing.AND(ap, b), c)
        assert expected == result
        assert [] == licensing.unknown_license_keys(result)

    def test_parse_license_expression6(self):
        a, _ap, b, _c, licensing = self.get_syms_and_licensing()
        express_string = 'l-a and l-b'
        result = licensing.parse(express_string)
        assert 'l-a AND l-b' == str(result)
        expected = licensing.AND(a, b)
        assert expected == result
        assert [] == licensing.unknown_license_keys(result)

    def test_parse_license_expression7(self):
        a, _ap, b, _c, licensing = self.get_syms_and_licensing()
        express_string = 'l-a or l-b'
        result = licensing.parse(express_string)
        assert 'l-a OR l-b' == str(result)
        expected = licensing.OR(a, b)
        assert expected == result
        assert [] == licensing.unknown_license_keys(result)

    def test_parse_license_expression8(self):
        a, _ap, b, c, licensing = self.get_syms_and_licensing()
        express_string = 'l-a and l-b OR l-c'
        result = licensing.parse(express_string)
        assert '(l-a AND l-b) OR l-c' == str(result)
        expected = licensing.OR(licensing.AND(a, b), c)
        assert expected == result
        assert [] == licensing.unknown_license_keys(result)

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
            LicenseSymbol('l-a'),
            LicenseSymbol('L-a+', ['l-a +']),
            LicenseSymbol('l-b'),
            LicenseSymbol('l-c'),
        ]
        licensing = Licensing(symbols)

        expresssion_str = 'l-a'
        result = licensing.parse(expresssion_str)
        assert expresssion_str == str(result)
        assert [] == licensing.unknown_license_keys(result)

        # plus sign is not attached to the symbol, but an alias
        expresssion_str = 'l-a +'
        result = licensing.parse(expresssion_str)
        assert 'l-a+' == str(result).lower()
        assert [] == licensing.unknown_license_keys(result)

        expresssion_str = '(l-a)'
        result = licensing.parse(expresssion_str)
        assert 'l-a' == str(result).lower()
        assert [] == licensing.unknown_license_keys(result)

        expresssion_str = '((l-a+ AND l-b) OR (l-c))'
        result = licensing.parse(expresssion_str)
        assert '(l-a+ AND l-b) OR l-c' == str(result)
        assert [] == licensing.unknown_license_keys(result)

        expresssion_str = 'l-a and l-b'
        result = licensing.parse(expresssion_str)
        assert 'l-a AND l-b' == str(result)
        assert [] == licensing.unknown_license_keys(result)

        expresssion_str = 'l-a or l-b'
        result = licensing.parse(expresssion_str)
        assert 'l-a OR l-b' == str(result)
        assert [] == licensing.unknown_license_keys(result)

        expresssion_str = 'l-a and l-b OR l-c'
        result = licensing.parse(expresssion_str)
        assert '(l-a AND l-b) OR l-c' == str(result)
        assert [] == licensing.unknown_license_keys(result)

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
        gpl2 = LicenseSymbol('GPL-2.0')
        lgpl = LicenseSymbol('LGPL 2.1')
        mit = LicenseSymbol('mit')
        expected = [gpl2, lgpl, mit]
        self.assertEqual(expected, licensing.license_symbols(expr))
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

    def test_parse_errors_catch_invalid_non_unicode_byte_strings_on_python3(self):
        py2 = sys.version_info[0] == 2
        py3 = sys.version_info[0] == 3

        licensing = Licensing()

        if py2:
            extra_bytes = bytes(chr(0) + chr(12) + chr(255))
            try:
                licensing.parse('mit (and LGPL 2.1)'.encode('utf-8') + extra_bytes)
                self.fail('Exception not raised')
            except ExpressionError as pe:
                assert str(pe).startswith('expression must be a string and')

        if py3:
            extra_bytes = bytes(chr(0) + chr(12) + chr(255), encoding='utf-8')
            try:
                licensing.parse('mit (and LGPL 2.1)'.encode('utf-8') + extra_bytes)
                self.fail('Exception not raised')
            except ParseError as pe:
                expected = {'error_code': PARSE_INVALID_NESTING, 'position': 6, 'token_string': '(', 'token_type': TOKEN_LPAR}
                assert expected == _parse_error_as_dict(pe)



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
                        'token_string': '2', 'token_type': LicenseSymbol('2')}
            assert expected == _parse_error_as_dict(pe)

    def test_parse_expression_with_trailing_unknown_should_raise_exception(self):
        gpl2, gpl2plus, lgpl, mit, licensing = self.get_symbols_and_licensing()
        unknown = LicenseSymbol(key='123')

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
        unknown = LicenseSymbol(key='123')
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
            (LicenseWithExceptionSymbol(mit, LicenseSymbol(key=u'123', is_exception=True)), u'mit with  123', 67)
        ]
        assert expected == tokens

        expr = licensing.parse('The GNU GPL 20 or later or (LGPL-2.1 and mit) or The GNU GPL 20 or mit with 123')
        expected = 'gpl-2.0+ OR (lgpl-2.1 AND mit) OR gpl-2.0 OR mit WITH 123'
        assert expected == str(expr)
        assert ['123'] == licensing.unknown_license_keys(expr)

    def test_parse_of_side_by_side_symbols_raise_exception(self):
        gpl2 = LicenseSymbol('gpl')
        l = Licensing([gpl2])
        try:
            l.parse('gpl mit')
            self.fail('ParseError not raised')
        except ParseError:
            pass

    def test_license_expression_is_equivalent(self):
        lic = Licensing()
        is_equiv = lic.is_equivalent

        self.assertTrue(is_equiv(lic.parse('mit AND gpl'), lic.parse('mit AND gpl')))
        self.assertTrue(is_equiv(lic.parse('mit AND gpl'), lic.parse('gpl AND mit')))
        self.assertTrue(is_equiv(lic.parse('mit AND gpl and apache'), lic.parse('apache and gpl AND mit')))
        self.assertTrue(is_equiv(lic.parse('mit AND (gpl AND apache)'), lic.parse('(mit AND gpl) AND apache')))

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

        self.assertTrue(is_equiv(lic.parse(ex1), lic.parse(ex2)))
        self.assertFalse(is_equiv(lic.parse('mit AND gpl'), lic.parse('mit OR gpl')))
        self.assertFalse(is_equiv(lic.parse('mit AND gpl'), lic.parse('gpl OR mit')))

    def test_validate_symbols(self):
        symbols = [
            LicenseSymbol('l-a'),
            LicenseSymbol('L-a+', ['l-a +']),
            LicenseSymbol('l-a+', is_exception=True),
            LicenseSymbol('l-b'),
            LicenseSymbol('l-c'),
        ]
        warnings, errors = validate_symbols(symbols)
        expectedw = []
        assert expectedw == warnings
        expectede = [
            'Invalid duplicated license key: l-a+.',
        ]
        assert expectede == errors

    def test_license_expression_license_keys(self):
        licensing = Licensing()
        self.assertEqual(['mit', 'gpl'], licensing.license_keys(licensing.parse(' ( mit ) and gpl')))
        self.assertEqual(['mit', 'gpl'], licensing.license_keys(licensing.parse('(mit and gpl)')))
        # these two are surprising for now: this is because the expression is a
        # logical expression so the order may be different on more complex expressions
        self.assertEqual(['mit', 'gpl'], licensing.license_keys(licensing.parse('mit AND gpl or gpl')))
        self.assertEqual(['l-a +', 'l-b', 'l -c+'], licensing.license_keys(licensing.parse('((l-a + AND l-b) OR (l -c+))')))

    def get_symbols_and_licensing(self):
        gpl2 = LicenseSymbol('GPL-2.0', ['The GNU GPL 20'])
        gpl2plus = LicenseSymbol('gpl-2.0+', ['The GNU GPL 20 or later', 'GPL-2.0 or later', 'GPL v2.0 or later'])
        lgpl = LicenseSymbol('LGPL-2.1', ['LGPL v2.1'])
        mit = LicenseSymbol('MIT', ['MIT license'])
        symbols = [gpl2, gpl2plus, lgpl, mit]
        licensing = Licensing(symbols)
        return gpl2, gpl2plus, lgpl, mit, licensing

    def test_unknown_keys(self):
        _gpl2, _gpl2plus, _lgpl, _mit, licensing = self.get_symbols_and_licensing()
        expr = licensing.parse('The GNU GPL 20 or LGPL-2.1 and mit')
        expected = 'gpl-2.0 OR (lgpl-2.1 AND mit)'
        assert expected == str(expr)
        assert [] == licensing.unknown_license_keys(expr)

    def test_unknown_keys_with_trailing_char(self):
        gpl2, _gpl2plus, lgpl, mit, licensing = self.get_symbols_and_licensing()
        expr = licensing.parse('The GNU GPL 20 or LGPL-2.1 and mitand2')
        expected = [gpl2, lgpl, mit, LicenseSymbol(key='2')]
        assert expected == licensing.license_symbols(licensing.parse(expr))
        assert ['2'] == licensing.unknown_license_keys(expr)

    def test_end_to_end(self):
        # these were formerly doctest portedd to actual real code tests here
        l = Licensing()
        expr = l.parse(' GPL-2.0 or LGPL 2.1 and mit ')
        expected = 'gpl-2.0 OR (lgpl 2.1 AND mit)'
        assert expected == str(expr)

        expected = [
            LicenseSymbol('GPL-2.0'),
            LicenseSymbol('LGPL 2.1'),
            LicenseSymbol('mit'),
        ]
        assert expected == l.license_symbols(expr)

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

        assert licensing.is_equivalent(expr1, expr2)

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
            LicenseSymbol('GPL-2.0'),
            LicenseSymbol('mit'),
            LicenseSymbol('LGPL 2.1')
        ]
        assert expected == l.license_symbols(l.parse(' GPL-2.0 and mit or LGPL 2.1 and mit '))

    def test_get_license_symbols2(self):
        l = Licensing()
        expected = [
            LicenseSymbol('GPL-2.0'),
            LicenseSymbol('LATER'),
            LicenseSymbol('mit'),
            LicenseSymbol('LGPL 2.1+'),
            LicenseSymbol('mit'),
            LicenseSymbol('Foo exception', is_exception=True),
        ]
        expr = ' GPL-2.0 or LATER and mit or LGPL 2.1+ and mit with Foo exception '
        assert expected == l.license_symbols(l.parse(expr), unique=False)

    def test_get_license_symbols3(self):
        l = Licensing()
        expected = [
            LicenseSymbol('mit'),
            LicenseSymbol('LGPL 2.1+'),
            LicenseSymbol('Foo exception', is_exception=True),
            LicenseSymbol('GPL-2.0'),
            LicenseSymbol('LATER'),
        ]
        expr = 'mit or LGPL 2.1+ and mit with Foo exception or GPL-2.0 or LATER '
        assert expected == l.license_symbols(l.parse(expr))

    def test_get_license_symbols4(self):
        l = Licensing()
        expected = [
            LicenseSymbol('GPL-2.0'),
            LicenseSymbol('LATER'),
            LicenseSymbol('big exception', is_exception=True),
            LicenseSymbol('mit'),
            LicenseSymbol('LGPL 2.1+'),
            LicenseSymbol('later'),
            LicenseSymbol('mit'),
            LicenseSymbol('later'),
            LicenseSymbol('Foo exception', is_exception=True),
        ]
        expr = (' GPL-2.0 or LATER with big exception and mit or '
                'LGPL 2.1+ or later and mit or later with Foo exception ')
        assert expected == l.license_symbols(l.parse(expr), unique=False)

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

        assert expected == result.render('{original_key}')
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

        expected = 'GPL 2.0 WITH Classpath 2.0 OR BSD-new'
        assert expected == result.render('{original_key}')

        expected_html = (
            '<a href="path/gpl 2.0">GPL 2.0</a> '
            'WITH <a href="path/classpath 2.0">Classpath 2.0</a> '
            'OR <a href="path/bsd-new">BSD-new</a>')
        assert expected_html == result.render('<a href="path/{key}">{original_key}</a>')

        expected = 'gpl 2.0 WITH classpath 2.0 OR bsd-new'
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
            LicenseSymbol('GPL-2.0'),
            LicenseSymbol('LGPL 2.1'),
            LicenseSymbol('mit')
        ]
        assert expected == sorted(licensing.license_symbols(expr))
        expected = 'GPL-2.0 OR (LGPL 2.1 AND mit)'
        assert expected == expr.render('{original_key}')

    def test_license_symbols(self):
        licensing = Licensing([
            'GPL-2.0 or LATER',
            'classpath Exception',
            'something with else+',
            'mit',
            'LGPL 2.1',
            'mit or later'
        ])

        expr = (' GPL-2.0 or LATER with classpath Exception and mit and '
                'mit with SOMETHING with ELSE+ or LGPL 2.1 and '
                'GPL-2.0 or LATER with classpath Exception and '
                'mit or later or LGPL 2.1 or mit or GPL-2.0 or LATER '
                'with SOMETHING with ELSE+ and lgpl 2.1')

        gpl2plus = LicenseSymbol(key='gpl-2.0 or later')
        cpex = LicenseSymbol(key='classpath exception', is_exception=True)
        someplus = LicenseSymbol(key='something with else+', is_exception=True)
        mitplus = LicenseSymbol(key='mit or later')
        mit = LicenseSymbol(key='mit')
        lgpl = LicenseSymbol(key='lgpl 2.1')
        gpl_with_cp = LicenseWithExceptionSymbol(license_symbol=gpl2plus, exception_symbol=cpex)
        mit_with_some = LicenseWithExceptionSymbol(license_symbol=mit, exception_symbol=someplus)
        gpl2_with_someplus = LicenseWithExceptionSymbol(license_symbol=gpl2plus, exception_symbol=someplus)

        parsed = licensing.parse(expr)
        expected = [gpl_with_cp, mit, mit_with_some, lgpl, gpl_with_cp, mitplus, lgpl, mit, gpl2_with_someplus, lgpl]

        assert expected == licensing.license_symbols(parsed, unique=False, decompose=False)

        expected = [gpl_with_cp, mit, mit_with_some, lgpl, mitplus, gpl2_with_someplus]
        assert expected == licensing.license_symbols(parsed, unique=True, decompose=False)

        expected = [gpl2plus, cpex, mit, mit, someplus, lgpl, gpl2plus, cpex, mitplus, lgpl, mit, gpl2plus, someplus, lgpl]
        assert expected == licensing.license_symbols(parsed, unique=False, decompose=True)

        expected = [gpl2plus, cpex, mit, someplus, lgpl, mitplus]
        assert expected == licensing.license_symbols(parsed, unique=True, decompose=True)

    def test_primary_license_symbol_and_primary_license_key(self):
        licensing = Licensing([
            'GPL-2.0 or LATER',
            'classpath Exception',
            'mit',
            'LGPL 2.1',
            'mit or later'
        ])

        expr = ' GPL-2.0 or LATER with classpath Exception and mit or LGPL 2.1 and mit or later '
        gpl = LicenseSymbol('GPL-2.0 or LATER')
        cpex = LicenseSymbol('classpath Exception', is_exception=True)
        expected = LicenseWithExceptionSymbol(gpl, cpex)
        parsed = licensing.parse(expr)
        assert expected == licensing.primary_license_symbol(parsed, decompose=False)
        assert gpl == licensing.primary_license_symbol(parsed, decompose=True)
        assert 'gpl-2.0 or later' == licensing.primary_license_key(parsed)

        expr = ' GPL-2.0 or later with classpath Exception and mit or LGPL 2.1 and mit or later '
        expected = 'GPL-2.0 or LATER WITH classpath Exception'
        assert expected == licensing.primary_license_symbol(parsed, decompose=False).render('{original_key}')

    def test_tokenize_step_by_step_does_not_munge_trailing_symbols(self):
        licensing = Licensing([
            'GPL-2.0 or LATER',
            'classpath Exception',
            'something with else+',
            'mit',
            'LGPL 2.1',
            'mit or later'
        ])

        expr = (' GPL-2.0 or LATER with classpath Exception and mit and '
                'mit with SOMETHING with ELSE+ or LGPL 2.1 and '
                'GPL-2.0 or LATER with classpath Exception and '
                'mit or later or LGPL 2.1 or mit or GPL-2.0 or LATER '
                'with SOMETHING with ELSE+ and lgpl 2.1')

        gpl2plus = LicenseSymbol(key='gpl-2.0 or later')
        cpex = LicenseSymbol(key='classpath exception', is_exception=True)
        cpex_plain = LicenseSymbol(key='classpath exception')
        someplus = LicenseSymbol(key='something with else+', is_exception=True)
        someplus_plain = LicenseSymbol(key='something with else+')
        mitplus = LicenseSymbol(key='mit or later')
        mit = LicenseSymbol(key='mit')
        lgpl = LicenseSymbol(key='lgpl 2.1')
        gpl2plus_with_cpex = LicenseWithExceptionSymbol(license_symbol=gpl2plus, exception_symbol=cpex)
        mit_with_some = LicenseWithExceptionSymbol(license_symbol=mit, exception_symbol=someplus)
        gpl2plus_with_someplus = LicenseWithExceptionSymbol(license_symbol=gpl2plus, exception_symbol=someplus)

        # fist scan
        scanner = licensing.get_resolving_scanner()
        result = list(scanner.scan(expr))
        from license_expression._pyahocorasick import Result, Output
        expected = [
            Result(0, 0, ' ', None),

            Result(1, 16, 'GPL-2.0 or LATER', Output('gpl-2.0 or later', gpl2plus)),
            Result(17, 17, ' ', None),
            Result(18, 21, 'with', Output('with', Keyword(value='with', type=10))),
            Result(22, 22, ' ', None),
            Result(23, 41, 'classpath Exception', Output('classpath exception', cpex_plain)),

            Result(42, 42, ' ', None),
            Result(43, 45, 'and', Output('and', Keyword(value='and', type=1))),
            Result(46, 46, ' ', None),
            Result(47, 49, 'mit', Output('mit', mit)),
            Result(50, 50, ' ', None),
            Result(51, 53, 'and', Output('and', Keyword(value='and', type=1))),
            Result(54, 54, ' ', None),

            Result(55, 57, 'mit', Output('mit', mit)),
            Result(58, 58, ' ', None),
            Result(59, 62, 'with', Output('with', Keyword(value='with', type=10))),
            Result(63, 63, ' ', None),
            Result(64, 83, 'SOMETHING with ELSE+', Output('something with else+', someplus_plain)),

            Result(84, 84, ' ', None),
            Result(85, 86, 'or', Output('or', Keyword(value='or', type=2))),
            Result(87, 87, ' ', None),
            Result(88, 95, 'LGPL 2.1', Output('lgpl 2.1', lgpl)),
            Result(96, 96, ' ', None),
            Result(97, 99, 'and', Output('and', Keyword(value='and', type=1))),
            Result(100, 100, ' ', None),

            Result(101, 116, 'GPL-2.0 or LATER', Output('gpl-2.0 or later', gpl2plus)),
            Result(117, 117, ' ', None),
            Result(118, 121, 'with', Output('with', Keyword(value='with', type=10))),
            Result(122, 122, ' ', None),
            Result(123, 141, 'classpath Exception', Output('classpath exception', cpex_plain)),

            Result(142, 142, ' ', None),
            Result(143, 145, 'and', Output('and', Keyword(value='and', type=1))),
            Result(146, 146, ' ', None),
            Result(147, 158, 'mit or later', Output('mit or later', mitplus)),
            Result(159, 159, ' ', None),
            Result(160, 161, 'or', Output('or', Keyword(value='or', type=2))),
            Result(162, 162, ' ', None),
            Result(163, 170, 'LGPL 2.1', Output('lgpl 2.1', lgpl)),
            Result(171, 171, ' ', None),
            Result(172, 173, 'or', Output('or', Keyword(value='or', type=2))),
            Result(174, 174, ' ', None),
            Result(175, 177, 'mit', Output('mit', mit)),
            Result(178, 178, ' ', None),
            Result(179, 180, 'or', Output('or', Keyword(value='or', type=2))),
            Result(181, 181, ' ', None),

            Result(182, 197, 'GPL-2.0 or LATER', Output('gpl-2.0 or later', gpl2plus)),
            Result(198, 198, ' ', None),
            Result(199, 202, 'with', Output('with', Keyword(value='with', type=10))),
            Result(203, 203, ' ', None),
            Result(204, 223, 'SOMETHING with ELSE+', Output('something with else+', someplus_plain)),

            Result(224, 224, ' ', None),
            Result(225, 227, 'and', Output('and', Keyword(value='and', type=1))),
            Result(228, 228, ' ', None),
            Result(229, 236, 'lgpl 2.1', Output('lgpl 2.1', lgpl))
        ]
        assert expected == result
        assert expected[-1].end + 1 == 237 == sum(len(r.string) for r in result)

        # skip spaces
        result = list(strip_and_skip_spaces(result))
        assert 54 == len(expected)
        assert 27 == len(result)

        # group results
        expected_groups = [
            (Result(1, 16, 'GPL-2.0 or LATER', Output('gpl-2.0 or later', gpl2plus)),
             Result(18, 21, 'with', Output('with', Keyword(value='with', type=10))),
             Result(23, 41, 'classpath Exception', Output('classpath exception', cpex_plain))),

            (Result(43, 45, 'and', Output('and', Keyword(value='and', type=1))),),
            (Result(47, 49, 'mit', Output('mit', LicenseSymbol(key='mit'))),),
            (Result(51, 53, 'and', Output('and', Keyword(value='and', type=1))),),

            (Result(55, 57, 'mit', Output('mit', mit)),
             Result(59, 62, 'with', Output('with', Keyword(value='with', type=10))),
             Result(64, 83, 'SOMETHING with ELSE+', Output('something with else+', someplus_plain))),

            (Result(85, 86, 'or', Output('or', Keyword(value='or', type=2))),),
            (Result(88, 95, 'LGPL 2.1', Output('lgpl 2.1', lgpl)),),
            (Result(97, 99, 'and', Output('and', Keyword(value='and', type=1))),),

            (Result(101, 116, 'GPL-2.0 or LATER', Output('gpl-2.0 or later', gpl2plus)),
             Result(118, 121, 'with', Output('with', Keyword(value='with', type=10))),
             Result(123, 141, 'classpath Exception', Output('classpath exception', cpex_plain))),

            (Result(143, 145, 'and', Output('and', Keyword(value='and', type=1))),),
            (Result(147, 158, 'mit or later', Output('mit or later', mitplus)),),
            (Result(160, 161, 'or', Output('or', Keyword(value='or', type=2))),),
            (Result(163, 170, 'LGPL 2.1', Output('lgpl 2.1', lgpl)),),
            (Result(172, 173, 'or', Output('or', Keyword(value='or', type=2))),),
            (Result(175, 177, 'mit', Output('mit', mit)),),
            (Result(179, 180, 'or', Output('or', Keyword(value='or', type=2))),),

            (Result(182, 197, 'GPL-2.0 or LATER', Output('gpl-2.0 or later', gpl2plus)),
             Result(199, 202, 'with', Output('with', Keyword(value='with', type=10))),
             Result(204, 223, 'SOMETHING with ELSE+', Output('something with else+', someplus_plain))),

            (Result(225, 227, 'and', Output('and', Keyword(value='and', type=1))),),
            (Result(229, 236, 'lgpl 2.1', Output('lgpl 2.1', lgpl)),),

        ]
        result_groups = list(group_results_for_with_subexpression(result))
        assert expected_groups == result_groups

        # finally retest it all with tokenize
        expected = [
            (gpl2plus_with_cpex, 'GPL-2.0 or LATER with classpath Exception', 1),
            (1, 'and', 43),
            (LicenseSymbol(key='mit'), 'mit', 47),
            (1, 'and', 51),
            (mit_with_some, 'mit with SOMETHING with ELSE+', 55),
            (2, 'or', 85),
            (lgpl, 'LGPL 2.1', 88),
            (1, 'and', 97),
            (gpl2plus_with_cpex, 'GPL-2.0 or LATER with classpath Exception', 101),
            (1, 'and', 143),
            (mitplus, 'mit or later', 147),
            (2, 'or', 160),
            (lgpl, 'LGPL 2.1', 163),
            (2, 'or', 172),
            (mit, 'mit', 175),
            (2, 'or', 179),
            (gpl2plus_with_someplus, 'GPL-2.0 or LATER with SOMETHING with ELSE+', 182),
            (1, 'and', 225),
            (lgpl, 'lgpl 2.1', 229),
        ]

        assert expected == list(licensing.tokenize(expr))


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
