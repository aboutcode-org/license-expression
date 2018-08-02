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

from collections import OrderedDict
from unittest import TestCase
import sys

from boolean.boolean import PARSE_UNBALANCED_CLOSING_PARENS
from boolean.boolean import PARSE_INVALID_SYMBOL_SEQUENCE

from license_expression import PARSE_INVALID_EXPRESSION
from license_expression import PARSE_INVALID_NESTING
from license_expression import PARSE_INVALID_EXCEPTION
from license_expression import PARSE_INVALID_SYMBOL_AS_EXCEPTION

from license_expression import ExpressionError
from license_expression import Keyword
from license_expression import Licensing
from license_expression import LicenseExpression
from license_expression import LicenseSymbol
from license_expression import LicenseSymbolLike
from license_expression import LicenseWithExceptionSymbol
from license_expression import ParseError
from license_expression import Result
from license_expression import Output

from license_expression import group_results_for_with_subexpression
from license_expression import splitter
from license_expression import strip_and_skip_spaces
from license_expression import validate_symbols

from license_expression import TOKEN_AND
from license_expression import TOKEN_LPAR
from license_expression import TOKEN_OR
from license_expression import TOKEN_RPAR
from license_expression import TOKEN_SYMBOL
from license_expression import TOKEN_WITH


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


class LicenseSymbolTest(TestCase):

    def test_LicenseSymbol(self):
        sym1 = LicenseSymbol('MIT', ['MIT license'])
        assert sym1 == sym1
        assert 'MIT' == sym1.key
        assert ('MIT license',) == sym1.aliases

        sym2 = LicenseSymbol('mit', ['MIT license'])
        assert 'mit' == sym2.key
        assert ('MIT license',) == sym2.aliases
        assert not sym2.is_exception
        assert sym1 != sym2
        assert sym1 is not sym2

        sym3 = LicenseSymbol('mit', ['MIT license'], is_exception=True)
        assert 'mit' == sym3.key
        assert ('MIT license',) == sym3.aliases
        assert sym3.is_exception
        assert sym2 != sym3

        sym4 = LicenseSymbol('mit', ['MIT license'])
        assert 'mit' == sym4.key
        assert ('MIT license',) == sym4.aliases
        # symbol equality is based ONLY on the key
        assert sym2 == sym4
        assert sym1 != sym4

        sym5 = LicenseWithExceptionSymbol(sym2, sym3)
        assert sym2 == sym5.license_symbol
        assert sym3 == sym5.exception_symbol

        sym6 = LicenseWithExceptionSymbol(sym4, sym3)
        # symbol equality is based ONLY on the key
        assert sym5 == sym6

    def test_license_symbols_key_cannot_contain_spaces(self):
        LicenseSymbol('mit ')
        LicenseSymbol(' mit ')
        try:
            LicenseSymbol(' m it ')
            self.fail('Exception not raised')
        except ExpressionError:
            pass


class LicensingTest(TestCase):

    def test_Licensing_create(self):
        Licensing()
        Licensing(None)
        Licensing(list())


class LicensingTokenizeWithoutSymbolsTest(TestCase):

    def test_tokenize_plain1(self):
        licensing = Licensing()
        expected = [
            (TOKEN_LPAR, '(', 1),
            (LicenseSymbol(key='mit'), 'mit', 3),
            (TOKEN_RPAR, ')', 7),
            (TOKEN_AND, 'and', 9),
            (LicenseSymbol(key='gpl'), 'gpl', 13)
        ]
        assert expected == list(licensing.tokenize(' ( mit ) and gpl'))

    def test_tokenize_plain2(self):
        licensing = Licensing()
        expected = [
            (TOKEN_LPAR, '(', 0),
            (LicenseSymbol(key='mit'), 'mit', 1),
            (TOKEN_AND, 'and', 5),
            (LicenseSymbol(key='gpl'), 'gpl', 9),
            (TOKEN_RPAR, ')', 12)
        ]
        assert expected == list(licensing.tokenize('(mit and gpl)'))

    def test_tokenize_plain3(self):
        licensing = Licensing()
        expected = [
            (LicenseSymbol(key='mit'), 'mit', 0),
            (TOKEN_AND, 'AND', 4),
            (LicenseSymbol(key='gpl'), 'gpl', 8),
            (TOKEN_OR, 'or', 12),
            (LicenseSymbol(key='gpl'), 'gpl', 15)
        ]
        assert expected == list(licensing.tokenize('mit AND gpl or gpl'))

    def test_tokenize_plain4(self):
        licensing = Licensing()
        expected = [
            (TOKEN_LPAR, '(', 0),
            (TOKEN_LPAR, '(', 1),
            (LicenseSymbol(key=u'l-a+'), u'l-a+', 2),
            (TOKEN_AND, 'AND', 7),
            (LicenseSymbol(key=u'l-b'), u'l-b', 11),
            (TOKEN_RPAR, ')', 14),
            (TOKEN_OR, 'OR', 16),
            (TOKEN_LPAR, '(', 19),
            (LicenseSymbol(key='l-c+'), 'l-c+', 20),
            (TOKEN_RPAR, ')', 24),
            (TOKEN_RPAR, ')', 25)
        ]
        assert expected == list(licensing.tokenize('((l-a+ AND l-b) OR (l-c+))'))

    def test_tokenize_plain5(self):
        licensing = Licensing()
        expected = [
            (TOKEN_LPAR, '(', 0),
            (TOKEN_LPAR, '(', 1),
            (LicenseSymbol(key='l-a+'), 'l-a+', 2),
            (TOKEN_AND, 'AND', 7),
            (LicenseSymbol(key='l-b'), 'l-b', 11),
            (TOKEN_RPAR, ')', 14),
            (TOKEN_OR, 'OR', 16),
            (TOKEN_LPAR, '(', 19),
            (LicenseSymbol(key='l-c+'), 'l-c+', 20),
            (TOKEN_RPAR, ')', 24),
            (TOKEN_RPAR, ')', 25),
            (TOKEN_AND, 'and', 27),
            (LicenseWithExceptionSymbol(
                license_symbol=LicenseSymbol(key='gpl'),
                exception_symbol=LicenseSymbol(key='classpath')),
             'gpl with classpath', 31
            )
        ]
        assert expected == list(licensing.tokenize('((l-a+ AND l-b) OR (l-c+)) and gpl with classpath'))


class LicensingTokenizeWithSymbolsTest(TestCase):

    def get_symbols_and_licensing(self):
        gpl_20 = LicenseSymbol('GPL-2.0', ['The-GNU-GPL-20'])
        gpl_20_plus = LicenseSymbol('gpl-2.0+',
            ['The-GNU-GPL-20-or-later', 'GPL-2.0-or-later', 'GPL-v2.0-or-later'])
        lgpl_21 = LicenseSymbol('LGPL-2.1', ['LGPL-v2.1'])
        mit = LicenseSymbol('MIT', ['MIT-license'])
        symbols = [gpl_20, gpl_20_plus, lgpl_21, mit]
        licensing = Licensing(symbols)
        return gpl_20, gpl_20_plus, lgpl_21, mit, licensing

    def test_tokenize_1(self):
        gpl_20, _gpl_20_plus, lgpl_21, mit, licensing = self.get_symbols_and_licensing()
        result = licensing.tokenize('The-GNU-GPL-20 or LGPL-2.1 and mit')
        expected = [
            (gpl_20, 'The-GNU-GPL-20', 0),
            (TOKEN_OR, 'or', 15),
            (lgpl_21, 'LGPL-2.1', 18),
            (TOKEN_AND, 'and', 27),
            (mit, 'mit', 31)]
        assert expected == list(result)

    def test_tokenize_with_trailing_unknown(self):
        gpl_20, _gpl_20_plus, lgpl_21, _mit, licensing = self.get_symbols_and_licensing()
        result = licensing.tokenize('The-GNU-GPL-20 or LGPL-2.1 and mit2')
        expected = [
            (gpl_20, 'The-GNU-GPL-20', 0),
            (TOKEN_OR, 'or', 15),
            (lgpl_21, 'LGPL-2.1', 18),
            (TOKEN_AND, 'and', 27),
            (LicenseSymbol(key='mit2'), 'mit2', 31)
        ]
        assert expected == list(result)

    def test_tokenize_3(self):
        gpl_20, gpl_20_plus, lgpl_21, mit, licensing = self.get_symbols_and_licensing()

        result = licensing.tokenize('The-GNU-GPL-20-or-later or (LGPL-2.1 and mit) or The-GNU-GPL-20 or mit')
        expected = [
            (gpl_20_plus, 'The-GNU-GPL-20-or-later', 0),
            (TOKEN_OR, 'or', 24),
            (TOKEN_LPAR, '(', 27),
            (lgpl_21, 'LGPL-2.1', 28),
            (TOKEN_AND, 'and', 37),
            (mit, 'mit', 41),
            (TOKEN_RPAR, ')', 44),
            (TOKEN_OR, 'or', 46),
            (gpl_20, 'The-GNU-GPL-20', 49),
            (TOKEN_OR, 'or', 64),
            (mit, 'mit', 67)
        ]
        assert expected == list(result)

    def test_tokenize_unknown_as_trailing_single_attached_character_does_not_match_known_license(self):
        symbols = [LicenseSymbol('MIT', ['MIT-license'])]
        l = Licensing(symbols)
        result = list(l.tokenize('mit2'))
        expected = [
            (LicenseSymbol(key='mit2'), 'mit2', 0),
        ]
        assert expected == result

    def test_tokenize_with_unknown_symbol_containing_known_symbol_leading(self):
        l = Licensing(['gpl-2.0'])
        result = list(l.tokenize('gpl-2.0 AND gpl-2.0-plus', strict=False))
        result = [s for s, _, _ in result]
        expected = [
            LicenseSymbol(key='gpl-2.0'),
            TOKEN_AND,
            LicenseSymbol(key='gpl-2.0-plus'),
        ]
        assert expected == result

    def test_tokenize_with_unknown_symbol_containing_known_symbol_contained(self):
        l = Licensing(['gpl-2.0'])
        result = list(l.tokenize('gpl-2.0 WITH exception-gpl-2.0-plus', strict=False))
        result = [s for s, _, _ in result]
        expected = [
            LicenseWithExceptionSymbol(
                LicenseSymbol(u'gpl-2.0'),
                LicenseSymbol(u'exception-gpl-2.0-plus')
            )
        ]
        assert expected == result

    def test_tokenize_with_unknown_symbol_containing_known_symbol_trailing(self):
        l = Licensing(['gpl-2.0'])
        result = list(l.tokenize('gpl-2.0 AND exception-gpl-2.0', strict=False))
        result = [s for s, _, _ in result]
        expected = [
            LicenseSymbol(u'gpl-2.0'),
            TOKEN_AND,
            LicenseSymbol(u'exception-gpl-2.0')
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

    def test_parse_raise_ExpressionError_when_validating(self):
        expression = 'gpl and bsd or lgpl with exception'
        licensing = Licensing()
        try:
            licensing.parse(expression, validate=True)
            self.fail('Exception not raised')
        except ExpressionError as ee:
            assert 'Unknown license key(s): gpl, bsd, lgpl, exception' == str(ee)

    def test_parse_raise_ExpressionError_when_validating_strict(self):
        expression = 'gpl and bsd or lgpl with exception'
        licensing = Licensing()
        try:
            licensing.parse(expression, validate=True, strict=True)
            self.fail('Exception not raised')
        except ExpressionError as ee:
            assert str(ee).startswith('exception_symbol must be an exception with "is_exception" set to True:')

    def test_parse_in_strict_mode_for_solo_symbol(self):
        expression = 'lgpl'
        licensing = Licensing()
        licensing.parse(expression, strict=True)

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
        except ParseError:
            pass

        expr = '(l-a + AND l-b))'
        try:
            licensing.parse(expr)
            self.fail("Exception not raised when validating '%s'" % expr)
        except ParseError:
            pass

        expr = 'l-a AND'
        try:
            licensing.parse(expr)
            self.fail("Exception not raised when validating '%s'" % expr)
        except ParseError:
            pass

        expr = 'OR l-a'
        try:
            licensing.parse(expr)
            self.fail("Exception not raised when validating '%s'" % expr)
        except ParseError:
            pass

        expr = '+l-a'
        licensing.parse(expr)

    def test_parse_can_parse(self):
        licensing = Licensing()
        expr = ' GPL-2.0 or LGPL2.1 and mit '
        parsed = licensing.parse(expr)
        gpl2 = LicenseSymbol('GPL-2.0')
        lgpl = LicenseSymbol('LGPL2.1')
        mit = LicenseSymbol('mit')
        expected = [gpl2, lgpl, mit]
        self.assertEqual(expected, licensing.license_symbols(parsed))
        self.assertEqual(expected, licensing.license_symbols(expr))
        self.assertEqual('GPL-2.0 OR (LGPL2.1 AND mit)', str(parsed))

        expected = licensing.OR(gpl2, licensing.AND(lgpl, mit))
        assert expected == parsed

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
            except ExpressionError as ee:
                assert str(ee).startswith('expression must be a string and')

        if py3:
            extra_bytes = bytes(chr(0) + chr(12) + chr(255), encoding='utf-8')
            try:
                licensing.parse('mit (and LGPL 2.1)'.encode('utf-8') + extra_bytes)
                self.fail('Exception not raised')
            except ExpressionError as ee:
                assert str(ee).startswith('Invalid license key')

    def test_parse_errors_does_not_raise_error_on_plain_non_unicode_raw_string(self):
        # plain non-unicode string does not raise error
        licensing = Licensing()
        x = licensing.parse(r'mit and (LGPL-2.1)')
        self.assertTrue(isinstance(x, LicenseExpression))

    def test_parse_simplify_and_contain_and_equal(self):
        licensing = Licensing()

        expr = licensing.parse(' GPL-2.0 or LGPL2.1 and mit ')

        expr2 = licensing.parse(' (mit and LGPL2.1) or GPL-2.0 ')
        self.assertEqual(expr2.simplify(), expr.simplify())
        self.assertEqual(expr2, expr)

        expr3 = licensing.parse('mit and LGPL2.1')
        self.assertTrue(expr3 in expr2)

    def test_license_expression_is_equivalent(self):
        lic = Licensing()
        is_equiv = lic.is_equivalent

        self.assertTrue(is_equiv(lic.parse('mit AND gpl'), lic.parse('mit AND gpl')))
        self.assertTrue(is_equiv(lic.parse('mit AND gpl'), lic.parse('gpl AND mit')))
        self.assertTrue(is_equiv(lic.parse('mit AND gpl and apache'), lic.parse('apache and gpl AND mit')))
        self.assertTrue(is_equiv(lic.parse('mit AND (gpl AND apache)'), lic.parse('(mit AND gpl) AND apache')))

        # same but without parsing:
        self.assertTrue(is_equiv('mit AND gpl', 'mit AND gpl'))
        self.assertTrue(is_equiv('mit AND gpl', 'gpl AND mit'))
        self.assertTrue(is_equiv('mit AND gpl and apache', 'apache and gpl AND mit'))
        self.assertTrue(is_equiv('mit AND (gpl AND apache)', '(mit AND gpl) AND apache'))

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

    def test_license_expression_license_keys(self):
        licensing = Licensing()
        assert ['mit', 'gpl'] == licensing.license_keys(licensing.parse(' ( mit ) and gpl'))
        assert ['mit', 'gpl'] == licensing.license_keys(licensing.parse('(mit and gpl)'))
        # these two are surprising for now: this is because the expression is a
        # logical expression so the order may be different on more complex expressions
        assert ['mit', 'gpl'] == licensing.license_keys(licensing.parse('mit AND gpl or gpl'))
        assert ['l-a+', 'l-b', '+l-c'] == licensing.license_keys(licensing.parse('((l-a+ AND l-b) OR (+l-c))'))
        # same without parsing
        assert ['mit', 'gpl'] == licensing.license_keys('mit AND gpl or gpl')
        assert ['l-a+', 'l-b', 'l-c+'] == licensing.license_keys('((l-a+ AND l-b) OR (l-c+))')

    def test_end_to_end(self):
        # these were formerly doctest ported to actual real code tests here
        l = Licensing()
        expr = l.parse(' GPL-2.0 or LGPL-2.1 and mit ')
        expected = 'GPL-2.0 OR (LGPL-2.1 AND mit)'
        assert expected == str(expr)

        expected = [
            LicenseSymbol('GPL-2.0'),
            LicenseSymbol('LGPL-2.1'),
            LicenseSymbol('mit'),
        ]
        assert expected == l.license_symbols(expr)

    def test_pretty(self):
        l = Licensing()
        expr = l.parse(' GPL-2.0 or LGPL2.1 and mit ')

        expected = '''OR(
  LicenseSymbol('GPL-2.0'),
  AND(
    LicenseSymbol('LGPL2.1'),
    LicenseSymbol('mit')
  )
)'''
        assert expected == expr.pretty()

    def test_simplify_and_contains(self):
        l = Licensing()

        expr = l.parse(' GPL-2.0 or LGPL2.1 and mit ')
        expr2 = l.parse(' GPL-2.0 or (mit and LGPL2.1) ')
        assert expr2.simplify() == expr.simplify()
        expr3 = l.parse('mit and LGPL2.1')
        assert expr3 in expr2

    def test_simplify_and_equivalent_and_contains(self):
        l = Licensing()
        expr2 = l.parse(' GPL-2.0 or (mit and LGPL-2.1) or bsd Or GPL-2.0  or (mit and LGPL-2.1)')
        # note thats simplification does SORT the symbols such that they can
        # eventually be compared sequence-wise. This sorting is based on license key
        expected = 'GPL-2.0 OR bsd OR (LGPL-2.1 AND mit)'
        assert expected == str(expr2.simplify())

        # Two expressions can be compared for equivalence:
        expr1 = l.parse(' GPL-2.0 or (LGPL-2.1 and mit) ')
        assert 'GPL-2.0 OR (LGPL-2.1 AND mit)' == str(expr1)
        expr2 = l.parse(' (mit and LGPL-2.1)  or GPL-2.0 ')
        assert '(mit AND LGPL-2.1) OR GPL-2.0' == str(expr2)
        assert l.is_equivalent(expr1, expr2)

        assert 'GPL-2.0 OR (LGPL-2.1 AND mit)' == str(expr1.simplify())
        assert 'GPL-2.0 OR (LGPL-2.1 AND mit)' == str(expr2.simplify())
        assert expr1.simplify() == expr2.simplify()

        expr3 = l.parse(' GPL-2.0 or mit or LGPL-2.1')
        assert not l.is_equivalent(expr2, expr3)
        expr4 = l.parse('mit and LGPL-2.1')
        assert expr4.simplify() in expr2.simplify()

        assert l.contains(expr2, expr4)

    def test_contains_works_with_plain_symbol(self):
        l = Licensing()
        assert not l.contains('mit', 'mit and LGPL-2.1')
        assert l.contains('mit and LGPL-2.1', 'mit')
        assert l.contains('mit', 'mit')
        assert not l.contains(l.parse('mit'), l.parse('mit and LGPL-2.1'))
        assert l.contains(l.parse('mit and LGPL-2.1'), l.parse('mit'))

        assert l.contains('mit with GPL', 'GPL')
        assert l.contains('mit with GPL', 'mit')
        assert l.contains('mit with GPL', 'mit with GPL')
        assert not l.contains('mit with GPL', 'GPL with mit')
        assert not l.contains('mit with GPL', 'GPL and mit')
        assert not l.contains('GPL', 'mit with GPL')
        assert l.contains('mit with GPL and GPL and BSD', 'GPL and BSD')

    def test_create_from_python(self):
        # Expressions can be built from Python expressions, using bitwise operators
        # between Licensing objects, but use with caution. The behavior is not as
        # well specified that using text expression and parse

        licensing = Licensing()
        expr1 = (licensing.LicenseSymbol('GPL-2.0')
                 | (licensing.LicenseSymbol('mit')
                    & licensing.LicenseSymbol('LGPL-2.1')))
        expr2 = licensing.parse(' GPL-2.0 or (mit and LGPL-2.1) ')

        assert 'GPL-2.0 OR (LGPL-2.1 AND mit)' == str(expr1.simplify())
        assert 'GPL-2.0 OR (LGPL-2.1 AND mit)' == str(expr2.simplify())

        assert licensing.is_equivalent(expr1, expr2)

        a = licensing.OR(
            LicenseSymbol(key='gpl-2.0'),
            licensing.AND(LicenseSymbol(key='mit'),
                LicenseSymbol(key='lgpl-2.1')
                )
            )
        b = licensing.OR(
             LicenseSymbol(key='gpl-2.0'),
             licensing.AND(LicenseSymbol(key='mit'),
                 LicenseSymbol(key='lgpl-2.1')
                 )
            )
        assert a == b

    def test_parse_with_repeated_or_later_raise_parse_error(self):
        l = Licensing()
        expr = 'LGPL2.1+ + and mit'
        try:
            l.parse(expr)
            self.fail('Exception not raised')
        except ParseError as ee:
            expected = 'Invalid symbols sequence such as (A B) for token: "+" at position: 9'
            assert expected == str(ee)

    def test_render_complex(self):
        licensing = Licensing()
        expression = '''
        EPL-1.0 AND Apache-1.1 AND Apache-2.0 AND BSD-Modified AND CPL-1.0 AND
        ICU-Composite-License AND JPEG-License AND JDOM-License AND LGPL-2.0 AND
        MIT-Open-Group AND MPL-1.1 AND SAX-PD AND Unicode-Inc-License-Agreement
        AND W3C-Software-Notice and License AND W3C-Documentation-License'''

        result = licensing.parse(expression)
        expected = ('EPL-1.0 AND Apache-1.1 AND Apache-2.0 AND BSD-Modified '
        'AND CPL-1.0 AND ICU-Composite-License AND JPEG-License '
        'AND JDOM-License AND LGPL-2.0 AND MIT-Open-Group AND MPL-1.1 '
        'AND SAX-PD AND Unicode-Inc-License-Agreement '
        'AND W3C-Software-Notice AND License AND W3C-Documentation-License')

        assert expected == result.render('{symbol.key}')
        expectedkey = ('EPL-1.0 AND Apache-1.1 AND Apache-2.0 AND BSD-Modified AND '
        'CPL-1.0 AND ICU-Composite-License AND JPEG-License AND JDOM-License AND '
        'LGPL-2.0 AND MIT-Open-Group AND MPL-1.1 AND SAX-PD AND '
        'Unicode-Inc-License-Agreement AND W3C-Software-Notice AND License AND'
        ' W3C-Documentation-License')
        assert expectedkey == result.render('{symbol.key}')

    def test_render_with(self):
        licensing = Licensing()
        expression = 'GPL-2.0 with Classpath-2.0 OR BSD-new'
        result = licensing.parse(expression)

        expected = 'GPL-2.0 WITH Classpath-2.0 OR BSD-new'
        assert expected == result.render('{symbol.key}')

        expected_html = (
            '<a href="path/GPL-2.0">GPL-2.0</a> WITH '
            '<a href="path/Classpath-2.0">Classpath-2.0</a> '
            'OR <a href="path/BSD-new">BSD-new</a>')
        assert expected_html == result.render('<a href="path/{symbol.key}">{symbol.key}</a>')

        expected = 'GPL-2.0 WITH Classpath-2.0 OR BSD-new'
        assert expected == result.render('{symbol.key}')

    def test_parse_complex(self):
        licensing = Licensing()
        expression = ' GPL-2.0 or later with classpath-Exception and mit or  LPL-2.1 and mit or later '
        result = licensing.parse(expression)
        # this may look weird, but we did not provide symbols hence in "or later",
        # "later" is treated as if it were a license
        expected = 'GPL-2.0 OR (later WITH classpath-Exception AND mit) OR (LPL-2.1 AND mit) OR later'
        assert expected == result.render('{symbol.key}')

    def test_parse_complex2(self):
        licensing = Licensing()
        expr = licensing.parse(" GPL-2.0 or LGPL-2.1 and mit ")
        expected = [
            LicenseSymbol('GPL-2.0'),
            LicenseSymbol('LGPL-2.1'),
            LicenseSymbol('mit')
        ]
        assert expected == sorted(licensing.license_symbols(expr))
        expected = 'GPL-2.0 OR (LGPL-2.1 AND mit)'
        assert expected == expr.render('{symbol.key}')

    def test_Licensing_can_split_valid_expressions_with_symbols_that_contain_and_with_or(self):
        expression = 'orgpl or withbsd with orclasspath and andmit or andlgpl and ormit or withme'
        result = [r.string for r in splitter(expression)]
        expected = [
            'orgpl',
            ' ',
            'or',
            ' ',
            'withbsd',
            ' ',
            'with',
            ' ',
            'orclasspath',
            ' ',
            'and',
            ' ',
            'andmit',
            ' ',
            'or',
            ' ',
            'andlgpl',
            ' ',
            'and',
            ' ',
            'ormit',
            ' ',
            'or',
            ' ',
            'withme'
        ]
        assert expected == result

    def test_Licensing_can_tokenize_valid_expressions_with_symbols_that_contain_and_with_or(self):
        licensing = Licensing()
        expression = 'orgpl or withbsd with orclasspath and andmit or anlgpl and ormit or withme'

        result = list(licensing.tokenize(expression))
        expected = [
            (LicenseSymbol(key='orgpl'), 'orgpl', 0),
            (2, 'or', 6),
            (LicenseWithExceptionSymbol(
                license_symbol=LicenseSymbol(key='withbsd'),
                exception_symbol=LicenseSymbol(key='orclasspath')),
             'withbsd with orclasspath', 9),
            (1, 'and', 34),
            (LicenseSymbol(key='andmit'), 'andmit', 38),
            (2, 'or', 45),
            (LicenseSymbol(key='anlgpl'), 'anlgpl', 48),
            (1, 'and', 55),
            (LicenseSymbol(key='ormit'), 'ormit', 59),
            (2, 'or', 65),
            (LicenseSymbol(key='withme'), 'withme', 68)
        ]

        assert expected == result

    def test_Licensing_can_parse_valid_expressions_with_symbols_that_contain_and_with_or(self):
        licensing = Licensing()
        expression = 'orgpl or withbsd with orclasspath and andmit or anlgpl and ormit or withme'

        result = licensing.parse(expression)
        expected = 'orgpl OR (withbsd WITH orclasspath AND andmit) OR (anlgpl AND ormit) OR withme'
        assert expected == result.render('{symbol.key}')


class LicensingParseWithSymbolsSimpleTest(TestCase):

    def test_Licensing_with_illegal_symbols_raise_Exception(self):
        try:
            Licensing([
                'GPL-2.0 or LATER',
                'classpath Exception',
                'something with else+',
                'mit',
                'LGPL 2.1',
                'mit or later'
            ])
            self.fail('Exception not raised')
        except ExpressionError as ee:
            expected = ("A license key cannot contains spaces: u'GPL-2.0 or LATER'")

            assert expected == str(ee)

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
        express_string = 'l-a+'
        result = licensing.parse(express_string)
        assert 'L-a+' == str(result)
        expected = ap
        assert expected == result
        assert [] == licensing.unknown_license_keys(result)

    def test_parse_license_expression3(self):
        _a, ap, _b, _c, licensing = self.get_syms_and_licensing()
        express_string = 'l-a+'
        result = licensing.parse(express_string)
        assert 'L-a+' == str(result)
        expected = ap
        assert expected == result
        assert [] == licensing.unknown_license_keys(result)

    def test_parse_license_expression4(self):
        _a, _ap, _b, _c, licensing = self.get_syms_and_licensing()
        express_string = '(l-a)'
        result = licensing.parse(express_string)
        assert 'l-a' == str(result)
        expected = LicenseSymbol(key='l-a', aliases=())
        assert expected == result
        assert [] == licensing.unknown_license_keys(result)

    def test_parse_license_expression5(self):
        _a, ap, b, c, licensing = self.get_syms_and_licensing()
        express_string = '((l-a+ AND l-b) OR (l-c))'
        result = licensing.parse(express_string)
        assert '(L-a+ AND l-b) OR l-c' == str(result)
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
            LicenseSymbol('L-a+', ['l-a+']),
            LicenseSymbol('l-b'),
            LicenseSymbol('l-c'),
        ]
        licensing = Licensing(symbols)

        expresssion_str = 'l-a'
        result = licensing.parse(expresssion_str)
        assert expresssion_str == str(result)
        assert [] == licensing.unknown_license_keys(result)

        # plus sign is not attached to the symbol, but an alias
        expresssion_str = 'l-a+'
        result = licensing.parse(expresssion_str)
        assert 'l-a+' == str(result).lower()
        assert [] == licensing.unknown_license_keys(result)

        expresssion_str = '(l-a)'
        result = licensing.parse(expresssion_str)
        assert 'l-a' == str(result).lower()
        assert [] == licensing.unknown_license_keys(result)

        expresssion_str = '((l-a+ AND l-b) OR (l-c))'
        result = licensing.parse(expresssion_str)
        assert '(L-a+ AND l-b) OR l-c' == str(result)
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

    def test_parse_of_side_by_side_symbols_raise_exception(self):
        gpl2 = LicenseSymbol('gpl')
        l = Licensing([gpl2])
        try:
            l.parse('gpl mit')
            self.fail('ParseError not raised')
        except ParseError:
            pass

    def test_validate_symbols(self):
        symbols = [
            LicenseSymbol('l-a', is_exception=True),
            LicenseSymbol('l-a'),
            LicenseSymbol('l-b'),
            LicenseSymbol('l-c'),
        ]
        warnings, errors = validate_symbols(symbols)
        expectedw = []
        assert expectedw == warnings
        expectede = [
            'Invalid duplicated license key: l-a.',
        ]
        assert expectede == errors


class LicensingParseWithSymbolsTest(TestCase):

    def test_parse_raise_ParseError_when_validating_strict_with_non_exception_symbols(self):
        licensing = Licensing(['gpl', 'bsd', 'lgpl', 'exception'])

        expression = 'gpl and bsd or lgpl with exception'
        try:
            licensing.parse(expression, validate=True, strict=True)
            self.fail('Exception not raised')
        except ParseError as pe:
            expected = {
                'error_code': PARSE_INVALID_SYMBOL_AS_EXCEPTION,
                'position': 25,
                'token_string': 'exception',
                'token_type': TOKEN_SYMBOL}
            assert expected == _parse_error_as_dict(pe)

    def test_parse_raise_ParseError_when_validating_strict_with_exception_symbols_in_incorrect_spot(self):
        licensing = Licensing([LicenseSymbol('gpl', is_exception=False),
                               LicenseSymbol('exception', is_exception=True)])
        licensing.parse('gpl with exception', validate=True, strict=True)
        try:
            licensing.parse('exception with gpl', validate=True, strict=True)
            self.fail('Exception not raised')
        except ParseError as pe:
            expected = {
                'error_code': PARSE_INVALID_EXCEPTION,
                'position': 0,
                'token_string': 'exception',
                'token_type': TOKEN_SYMBOL}
            assert expected == _parse_error_as_dict(pe)

        try:
            licensing.parse('gpl with gpl', validate=True, strict=True)
            self.fail('Exception not raised')
        except ParseError as pe:
            expected = {
                'error_code': PARSE_INVALID_SYMBOL_AS_EXCEPTION,
                'position': 9,
                'token_string': 'gpl',
                'token_type': TOKEN_SYMBOL}
            assert expected == _parse_error_as_dict(pe)

    def test_with_unknown_symbol_string_contained_in_known_symbol_does_not_crash_with(self):
        l = Licensing(['lgpl-3.0-plus'])
        license_expression = 'lgpl-3.0-plus WITH openssl-exception-lgpl-3.0-plus'
        l.parse(license_expression)

    def test_with_unknown_symbol_string_contained_in_known_symbol_does_not_crash_and(self):
        l = Licensing(['lgpl-3.0-plus'])
        license_expression = 'lgpl-3.0-plus AND openssl-exception-lgpl-3.0-plus'
        l.parse(license_expression)

    def test_with_unknown_symbol_string_contained_in_known_symbol_does_not_crash_or(self):
        l = Licensing(['lgpl-3.0-plus'])
        license_expression = 'lgpl-3.0-plus OR openssl-exception-lgpl-3.0-plus'
        l.parse(license_expression)

    def test_with_known_symbol_string_contained_in_known_symbol_does_not_crash_or(self):
        l = Licensing(['lgpl-3.0-plus', 'openssl-exception-lgpl-3.0-plus'])
        license_expression = 'lgpl-3.0-plus OR openssl-exception-lgpl-3.0-plus'
        l.parse(license_expression)

    def test_with_known_symbol_string_contained_in_known_symbol_does_not_crash_with(self):
        l = Licensing(['lgpl-3.0-plus', 'openssl-exception-lgpl-3.0-plus'])
        license_expression = 'lgpl-3.0-plus WITH openssl-exception-lgpl-3.0-plus'
        l.parse(license_expression)


class LicensingSymbolsReplacementTest(TestCase):

    def get_symbols_and_licensing(self):
        gpl2 = LicenseSymbol('gpl-2.0', ['The GNU GPL 20', 'GPL-2.0', 'GPL v2.0'])
        gpl2plus = LicenseSymbol('gpl-2.0+', ['The GNU GPL 20 or later', 'GPL-2.0 or later', 'GPL v2.0 or later'])
        lgpl = LicenseSymbol('LGPL-2.1', ['LGPL v2.1'])
        mit = LicenseSymbol('MIT', ['MIT license'])
        mitand2 = LicenseSymbol('mitand2', ['mitand2', 'mitand2 license'])
        symbols = [gpl2, gpl2plus, lgpl, mit, mitand2]
        licensing = Licensing(symbols)
        return gpl2, gpl2plus, lgpl, mit, mitand2, licensing

    def test_simple_substitution(self):
        gpl2, gpl2plus, _lgpl, _mit, _mitand2, licensing = self.get_symbols_and_licensing()
        subs = {gpl2plus: gpl2}

        expr = licensing.parse('gpl-2.0 or gpl-2.0+')
        result = expr.subs(subs)
        assert 'gpl-2.0 OR gpl-2.0' == result.render()

    def test_advanced_substitution(self):
        _gpl2, _gpl2plus, lgpl, _mit, _mitand2, licensing = self.get_symbols_and_licensing()
        source = licensing.parse('gpl-2.0+ and mit')
        target = lgpl
        subs = {source: target}

        expr = licensing.parse('gpl-2.0 or gpl-2.0+ and mit')
        result = expr.subs(subs)
        assert 'gpl-2.0 OR LGPL-2.1' == result.render()

    def test_multiple_substitutions(self):
        gpl2, gpl2plus, lgpl, mit, _mitand2, licensing = self.get_symbols_and_licensing()

        source1 = licensing.parse('gpl-2.0+ and mit')
        target1 = lgpl

        source2 = licensing.parse('mitand2')
        target2 = mit

        source3 = gpl2
        target3 = gpl2plus

        subs = OrderedDict([
            (source1, target1),
            (source2, target2),
            (source3, target3),
        ])

        expr = licensing.parse('gpl-2.0 or gpl-2.0+ and mit')
        # step 1: yields 'gpl-2.0 or lgpl'
        # step 2: yields 'gpl-2.0+ or LGPL-2.1'
        result = expr.subs(subs)
        assert 'gpl-2.0+ OR LGPL-2.1' == result.render()

    def test_multiple_substitutions_complex(self):
        gpl2, gpl2plus, lgpl, mit, _mitand2, licensing = self.get_symbols_and_licensing()

        source1 = licensing.parse('gpl-2.0+ and mit')
        target1 = lgpl

        source2 = licensing.parse('mitand2')
        target2 = mit

        source3 = gpl2
        target3 = gpl2plus

        subs = OrderedDict([
            (source1, target1),
            (source2, target2),
            (source3, target3),
        ])

        expr = licensing.parse('(gpl-2.0 or gpl-2.0+ and mit) and (gpl-2.0 or gpl-2.0+ and mit)')
        # step 1: yields 'gpl-2.0 or lgpl'
        # step 2: yields 'gpl-2.0+ or LGPL-2.1'
        result = expr.subs(subs)
        assert '(gpl-2.0+ OR LGPL-2.1) AND (gpl-2.0+ OR LGPL-2.1)' == result.render()

        expr = licensing.parse('(gpl-2.0 or mit and gpl-2.0+) and (gpl-2.0 or gpl-2.0+ and mit)')
        # step 1: yields 'gpl-2.0 or lgpl'
        # step 2: yields 'gpl-2.0+ or LGPL-2.1'
        result = expr.subs(subs)
        assert '(gpl-2.0+ OR LGPL-2.1) AND (gpl-2.0+ OR LGPL-2.1)' == result.render()


class LicensingParseWithSymbolsAdvancedTest(TestCase):

    def get_symbols_and_licensing(self):
        gpl2 = LicenseSymbol('gpl-2.0', ['The-GNU-GPL-20', 'GPL-2.0', 'GPL-v2.0'])
        gpl2plus = LicenseSymbol('gpl-2.0+', ['The-GNU-GPL-20-or-later', 'GPL-2.0-or-later', 'GPL-v2.0-or-later'])
        lgpl = LicenseSymbol('LGPL-2.1', ['LGPL v2.1'])
        mit = LicenseSymbol('MIT', ['MIT license'])
        mitand2 = LicenseSymbol('mitand2', ['mitand2', 'mitand2-license'])
        symbols = [gpl2, gpl2plus, lgpl, mit, mitand2]
        licensing = Licensing(symbols)
        return gpl2, gpl2plus, lgpl, mit, mitand2, licensing

    def test_parse_trailing_char_raise_exception(self):
        _gpl2, _gpl2plus, _lgpl, _mit, _mitand2, licensing = self.get_symbols_and_licensing()
        try:
            licensing.parse('The-GNU-GPL-20 or LGPL-2.1 and mit 2')
            self.fail('Exception not raised')
        except ParseError as pe:
            expected = {
                'error_code': PARSE_INVALID_SYMBOL_SEQUENCE,
                'position': 35,
                'token_string': '2',
                'token_type': LicenseSymbol('2')
            }
            assert expected == _parse_error_as_dict(pe)

    def test_parse_trailing_char_raise_exception_if_validate(self):
        _gpl2, _gpl2plus, _lgpl, _mit, _mitand2, licensing = self.get_symbols_and_licensing()
        try:
            licensing.parse('The-GNU-GPL-20 or LGPL-2.1 and mit2', validate=True)
            self.fail('Exception not raised')
        except ExpressionError as pe:
            assert 'Unknown license key(s): mit2' in str(pe)

    def test_parse_expression_with_trailing_unknown_should_raise_exception(self):
        gpl2, gpl2plus, lgpl, mit, _mitand2, licensing = self.get_symbols_and_licensing()
        unknown = LicenseSymbol(key='123')

        tokens = list(licensing.tokenize('The-GNU-GPL-20-or-later or (LGPL-2.1 and mit) or The-GNU-GPL-20 or mit 123'))
        expected = [
            (gpl2plus, 'The-GNU-GPL-20-or-later', 0),
            (TOKEN_OR, 'or', 24),
            (TOKEN_LPAR, '(', 27),
            (lgpl, 'LGPL-2.1', 28),
            (TOKEN_AND, 'and', 37),
            (mit, 'mit', 41),
            (TOKEN_RPAR, ')', 44),
            (TOKEN_OR, 'or', 46),
            (gpl2, 'The-GNU-GPL-20', 49),
            (TOKEN_OR, 'or', 64),
            (mit, 'mit', 67),
            (unknown, '123', 71)
        ]
        assert expected == tokens

        try:
            licensing.parse('The-GNU-GPL-20-or-later or (LGPL-2.1 and mit) or The-GNU-GPL-20 or mit 123')
            self.fail('Exception not raised')
        except ParseError as pe:
            expected = {'error_code': PARSE_INVALID_SYMBOL_SEQUENCE, 'position': 71,
                        'token_string': '123', 'token_type': unknown}
            assert expected == _parse_error_as_dict(pe)

    def test_parse_expression_with_trailing_unknown_should_raise_exception2(self):
        _gpl2, _gpl2_plus, _lgpl, _mit, _mitand2, licensing = self.get_symbols_and_licensing()
        unknown = LicenseSymbol(key='123')
        try:
            licensing.parse('The-GNU-GPL-20 or mit 123')
            self.fail('Exception not raised')
        except ParseError as pe:
            expected = {'error_code': PARSE_INVALID_SYMBOL_SEQUENCE, 'position': 22,
                        'token_string': '123', 'token_type': unknown}
            assert expected == _parse_error_as_dict(pe)

    def test_parse_expression_with_WITH(self):
        gpl2, _gpl2plus, lgpl, mit, mitand2, _ = self.get_symbols_and_licensing()
        mitexp = LicenseSymbol('mitexp', ('mit-exp',), is_exception=True)
        gpl_20_or_later = LicenseSymbol('GPL-2.0+', ['The-GNU-GPL-20-or-later'])

        symbols = [gpl2, lgpl, mit, mitand2, mitexp, gpl_20_or_later]
        licensing = Licensing(symbols)
        expr = 'The-GNU-gpl-20-or-later or (LGPL-2.1 and mit) or The-GNU-GPL-20 or mit with mit-exp'
        tokens = list(licensing.tokenize(expr))
        expected = [
            (gpl_20_or_later, 'The-GNU-gpl-20-or-later', 0),
            (TOKEN_OR, 'or', 24),
            (TOKEN_LPAR, '(', 27),
            (lgpl, 'LGPL-2.1', 28),
            (TOKEN_AND, 'and', 37),
            (mit, 'mit', 41),
            (TOKEN_RPAR, ')', 44),
            (TOKEN_OR, 'or', 46),
            (gpl2, 'The-GNU-GPL-20', 49),
            (TOKEN_OR, 'or', 64),
            (LicenseWithExceptionSymbol(mit, mitexp), 'mit with mit-exp', 67)
        ]

        assert expected == tokens

        parsed = licensing.parse(expr)
        expected = 'GPL-2.0+ OR (LGPL-2.1 AND MIT) OR gpl-2.0 OR MIT WITH mitexp'
        assert expected == str(parsed)
        expected = 'GPL-2.0+ OR (LGPL-2.1 AND MIT) OR gpl-2.0 OR MIT WITH mitexp'
        assert expected == parsed.render()

    def test_parse_expression_with_WITH_and_unknown_symbol(self):
        gpl2, _gpl2plus, lgpl, mit, mitand2, _ = self.get_symbols_and_licensing()
        mitexp = LicenseSymbol('mitexp', ('mit exp',), is_exception=True)
        gpl_20_or_later = LicenseSymbol('GPL-2.0+', ['The-GNU-GPL-20-or-later'])

        symbols = [gpl2, lgpl, mit, mitand2, mitexp, gpl_20_or_later]
        licensing = Licensing(symbols)
        expr = 'The-GNU-GPL-20-or-later or (LGPL-2.1 and mit) or The-GNU-GPL-20 or mit with 123'
        parsed = licensing.parse(expr)

        assert ['123'] == licensing.unknown_license_keys(parsed)
        assert ['123'] == licensing.unknown_license_keys(expr)

    def test_unknown_keys(self):
        _gpl2, _gpl2plus, _lgpl, _mit, _mitand2, licensing = self.get_symbols_and_licensing()
        expr = 'The-GNU-GPL-20 or LGPL-2.1 and mit'
        parsed = licensing.parse(expr)
        expected = 'gpl-2.0 OR (LGPL-2.1 AND MIT)'
        assert expected == str(parsed)
        assert 'gpl-2.0 OR (LGPL-2.1 AND MIT)' == parsed.render('{symbol.key}')
        assert [] == licensing.unknown_license_keys(parsed)
        assert [] == licensing.unknown_license_keys(expr)

    def test_unknown_keys_with_trailing_char(self):
        gpl2, _gpl2plus, lgpl, _mit, mitand2, licensing = self.get_symbols_and_licensing()
        expr = 'The-GNU-GPL-20 or LGPL-2.1 and mitand2'
        parsed = licensing.parse(expr)
        expected = [gpl2, lgpl, mitand2]
        assert expected == licensing.license_symbols(parsed)
        assert expected == licensing.license_symbols(licensing.parse(parsed))
        assert expected == licensing.license_symbols(expr)
        assert [] == licensing.unknown_license_keys(parsed)
        assert [] == licensing.unknown_license_keys(expr)

    def test_unknown_keys_with_trailing_char_2(self):
        _gpl2, _gpl2plus, _lgpl, _mit, _mitand2, licensing = self.get_symbols_and_licensing()
        expr = 'The-GNU-GPL-20 or LGPL-2.1 and mit and3'

        try:
            licensing.parse(expr)
            self.fail('ParseError should be raised')
        except ParseError as pe:
            expected = {
                'error_code': 5,
                'position': 35,
                'token_string': 'and3',
                'token_type': LicenseSymbol(key='and3')
            }

            assert expected == _parse_error_as_dict(pe)

    def test_parse_with_overlapping_key_with_licensing(self):
        symbols = [
            LicenseSymbol('MIT', ['MIT-license']),
            LicenseSymbol('LGPL-2.1', ['LGPL-v2.1']),
            LicenseSymbol('zlib', ['zlib']),
            LicenseSymbol('d-zlib', ['D-zlib']),
            LicenseSymbol('mito', ['mit-o']),
            LicenseSymbol('hmit', ['h-verylonglicense']),
        ]
        licensing = Licensing(symbols)

        expression = 'mit or mit AND zlib or mit or mit with verylonglicense'
        results = str(licensing.parse(expression))
        expected = 'MIT OR (MIT AND zlib) OR MIT OR MIT WITH verylonglicense'
        self.assertEqual(expected, results)


class LicensingSymbolsTest(TestCase):

    def test_get_license_symbols(self):
        symbols = [
            LicenseSymbol('GPL-2.0'),
            LicenseSymbol('mit'),
            LicenseSymbol('LGPL-2.1')
        ]
        l = Licensing(symbols)
        assert symbols == l.license_symbols(l.parse(' GPL-2.0 and mit or LGPL-2.1 and mit '))

    def test_get_license_symbols2(self):
        symbols = [
            LicenseSymbol('GPL-2.0'),
            LicenseSymbol('LATER'),
            LicenseSymbol('mit'),
            LicenseSymbol('LGPL-2.1+'),
            LicenseSymbol('Foo-exception', is_exception=True),
        ]
        l = Licensing(symbols)
        expr = ' GPL-2.0 or LATER and mit or LGPL-2.1+ and mit with Foo-exception '
        expected = [
            LicenseSymbol('GPL-2.0'),
            LicenseSymbol('LATER'),
            LicenseSymbol('mit'),
            LicenseSymbol('LGPL-2.1+'),
            LicenseSymbol('mit'),
            LicenseSymbol('Foo-exception', is_exception=True),
        ]
        assert expected == l.license_symbols(l.parse(expr), unique=False)

    def test_get_license_symbols3(self):
        symbols = [
            LicenseSymbol('mit'),
            LicenseSymbol('LGPL-2.1+'),
            LicenseSymbol('Foo-exception', is_exception=True),
            LicenseSymbol('GPL-2.0'),
            LicenseSymbol('LATER'),
        ]
        l = Licensing(symbols)
        expr = 'mit or LGPL-2.1+ and mit with Foo-exception or GPL-2.0 or LATER '
        assert symbols == l.license_symbols(l.parse(expr))

    def test_get_license_symbols4(self):
        symbols = [
            LicenseSymbol('GPL-2.0'),
            LicenseSymbol('LATER'),
            LicenseSymbol('big-exception', is_exception=True),
            LicenseSymbol('mit'),
            LicenseSymbol('LGPL-2.1+'),
            LicenseSymbol('Foo-exception', is_exception=True),
        ]
        l = Licensing(symbols)
        expr = (' GPL-2.0 or LATER with big-exception and mit or '
                'LGPL-2.1+ and mit or later with Foo-exception ')
        expected = [
            LicenseSymbol('GPL-2.0'),
            LicenseSymbol('LATER'),
            LicenseSymbol('big-exception', is_exception=True),
            LicenseSymbol('mit'),
            LicenseSymbol('LGPL-2.1+'),
            LicenseSymbol('mit'),
            LicenseSymbol('LATER'),
            LicenseSymbol('Foo-exception', is_exception=True),
        ]

        assert expected == l.license_symbols(l.parse(expr), unique=False)

    def test_get_license_symbols5(self):
        l = Licensing()
        expr = (' GPL-2.0 or LATER with big-exception and mit or '
                'LGPL-2.1+ and mit or later with Foo-exception ')
        expected = [
            LicenseSymbol('GPL-2.0'),
            LicenseSymbol('LATER'),
            LicenseSymbol('big-exception', is_exception=False),
            LicenseSymbol('mit'),
            LicenseSymbol('LGPL-2.1+'),
            LicenseSymbol('mit'),
            LicenseSymbol('later'),
            LicenseSymbol('Foo-exception', is_exception=False),
        ]

        assert expected == l.license_symbols(l.parse(expr), unique=False)

    def test_license_symbols(self):
        licensing = Licensing([
            'GPL-2.0-or-LATER',
            'classpath-Exception',
            'something-with-else+',
            'mit',
            'LGPL-2.1',
            'mit-or-later'
        ])

        expr = (' GPL-2.0-or-LATER with classpath-Exception and mit and '
                'mit with SOMETHING-with-ELSE+ or LGPL-2.1 and '
                'GPL-2.0-or-LATER with classpath-Exception and '
                'mit-or-later or LGPL-2.1 or mit or GPL-2.0-or-LATER '
                'with SOMETHING-with-ELSE+ and lgpl-2.1')

        gpl2plus = LicenseSymbol(key='GPL-2.0-or-LATER')
        cpex = LicenseSymbol(key='classpath-Exception')
        someplus = LicenseSymbol(key='something-with-else+')
        mitplus = LicenseSymbol(key='mit-or-later')
        mit = LicenseSymbol(key='mit')
        lgpl = LicenseSymbol(key='LGPL-2.1')
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
            'GPL-2.0-or-LATER',
            'classpath-Exception',
            'mit',
            'LGPL-2.1',
            'mit-or-later'
        ])

        expr = ' GPL-2.0-or-LATER with classpath-Exception and mit or LGPL-2.1 and mit-or-later '
        gpl = LicenseSymbol('GPL-2.0-or-LATER')
        cpex = LicenseSymbol('classpath-Exception')
        expected = LicenseWithExceptionSymbol(gpl, cpex)
        parsed = licensing.parse(expr)
        assert expected == licensing.primary_license_symbol(parsed, decompose=False)
        assert gpl == licensing.primary_license_symbol(parsed, decompose=True)
        assert 'GPL-2.0-or-LATER' == licensing.primary_license_key(parsed)

        expr = ' GPL-2.0-or-later with classpath-Exception and mit or LGPL-2.1 and mit-or-later '
        expected = 'GPL-2.0-or-LATER WITH classpath-Exception'
        assert expected == licensing.primary_license_symbol(
            parsed, decompose=False).render('{symbol.key}')


class SplitAndTokenizeTest(TestCase):

    def test_splitter(self):
        expr = (' GPL-2.0 or later with classpath Exception and mit and '
                'mit with SOMETHING with ELSE+ or LGPL 2.1 and '
                'GPL-2.0 or LATER with (Classpath Exception and '
                'mit or later) or LGPL 2.1 or mit or GPL-2.0 or LATER '
                'with SOMETHING with ELSE+ and lgpl 2.1')
        results = list(splitter(expr))
        expected = [
            Result(0, 0, ' ', None),
            Result(1, 7, 'GPL-2.0', Output('GPL-2.0', LicenseSymbol(key='GPL-2.0',))),
            Result(8, 8, ' ', None),
            Result(9, 10, 'or', Output('or', Keyword(value='or', type=TOKEN_OR))),
            Result(11, 11, ' ', None),
            Result(12, 16, 'later', Output('later', LicenseSymbol(key='later',))),
            Result(17, 17, ' ', None),
            Result(18, 21, 'with', Output('with', Keyword(value='with', type=TOKEN_WITH))),
            Result(22, 22, ' ', None),
            Result(23, 31, 'classpath', Output('classpath', LicenseSymbol(key='classpath',))),
            Result(32, 32, ' ', None),
            Result(33, 41, 'Exception', Output('Exception', LicenseSymbol(key='Exception',))),
            Result(42, 42, ' ', None),
            Result(43, 45, 'and', Output('and', Keyword(value='and', type=TOKEN_AND))),
            Result(46, 46, ' ', None),
            Result(47, 49, 'mit', Output('mit', LicenseSymbol(key='mit',))),
            Result(50, 50, ' ', None),
            Result(51, 53, 'and', Output('and', Keyword(value='and', type=TOKEN_AND))),
            Result(54, 54, ' ', None),
            Result(55, 57, 'mit', Output('mit', LicenseSymbol(key='mit',))),
            Result(58, 58, ' ', None),
            Result(59, 62, 'with', Output('with', Keyword(value='with', type=TOKEN_WITH))),
            Result(63, 63, ' ', None),
            Result(64, 72, 'SOMETHING', Output('SOMETHING', LicenseSymbol(key='SOMETHING',))),
            Result(73, 73, ' ', None),
            Result(74, 77, 'with', Output('with', Keyword(value='with', type=TOKEN_WITH))),
            Result(78, 78, ' ', None),
            Result(79, 83, 'ELSE+', Output('ELSE+', LicenseSymbol(key='ELSE+',))),
            Result(84, 84, ' ', None),
            Result(85, 86, 'or', Output('or', Keyword(value='or', type=TOKEN_OR))),
            Result(87, 87, ' ', None),
            Result(88, 91, 'LGPL', Output('LGPL', LicenseSymbol(key='LGPL',))),
            Result(92, 92, ' ', None),
            Result(93, 95, '2.1', Output('2.1', LicenseSymbol(key='2.1',))),
            Result(96, 96, ' ', None),
            Result(97, 99, 'and', Output('and', Keyword(value='and', type=TOKEN_AND))),
            Result(100, 100, ' ', None),
            Result(101, 107, 'GPL-2.0', Output('GPL-2.0', LicenseSymbol(key='GPL-2.0',))),
            Result(108, 108, ' ', None),
            Result(109, 110, 'or', Output('or', Keyword(value='or', type=TOKEN_OR))),
            Result(111, 111, ' ', None),
            Result(112, 116, 'LATER', Output('LATER', LicenseSymbol(key='LATER',))),
            Result(117, 117, ' ', None),
            Result(118, 121, 'with', Output('with', Keyword(value='with', type=TOKEN_WITH))),
            Result(122, 122, ' ', None),
            Result(123, 123, '(', Output('(', Keyword(value='(', type=TOKEN_LPAR))),
            Result(124, 132, 'Classpath', Output('Classpath', LicenseSymbol(key='Classpath',))),
            Result(133, 133, ' ', None),
            Result(134, 142, 'Exception', Output('Exception', LicenseSymbol(key='Exception',))),
            Result(143, 143, ' ', None),
            Result(144, 146, 'and', Output('and', Keyword(value='and', type=TOKEN_AND))),
            Result(147, 147, ' ', None),
            Result(148, 150, 'mit', Output('mit', LicenseSymbol(key='mit',))),
            Result(151, 151, ' ', None),
            Result(152, 153, 'or', Output('or', Keyword(value='or', type=TOKEN_OR))),
            Result(154, 154, ' ', None),
            Result(155, 159, 'later', Output('later', LicenseSymbol(key='later',))),
            Result(160, 160, ')', Output(')', Keyword(value=')', type=TOKEN_RPAR))),
            Result(161, 161, ' ', None),
            Result(162, 163, 'or', Output('or', Keyword(value='or', type=TOKEN_OR))),
            Result(164, 164, ' ', None),
            Result(165, 168, 'LGPL', Output('LGPL', LicenseSymbol(key='LGPL',))),
            Result(169, 169, ' ', None),
            Result(170, 172, '2.1', Output('2.1', LicenseSymbol(key='2.1',))),
            Result(173, 173, ' ', None),
            Result(174, 175, 'or', Output('or', Keyword(value='or', type=TOKEN_OR))),
            Result(176, 176, ' ', None),
            Result(177, 179, 'mit', Output('mit', LicenseSymbol(key='mit',))),
            Result(180, 180, ' ', None),
            Result(181, 182, 'or', Output('or', Keyword(value='or', type=TOKEN_OR))),
            Result(183, 183, ' ', None),
            Result(184, 190, 'GPL-2.0', Output('GPL-2.0', LicenseSymbol(key='GPL-2.0',))),
            Result(191, 191, ' ', None),
            Result(192, 193, 'or', Output('or', Keyword(value='or', type=TOKEN_OR))),
            Result(194, 194, ' ', None),
            Result(195, 199, 'LATER', Output('LATER', LicenseSymbol(key='LATER',))),
            Result(200, 200, ' ', None),
            Result(201, 204, 'with', Output('with', Keyword(value='with', type=TOKEN_WITH))),
            Result(205, 205, ' ', None),
            Result(206, 214, 'SOMETHING', Output('SOMETHING', LicenseSymbol(key='SOMETHING',))),
            Result(215, 215, ' ', None),
            Result(216, 219, 'with', Output('with', Keyword(value='with', type=TOKEN_WITH))),
            Result(220, 220, ' ', None),
            Result(221, 225, 'ELSE+', Output('ELSE+', LicenseSymbol(key='ELSE+',))),
            Result(226, 226, ' ', None),
            Result(227, 229, 'and', Output('and', Keyword(value='and', type=TOKEN_AND))),
            Result(230, 230, ' ', None),
            Result(231, 234, 'lgpl', Output('lgpl', LicenseSymbol(key='lgpl',))),
            Result(235, 235, ' ', None),
            Result(236, 238, '2.1', Output('2.1', LicenseSymbol(key='2.1',)))
        ]
        assert expected == results

    def test_tokenize_step_by_step_does_not_munge_trailing_symbols(self):
        gpl2 = LicenseSymbol(key='GPL-2.0')
        gpl2plus = LicenseSymbol(key='GPL-2.0-or-LATER')
        cpex = LicenseSymbol(key='classpath-Exception', is_exception=True)

        mitthing = LicenseSymbol(key='mithing')
        mitthing_with_else = LicenseSymbol(key='mitthing-with-else+', is_exception=False)

        mit = LicenseSymbol(key='mit')
        mitplus = LicenseSymbol(key='mit-or-later')

        elsish = LicenseSymbol(key='else')
        elsishplus = LicenseSymbol(key='else+')

        lgpl = LicenseSymbol(key='LGPL-2.1')

        licensing = Licensing([
            gpl2,
            gpl2plus,
            cpex,
            mitthing,
            mitthing_with_else,
            mit,
            mitplus,
            elsish,
            elsishplus,
            lgpl,
        ])

        expr = (' GPL-2.0-or-later with classpath-Exception and mit and '
                'mit with mitthing-with-ELSE+ or LGPL-2.1 and '
                'GPL-2.0-or-LATER with Classpath-Exception and '
                'mit-or-later or LGPL-2.1 or mit or GPL-2.0-or-LATER '
                'with mitthing-with-ELSE+ and lgpl-2.1 or gpl-2.0')

        # fist scan
        result = list(splitter(expr, licensing.symbols_by_key))

        WITH_KW = Keyword(value=' with ', type=10)
        AND_KW = Keyword(value=' and ', type=1)
        OR_KW = Keyword(value=' or ', type=2)

        expected = [
            Result(0, 0, u' ', None),
            Result(1, 16, u'GPL-2.0-or-later', Output(u'GPL-2.0-or-later', LicenseSymbol(u'GPL-2.0-or-LATER', is_exception=False))),
            Result(17, 17, u' ', None),
            Result(18, 21, u'with', Output(u'with', Keyword(value=u'with', type=10))),
            Result(22, 22, u' ', None),
            Result(23, 41, u'classpath-Exception', Output(u'classpath-Exception', LicenseSymbol(u'classpath-Exception', is_exception=True))),
            Result(42, 42, u' ', None),
            Result(43, 45, u'and', Output(u'and', Keyword(value=u'and', type=1))),
            Result(46, 46, u' ', None),
            Result(47, 49, u'mit', Output(u'mit', LicenseSymbol(u'mit', is_exception=False))),
            Result(50, 50, u' ', None),
            Result(51, 53, u'and', Output(u'and', Keyword(value=u'and', type=1))),
            Result(54, 54, u' ', None),
            Result(55, 57, u'mit', Output(u'mit', LicenseSymbol(u'mit', is_exception=False))),
            Result(58, 58, u' ', None),
            Result(59, 62, u'with', Output(u'with', Keyword(value=u'with', type=10))),
            Result(63, 63, u' ', None),
            Result(64, 82, u'mitthing-with-ELSE+', Output(u'mitthing-with-ELSE+', LicenseSymbol(u'mitthing-with-else+', is_exception=False))),
            Result(83, 83, u' ', None),
            Result(84, 85, u'or', Output(u'or', Keyword(value=u'or', type=2))),
            Result(86, 86, u' ', None),
            Result(87, 94, u'LGPL-2.1', Output(u'LGPL-2.1', LicenseSymbol(u'LGPL-2.1', is_exception=False))),
            Result(95, 95, u' ', None),
            Result(96, 98, u'and', Output(u'and', Keyword(value=u'and', type=1))),
            Result(99, 99, u' ', None),
            Result(100, 115, u'GPL-2.0-or-LATER', Output(u'GPL-2.0-or-LATER', LicenseSymbol(u'GPL-2.0-or-LATER', is_exception=False))),
            Result(116, 116, u' ', None),
            Result(117, 120, u'with', Output(u'with', Keyword(value=u'with', type=10))),
            Result(121, 121, u' ', None),
            Result(122, 140, u'Classpath-Exception', Output(u'Classpath-Exception', LicenseSymbol(u'classpath-Exception', is_exception=True))),
            Result(141, 141, u' ', None),
            Result(142, 144, u'and', Output(u'and', Keyword(value=u'and', type=1))),
            Result(145, 145, u' ', None),
            Result(146, 157, u'mit-or-later', Output(u'mit-or-later', LicenseSymbol(u'mit-or-later', is_exception=False))),
            Result(158, 158, u' ', None),
            Result(159, 160, u'or', Output(u'or', Keyword(value=u'or', type=2))),
            Result(161, 161, u' ', None),
            Result(162, 169, u'LGPL-2.1', Output(u'LGPL-2.1', LicenseSymbol(u'LGPL-2.1', is_exception=False))),
            Result(170, 170, u' ', None),
            Result(171, 172, u'or', Output(u'or', Keyword(value=u'or', type=2))),
            Result(173, 173, u' ', None),
            Result(174, 176, u'mit', Output(u'mit', LicenseSymbol(u'mit', is_exception=False))),
            Result(177, 177, u' ', None),
            Result(178, 179, u'or', Output(u'or', Keyword(value=u'or', type=2))),
            Result(180, 180, u' ', None),
            Result(181, 196, u'GPL-2.0-or-LATER', Output(u'GPL-2.0-or-LATER', LicenseSymbol(u'GPL-2.0-or-LATER', is_exception=False))),
            Result(197, 197, u' ', None),
            Result(198, 201, u'with', Output(u'with', Keyword(value=u'with', type=10))),
            Result(202, 202, u' ', None),
            Result(203, 221, u'mitthing-with-ELSE+', Output(u'mitthing-with-ELSE+', LicenseSymbol(u'mitthing-with-else+', is_exception=False))),
            Result(222, 222, u' ', None),
            Result(223, 225, u'and', Output(u'and', Keyword(value=u'and', type=1))),
            Result(226, 226, u' ', None),
            Result(227, 234, u'lgpl-2.1', Output(u'lgpl-2.1', LicenseSymbol(u'LGPL-2.1', is_exception=False))),
            Result(235, 235, u' ', None),
            Result(236, 237, u'or', Output(u'or', Keyword(value=u'or', type=2))),
            Result(238, 238, u' ', None),
            Result(239, 245, u'gpl-2.0', Output(u'gpl-2.0', LicenseSymbol(u'GPL-2.0', is_exception=False)))
        ]

        assert expected == result
        assert 246 == expected[-1].end + 1
        assert 246 == sum(len(r.string) for r in result)

        # skip spaces
        result = list(strip_and_skip_spaces(result))
        # here only the first token is a space
        expected_no_spaces = [r for r in expected if r.output]
        assert expected_no_spaces == result

        # group results

        expected_groups = [
            (Result(1, 16, u'GPL-2.0-or-later', Output(u'GPL-2.0-or-later', LicenseSymbol(u'GPL-2.0-or-LATER', is_exception=False))),
             Result(18, 21, u'with', Output(u'with', Keyword(value=u'with', type=10))),
             Result(23, 41, u'classpath-Exception', Output(u'classpath-Exception', LicenseSymbol(u'classpath-Exception', is_exception=True)))),
            (Result(43, 45, u'and', Output(u'and', Keyword(value=u'and', type=1))),),
            (Result(47, 49, u'mit', Output(u'mit', LicenseSymbol(u'mit', is_exception=False))),),
            (Result(51, 53, u'and', Output(u'and', Keyword(value=u'and', type=1))),),
            (Result(55, 57, u'mit', Output(u'mit', LicenseSymbol(u'mit', is_exception=False))),
             Result(59, 62, u'with', Output(u'with', Keyword(value=u'with', type=10))),
             Result(64, 82, u'mitthing-with-ELSE+', Output(u'mitthing-with-ELSE+', LicenseSymbol(u'mitthing-with-else+', is_exception=False)))),
            (Result(84, 85, u'or', Output(u'or', Keyword(value=u'or', type=2))),),
            (Result(87, 94, u'LGPL-2.1', Output(u'LGPL-2.1', LicenseSymbol(u'LGPL-2.1', is_exception=False))),),
            (Result(96, 98, u'and', Output(u'and', Keyword(value=u'and', type=1))),),
            (Result(100, 115, u'GPL-2.0-or-LATER', Output(u'GPL-2.0-or-LATER', LicenseSymbol(u'GPL-2.0-or-LATER', is_exception=False))),
             Result(117, 120, u'with', Output(u'with', Keyword(value=u'with', type=10))),
             Result(122, 140, u'Classpath-Exception', Output(u'Classpath-Exception', LicenseSymbol(u'classpath-Exception', is_exception=True)))),
            (Result(142, 144, u'and', Output(u'and', Keyword(value=u'and', type=1))),),
            (Result(146, 157, u'mit-or-later', Output(u'mit-or-later', LicenseSymbol(u'mit-or-later', is_exception=False))),),
            (Result(159, 160, u'or', Output(u'or', Keyword(value=u'or', type=2))),),
            (Result(162, 169, u'LGPL-2.1', Output(u'LGPL-2.1', LicenseSymbol(u'LGPL-2.1', is_exception=False))),),
            (Result(171, 172, u'or', Output(u'or', Keyword(value=u'or', type=2))),),
            (Result(174, 176, u'mit', Output(u'mit', LicenseSymbol(u'mit', is_exception=False))),),
            (Result(178, 179, u'or', Output(u'or', Keyword(value=u'or', type=2))),),
            (Result(181, 196, u'GPL-2.0-or-LATER', Output(u'GPL-2.0-or-LATER', LicenseSymbol(u'GPL-2.0-or-LATER', is_exception=False))),
             Result(198, 201, u'with', Output(u'with', Keyword(value=u'with', type=10))),
             Result(203, 221, u'mitthing-with-ELSE+', Output(u'mitthing-with-ELSE+', LicenseSymbol(u'mitthing-with-else+', is_exception=False)))),
            (Result(223, 225, u'and', Output(u'and', Keyword(value=u'and', type=1))),),
            (Result(227, 234, u'lgpl-2.1', Output(u'lgpl-2.1', LicenseSymbol(u'LGPL-2.1', is_exception=False))),),
            (Result(236, 237, u'or', Output(u'or', Keyword(value=u'or', type=2))),),
            (Result(239, 245, u'gpl-2.0', Output(u'gpl-2.0', LicenseSymbol(u'GPL-2.0', is_exception=False))),)
        ]

        result_groups = list(group_results_for_with_subexpression(result))
        assert expected_groups == result_groups

        # finally retest it all with tokenize
        gpl2plus_with_cpex = LicenseWithExceptionSymbol(license_symbol=gpl2plus, exception_symbol=cpex)
        gpl2plus_with_someplus = LicenseWithExceptionSymbol(license_symbol=gpl2plus, exception_symbol=mitthing_with_else)
        mit_with_mitthing_with_else = LicenseWithExceptionSymbol(license_symbol=mit, exception_symbol=mitthing_with_else)

        expected = [
            (gpl2plus_with_cpex,
             u'GPL-2.0-or-later with classpath-Exception',
             1),
            (1, u'and', 43),
            (LicenseSymbol(u'mit', is_exception=False), u'mit', 47),
            (1, u'and', 51),
            (mit_with_mitthing_with_else,
             u'mit with mitthing-with-ELSE+',
             55),
            (2, u'or', 84),
            (LicenseSymbol(u'LGPL-2.1', is_exception=False), u'LGPL-2.1', 87),
            (1, u'and', 96),
            (gpl2plus_with_cpex,
             u'GPL-2.0-or-LATER with Classpath-Exception',
             100),
            (1, u'and', 142),
            (LicenseSymbol(u'mit-or-later', is_exception=False), u'mit-or-later', 146),
            (2, u'or', 159),
            (LicenseSymbol(u'LGPL-2.1', is_exception=False), u'LGPL-2.1', 162),
            (2, u'or', 171),
            (LicenseSymbol(u'mit', is_exception=False), u'mit', 174),
            (2, u'or', 178),
            (gpl2plus_with_someplus,
             u'GPL-2.0-or-LATER with mitthing-with-ELSE+',
             181),
            (1, u'and', 223),
            (LicenseSymbol(u'LGPL-2.1', is_exception=False), u'lgpl-2.1', 227),
            (2, u'or', 236),
            (gpl2, u'gpl-2.0', 239)
        ]
        assert expected == list(licensing.tokenize(expr))


class LicensingExpressionTest(TestCase):

    def test_is_equivalent_with_same_Licensing(self):
        licensing = Licensing()
        parsed1 = licensing.parse('gpl-2.0 AND zlib')
        parsed2 = licensing.parse('gpl-2.0 AND zlib AND zlib')
        assert licensing.is_equivalent(parsed1, parsed2)
        assert Licensing().is_equivalent(parsed1, parsed2)

    def test_is_equivalent_with_same_Licensing2(self):
        licensing = Licensing()
        parsed1 = licensing.parse('(gpl-2.0 AND zlib) or lgpl')
        parsed2 = licensing.parse('lgpl or (gpl-2.0 AND zlib)')
        assert licensing.is_equivalent(parsed1, parsed2)
        assert Licensing().is_equivalent(parsed1, parsed2)

    def test_is_equivalent_with_different_Licensing_and_compound_expression(self):
        licensing1 = Licensing()
        licensing2 = Licensing()
        parsed1 = licensing1.parse('gpl-2.0 AND zlib')
        parsed2 = licensing2.parse('gpl-2.0 AND zlib AND zlib')
        assert Licensing().is_equivalent(parsed1, parsed2)
        assert licensing1.is_equivalent(parsed1, parsed2)
        assert licensing2.is_equivalent(parsed1, parsed2)

    def test_is_equivalent_with_different_Licensing_and_compound_expression2(self):
        licensing1 = Licensing()
        licensing2 = Licensing()
        parsed1 = licensing1.parse('gpl-2.0 AND zlib')
        parsed2 = licensing2.parse('zlib and gpl-2.0')
        assert Licensing().is_equivalent(parsed1, parsed2)
        assert licensing1.is_equivalent(parsed1, parsed2)
        assert licensing2.is_equivalent(parsed1, parsed2)

    def test_is_equivalent_with_different_Licensing_and_simple_expression(self):
        licensing1 = Licensing()
        licensing2 = Licensing()
        parsed1 = licensing1.parse('gpl-2.0')
        parsed2 = licensing2.parse('gpl-2.0')
        assert Licensing().is_equivalent(parsed1, parsed2)
        assert licensing1.is_equivalent(parsed1, parsed2)
        assert licensing2.is_equivalent(parsed1, parsed2)

    def test_is_equivalent_with_symbols_and_complex_expression(self):
        licensing_no_sym = Licensing()
        licensing1 = Licensing([
            'GPL-2.0-or-LATER',
            'classpath-Exception',
            'agpl+',
            'mit',
            'LGPL-2.1',
        ])
        licensing2 = Licensing([
            'GPL-2.0-or-LATER',
            'classpath-Exception',
            'agpl+',
            'mit',
            'LGPL-2.1',
        ])

        parsed1 = licensing1.parse(' ((LGPL-2.1 or mit) and GPL-2.0-or-LATER with classpath-Exception) and agpl+')
        parsed2 = licensing2.parse(' agpl+ and (GPL-2.0-or-LATER with classpath-Exception and (mit  or LGPL-2.1))')
        assert licensing1.is_equivalent(parsed1, parsed2)
        assert licensing2.is_equivalent(parsed1, parsed2)
        assert licensing_no_sym.is_equivalent(parsed1, parsed2)

        parsed3 = licensing1.parse(' ((LGPL-2.1 or mit) OR GPL-2.0-or-LATER with classpath-Exception) and agpl+')
        assert not licensing1.is_equivalent(parsed1, parsed3)
        assert not licensing2.is_equivalent(parsed1, parsed3)
        assert not licensing_no_sym.is_equivalent(parsed1, parsed3)

    def test_all_symbol_classes_can_compare_and_sort(self):
        l1 = LicenseSymbol('a')
        l2 = LicenseSymbol('b')
        lx = LicenseWithExceptionSymbol(l1, l2)
        lx2 = LicenseWithExceptionSymbol(l1, l2)
        assert not (lx < lx2)
        assert not (lx2 < lx)
        assert lx2 == lx
        assert not (lx2 != lx)
        assert l1 < l2
        assert l2 > l1
        assert not (l2 == l1)
        assert l2 != l1

        class SymLike(object):

            def __init__(self, key, is_exception=False):
                self.key = key
                self.is_exception = is_exception

        l3 = LicenseSymbolLike(SymLike('b'))
        lx3 = LicenseWithExceptionSymbol(l1, l3)
        assert not (lx < lx3)
        assert not (lx3 < lx)
        assert lx3 == lx
        assert hash(lx3) == hash(lx)
        assert not (lx3 != lx)

        assert l2 == l3
        assert hash(l2) == hash(l3)

        l4 = LicenseSymbolLike(SymLike('c'))

        expected = [l1, lx, lx2, lx3, l3, l2, l4]
        assert expected == sorted([l4, l3, l2, l1, lx , lx2, lx3])
