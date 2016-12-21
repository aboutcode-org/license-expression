# license-expression is a free software tool from nexB Inc. and others.
# Visit https://github.com/nexB/license-expression for support and download.
#
# Copyright (c) 2016 nexB Inc. and others. All rights reserved.
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

from unittest import TestCase
import sys

import license_expression
from license_expression import ExpressionError
from license_expression import Licensing
from license_expression import LicenseExpression
from license_expression import ParseError
from license_expression import PARSE_INVALID_EXPRESSION
from license_expression import PARSE_INVALID_NESTING


py2 = sys.version_info[0] == 2
py3 = sys.version_info[0] == 3


class LicenseExpressionTestCase(TestCase):
    def test_license_expression_parse(self):
        expression = ' ( (( gpl and bsd ) or lgpl)  and gpl-exception) '
        expected = '((gpl AND bsd) OR lgpl) AND gpl-exception'
        licensing = Licensing()
        self.assertEqual(expected, str(licensing.parse(expression)))

    def test_license_expression_parse_raise_ParseError(self):
        expression = ' ( (( gpl and bsd ) or lgpl)  and gpl-exception)) '
        licensing = Licensing()
        try:
            licensing.parse(expression)
            self.fail('ParseError should be raised')
        except ParseError:
            pass

    def test_license_expression_parse_does_not_raise_error_for_empty_expression(self):
        licensing = Licensing()
        self.assertEqual('', licensing.parse(''))

    def test_license_expression_license_keys(self):
        licensing = Licensing()
        self.assertEqual(['mit', 'gpl'], licensing.license_keys(' ( mit ) and gpl'))
        self.assertEqual(['mit', 'gpl'], licensing.license_keys('(mit and gpl)'))
        # these two are surprising for now: this is because the expression is a
        # logical expression so the order may be different on more complex expressions
        self.assertEqual(['mit', 'gpl'], licensing.license_keys('mit AND gpl or gpl'))
        self.assertEqual(['l-a +', 'l-b', 'l -c+'], licensing.license_keys('((l-a + AND l-b) OR (l -c+))'))

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


class LicenseExpressionValidatorTestCase(TestCase):

    def test_clean_and_validate_refs(self):
        license_refs = [
            license_expression.LicenseRef('l-a', None, [], False),
            license_expression.LicenseRef('l-a+', 'L-a+', ['l-a +'], False),
            license_expression.LicenseRef('l-a+', None, [], True),
            license_expression.LicenseRef('l-b', None, [], False),
            license_expression.LicenseRef('l-c', None, [], False),
        ]
        keys, aliases, exceptions, errors = license_expression.clean_and_validate_refs(license_refs)
        assert {'l-a': 'l-a', 'l-a+': 'l-a+', 'l-b': 'l-b', 'l-c': 'l-c'} == keys
        assert {'l-a': 'l-a', 'l-a +': 'l-a+', 'l-a+': 'l-a+', 'l-b': 'l-b', 'l-c': 'l-c'} == aliases
        assert set(['l-a+']) == exceptions

        if py2:
            expected = [
                "Invalid duplicated license key: u'l-a+'.",
                "Invalid duplicated license name: u'l-a+'.",
            ]
        if py3:
            expected = [
                "Invalid duplicated license key: 'l-a+'.",
                "Invalid duplicated license name: 'l-a+'.",
            ]

        assert expected == errors

    def test_parse_and_resolve_license_expression(self):
        license_refs = [

            license_expression.LicenseRef('l-a', None, [], False),
            license_expression.LicenseRef('l-a+', 'L-a+', ['l-a +'], False),
            license_expression.LicenseRef('l-b', None, [], False),
            license_expression.LicenseRef('l-c', None, [], False),
        ]
        licensing = Licensing(license_refs)

        valid_input = [
            'l-a',
            'l-a +',
            '(l-a)',
            '((l-a+ AND l-b) OR (l-c))',
            'l-a and l-b',
            'l-a or l-b',
            'l-a and l-b OR l-c',
        ]
        for expr in valid_input:
            expp = licensing.parse(expr, resolve=True)
            assert [] == licensing.unresolved_keys(expp)
            assert [] == licensing.resolution_errors(expp)

    def test_parse_invalid_expression_raise_expression(self):
        licensing = Licensing()

        invalid_input = [
            'wrong',
            'l-a AND none',
            '(l-a + AND l-b',
            '(l-a + AND l-b))',
            'l-a AND',
            'OR l-a',
            '+ l-a',
        ]

        for expr in invalid_input:
            try:
                licensing.parse(expr, resolve=True)
                self.fail("Exception not raised when validating '%s'" % expr)
            except (ExpressionError, ParseError):
                pass


class LicensingTestCase(TestCase):
    def test_parse_can_parse_(self):
        lx = license_expression
        licensing = lx.Licensing()
        LicSym = licensing.LicenseSymbol

        expr = licensing.parse(' GPL-2.0 or LGPL 2.1 and mit ')
        expected = [LicSym('GPL-2.0'), LicSym('LGPL 2.1'), LicSym('mit')]
        self.assertEqual(expected, licensing.license_symbols(expr))
        self.assertEqual('GPL-2.0 OR (LGPL 2.1 AND mit)', str(expr))

        expected = licensing.OR(
          LicSym('GPL-2.0'),
          licensing.AND(
            LicSym('LGPL 2.1'),
            LicSym('mit')
          )
        )
        self.assertEqual(expected, expr)

    def test_simplify_and_contain_and_equal(self):
        lx = license_expression
        licensing = lx.Licensing()

        expr = licensing.parse(' GPL-2.0 or LGPL 2.1 and mit ')

        expr2 = licensing.parse(' (mit and LGPL 2.1) or GPL-2.0 ')
        self.assertEqual(expr2.simplify(), expr.simplify())
        self.assertEqual(expr2, expr)

        expr3 = licensing.parse('mit and LGPL 2.1')
        self.assertTrue(expr3 in expr2)

    def test_parse_errors_catch_invalid_nesting(self):
        lx = license_expression
        licensing = lx.Licensing()

        try:
            licensing.parse('mit (and LGPL 2.1)')
            self.fail('Exception not raised')
        except ParseError as pe:
            self.assertEqual(PARSE_INVALID_NESTING, pe.error_code)

    def test_parse_errors_catch_invalid_expression_with_bare_and(self):
        lx = license_expression
        licensing = lx.Licensing()

        try:
            licensing.parse('and')
            self.fail('Exception not raised')
        except ParseError as pe:
            self.assertEqual(PARSE_INVALID_EXPRESSION, pe.error_code)

    def test_parse_errors_catch_invalid_expression_with_or_and_no_other(self):
        lx = license_expression
        licensing = lx.Licensing()
        try:
            licensing.parse('or that')
            self.fail('Exception not raised')
        except ParseError as pe:
            self.assertEqual(PARSE_INVALID_EXPRESSION, pe.error_code)

    def test_parse_errors_catch_invalid_expression_with_empty_parens(self):
        lx = license_expression
        licensing = lx.Licensing()

        try:
            licensing.parse('with ( )this')
            self.fail('Exception not raised')
        except ParseError as pe:
            self.assertEqual(PARSE_INVALID_NESTING, pe.error_code)
            self.assertEqual("Invalid expression nesting such as (AND xx) for token: '(' at position: 5.", str(pe))

    def test_parse_errors_catch_invalid_non_unicode_byte_strings(self):
        lx = license_expression
        licensing = lx.Licensing()

        if py2:
            extra_bytes = bytes(chr(0) + chr(12) + chr(255))
        if py3:
            extra_bytes = bytes(chr(0) + chr(12) + chr(255), encoding='utf-8')

        try:
            licensing.parse('mit (and LGPL 2.1)'.encode('utf-8') + extra_bytes)

            self.fail('Exception not raised')
        except ParseError as pe:
            self.assertEqual(license_expression.PARSE_UNKNOWN_TOKEN, pe.error_code)
            if py2:
                expected = "Unknown token for token: '\\x00' at position: 18."
            if py3:
                expected = '''Unknown token for token: "'" at position: 1.'''
            self.assertEqual(expected, str(pe))

    def test_parse_errors_does_not_raise_error_on_plain_non_unicode_raw_string(self):
        # plain non-unicode string does not raise error
        lx = license_expression
        licensing = lx.Licensing()
        x = licensing.parse(r'mit and (LGPL 2.1)')
        self.assertTrue(isinstance(x, LicenseExpression))
