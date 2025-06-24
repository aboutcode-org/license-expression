#
# Copyright (c) nexB Inc. and others. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/license-expression for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import json
import pathlib
import sys
from collections import namedtuple
from os.path import abspath
from os.path import join
from os.path import dirname
from unittest import TestCase

from boolean.boolean import PARSE_UNBALANCED_CLOSING_PARENS
from boolean.boolean import PARSE_INVALID_SYMBOL_SEQUENCE

from license_expression import PARSE_INVALID_EXPRESSION
from license_expression import PARSE_INVALID_NESTING
from license_expression import PARSE_INVALID_EXCEPTION
from license_expression import PARSE_INVALID_SYMBOL_AS_EXCEPTION
from license_expression import PARSE_INVALID_OPERATOR_SEQUENCE

from license_expression import ExpressionError
from license_expression import Keyword
from license_expression import Licensing
from license_expression import LicenseExpression
from license_expression import LicenseSymbol
from license_expression import LicenseSymbolLike
from license_expression import LicenseWithExceptionSymbol
from license_expression import ParseError
from license_expression import Token

from license_expression import build_token_groups_for_with_subexpression
from license_expression import validate_symbols

from license_expression import TOKEN_AND
from license_expression import TOKEN_LPAR
from license_expression import TOKEN_OR
from license_expression import TOKEN_RPAR
from license_expression import TOKEN_SYMBOL
from license_expression import TOKEN_WITH
from license_expression import build_licensing
from license_expression import build_spdx_licensing
from license_expression import combine_expressions
from license_expression import get_license_index


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
        sym1 = LicenseSymbol("MIT", ["MIT license"])
        assert sym1 == sym1
        assert "MIT" == sym1.key
        assert ("MIT license",) == sym1.aliases

        sym2 = LicenseSymbol("mit", ["MIT license"])
        assert "mit" == sym2.key
        assert ("MIT license",) == sym2.aliases
        assert not sym2.is_exception
        assert sym1 != sym2
        assert sym1 is not sym2

        sym3 = LicenseSymbol("mit", ["MIT license"], is_exception=True)
        assert "mit" == sym3.key
        assert ("MIT license",) == sym3.aliases
        assert sym3.is_exception
        assert sym2 != sym3

        sym4 = LicenseSymbol("mit", ["MIT license"])
        assert "mit" == sym4.key
        assert ("MIT license",) == sym4.aliases
        # symbol equality is based ONLY on the key
        assert sym2 == sym4
        assert sym1 != sym4

        sym5 = LicenseWithExceptionSymbol(sym2, sym3)
        assert sym2 == sym5.license_symbol
        assert sym3 == sym5.exception_symbol

        sym6 = LicenseWithExceptionSymbol(sym4, sym3)
        # symbol euqality is based ONLY on the key
        assert sym5 == sym6

    def test_python_operators_simple(self):
        licensing = Licensing()

        sym1 = LicenseSymbol("MIT")
        sym2 = LicenseSymbol("BSD-2")

        assert sym1 & sym2 == licensing.AND(sym1, sym2)
        assert sym1 | sym2 == licensing.OR(sym1, sym2)

        sym3 = LicenseWithExceptionSymbol(
            LicenseSymbol("GPL-3.0-or-later"), LicenseSymbol("GCC-exception-3.1")
        )

        # Make sure LicenseWithExceptionSymbol operation work on left and right side
        assert sym3 & sym1 == licensing.AND(sym3, sym1)
        assert sym1 & sym3 == licensing.AND(sym1, sym3)
        assert sym3 | sym1 == licensing.OR(sym3, sym1)
        assert sym1 | sym3 == licensing.OR(sym3, sym1)

    def test_boolean_expression_operators(self):
        # Make sure LicenseWithExceptionSymbol boolean expression are set
        assert LicenseWithExceptionSymbol.Symbol is not None
        assert LicenseWithExceptionSymbol.TRUE is not None
        assert LicenseWithExceptionSymbol.FALSE is not None
        assert LicenseWithExceptionSymbol.AND is not None
        assert LicenseWithExceptionSymbol.OR is not None
        assert LicenseWithExceptionSymbol.NOT is not None

        # Make sure LicenseWithExceptionSymbol matches LicenseSymbol
        assert LicenseWithExceptionSymbol.Symbol == LicenseSymbol
        assert LicenseWithExceptionSymbol.TRUE == LicenseSymbol.TRUE
        assert LicenseWithExceptionSymbol.FALSE == LicenseSymbol.FALSE
        assert LicenseWithExceptionSymbol.AND == LicenseSymbol.AND
        assert LicenseWithExceptionSymbol.OR == LicenseSymbol.OR
        assert LicenseWithExceptionSymbol.NOT == LicenseSymbol.NOT


class LicensingTest(TestCase):
    def test_Licensing_create(self):
        Licensing()
        Licensing(None)
        Licensing(list())


class LicensingTokenizeWithoutSymbolsTest(TestCase):
    def test_tokenize_plain1(self):
        licensing = Licensing()
        expected = [
            (TOKEN_LPAR, "(", 1),
            (LicenseSymbol(key="mit"), "mit", 3),
            (TOKEN_RPAR, ")", 7),
            (TOKEN_AND, "and", 9),
            (LicenseSymbol(key="gpl"), "gpl", 13),
        ]
        assert list(licensing.tokenize(" ( mit ) and gpl")) == expected

    def test_tokenize_plain2(self):
        licensing = Licensing()
        expected = [
            (TOKEN_LPAR, "(", 0),
            (LicenseSymbol(key="mit"), "mit", 1),
            (TOKEN_AND, "and", 5),
            (LicenseSymbol(key="gpl"), "gpl", 9),
            (TOKEN_RPAR, ")", 12),
        ]
        assert list(licensing.tokenize("(mit and gpl)")) == expected

    def test_tokenize_plain3(self):
        licensing = Licensing()
        expected = [
            (LicenseSymbol(key="mit"), "mit", 0),
            (TOKEN_AND, "AND", 4),
            (LicenseSymbol(key="gpl"), "gpl", 8),
            (TOKEN_OR, "or", 12),
            (LicenseSymbol(key="gpl"), "gpl", 15),
        ]
        assert list(licensing.tokenize("mit AND gpl or gpl")) == expected

    def test_tokenize_plain4(self):
        licensing = Licensing()
        expected = [
            (TOKEN_LPAR, "(", 0),
            (TOKEN_LPAR, "(", 1),
            (LicenseSymbol(key="l-a+"), "l-a+", 2),
            (TOKEN_AND, "AND", 7),
            (LicenseSymbol(key="l-b"), "l-b", 11),
            (TOKEN_RPAR, ")", 14),
            (TOKEN_OR, "OR", 16),
            (TOKEN_LPAR, "(", 19),
            (LicenseSymbol(key="l-c+"), "l-c+", 20),
            (TOKEN_RPAR, ")", 24),
            (TOKEN_RPAR, ")", 25),
        ]
        assert list(licensing.tokenize("((l-a+ AND l-b) OR (l-c+))")) == expected

    def test_tokenize_plain5(self):
        licensing = Licensing()
        expected = [
            (TOKEN_LPAR, "(", 0),
            (TOKEN_LPAR, "(", 1),
            (LicenseSymbol(key="l-a+"), "l-a+", 2),
            (TOKEN_AND, "AND", 7),
            (LicenseSymbol(key="l-b"), "l-b", 11),
            (TOKEN_RPAR, ")", 14),
            (TOKEN_OR, "OR", 16),
            (TOKEN_LPAR, "(", 19),
            (LicenseSymbol(key="l-c+"), "l-c+", 20),
            (TOKEN_RPAR, ")", 24),
            (TOKEN_RPAR, ")", 25),
            (TOKEN_AND, "and", 27),
            (
                LicenseWithExceptionSymbol(
                    license_symbol=LicenseSymbol(key="gpl"),
                    exception_symbol=LicenseSymbol(key="classpath"),
                ),
                "gpl with classpath",
                31,
            ),
        ]
        tokens = licensing.tokenize("((l-a+ AND l-b) OR (l-c+)) and gpl with classpath")
        assert list(tokens) == expected


class LicensingTokenizeWithSymbolsTest(TestCase):
    def get_symbols_and_licensing(self):
        gpl_20 = LicenseSymbol("GPL-2.0", ["The GNU GPL 20"])
        gpl_20_plus = LicenseSymbol(
            "gpl-2.0+", ["The GNU GPL 20 or later", "GPL-2.0 or later", "GPL v2.0 or later"]
        )
        lgpl_21 = LicenseSymbol("LGPL-2.1", ["LGPL v2.1"])
        mit = LicenseSymbol("MIT", ["MIT license"])
        symbols = [gpl_20, gpl_20_plus, lgpl_21, mit]
        licensing = Licensing(symbols)
        return gpl_20, gpl_20_plus, lgpl_21, mit, licensing

    def test_tokenize_1_with_symbols(self):
        gpl_20, _gpl_20_plus, lgpl_21, mit, licensing = self.get_symbols_and_licensing()

        result = licensing.tokenize("The GNU GPL 20 or LGPL v2.1 AND MIT license ")
        #                                      111111111122222222223333333333444
        #                            0123456789012345678901234567890123456789012

        expected = [
            (gpl_20, "The GNU GPL 20", 0),
            (TOKEN_OR, "or", 15),
            (lgpl_21, "LGPL v2.1", 18),
            (TOKEN_AND, "AND", 28),
            (mit, "MIT license", 32),
        ]
        assert list(result) == expected

    def test_tokenize_1_no_symbols(self):
        licensing = Licensing()

        result = licensing.tokenize("The GNU GPL 20 or LGPL v2.1 AND MIT license")

        expected = [
            (LicenseSymbol("The GNU GPL 20"), "The GNU GPL 20", 0),
            (TOKEN_OR, "or", 15),
            (LicenseSymbol("LGPL v2.1"), "LGPL v2.1", 18),
            (TOKEN_AND, "AND", 28),
            (LicenseSymbol("MIT license"), "MIT license", 32),
        ]

        assert list(result) == expected

    def test_tokenize_with_trailing_unknown(self):
        gpl_20, _gpl_20_plus, lgpl_21, _mit, licensing = self.get_symbols_and_licensing()
        result = licensing.tokenize("The GNU GPL 20 or LGPL-2.1 and mit2")
        expected = [
            (gpl_20, "The GNU GPL 20", 0),
            (TOKEN_OR, "or", 15),
            (lgpl_21, "LGPL-2.1", 18),
            (TOKEN_AND, "and", 27),
            (LicenseSymbol(key="mit2"), "mit2", 31),
        ]
        assert list(result) == expected

    def test_tokenize_3(self):
        gpl_20, gpl_20_plus, lgpl_21, mit, licensing = self.get_symbols_and_licensing()

        result = licensing.tokenize(
            "The GNU GPL 20 or later or (LGPL-2.1 and mit) or The GNU GPL 20 or mit"
        )
        expected = [
            (gpl_20_plus, "The GNU GPL 20 or later", 0),
            (TOKEN_OR, "or", 24),
            (TOKEN_LPAR, "(", 27),
            (lgpl_21, "LGPL-2.1", 28),
            (TOKEN_AND, "and", 37),
            (mit, "mit", 41),
            (TOKEN_RPAR, ")", 44),
            (TOKEN_OR, "or", 46),
            (gpl_20, "The GNU GPL 20", 49),
            (2, "or", 64),
            (mit, "mit", 67),
        ]
        assert list(result) == expected

    def test_tokenize_unknown_as_trailing_single_attached_character(self):
        symbols = [LicenseSymbol("MIT", ["MIT license"])]
        l = Licensing(symbols)
        result = list(l.tokenize("mit2"))
        expected = [
            (LicenseSymbol("mit2"), "mit2", 0),
        ]
        assert result == expected

    def test_tokenize_with_unknown_symbol_containing_known_symbol_leading(self):
        l = Licensing(["gpl-2.0"])
        result = list(l.tokenize("gpl-2.0 AND gpl-2.0-plus", strict=False))
        result = [s for s, _, _ in result]
        expected = [
            LicenseSymbol(key="gpl-2.0"),
            TOKEN_AND,
            LicenseSymbol(key="gpl-2.0-plus"),
        ]
        assert result == expected

    def test_tokenize_with_unknown_symbol_containing_known_symbol_contained(self):
        l = Licensing(["gpl-2.0"])
        result = list(l.tokenize("gpl-2.0 WITH exception-gpl-2.0-plus", strict=False))
        result = [s for s, _, _ in result]
        expected = [
            LicenseWithExceptionSymbol(
                LicenseSymbol("gpl-2.0"), LicenseSymbol("exception-gpl-2.0-plus")
            )
        ]
        assert result == expected

    def test_tokenize_with_unknown_symbol_containing_known_symbol_trailing(self):
        l = Licensing(["gpl-2.0"])
        result = list(l.tokenize("gpl-2.0 AND exception-gpl-2.0", strict=False))
        result = [s for s, _, _ in result]
        expected = [LicenseSymbol("gpl-2.0"), TOKEN_AND, LicenseSymbol("exception-gpl-2.0")]
        assert result == expected


class LicensingParseTest(TestCase):
    def test_parse_does_not_raise_error_for_empty_expression(self):
        licensing = Licensing()
        assert None == licensing.parse("")

    def test_parse(self):
        expression = " ( (( gpl and bsd ) or lgpl)  and gpl-exception) "
        expected = "((gpl AND bsd) OR lgpl) AND gpl-exception"
        licensing = Licensing()
        self.assertEqual(expected, str(licensing.parse(expression)))

    def test_parse_raise_ParseError(self):
        expression = " ( (( gpl and bsd ) or lgpl)  and gpl-exception)) "
        licensing = Licensing()
        try:
            licensing.parse(expression)
            self.fail("ParseError should be raised")
        except ParseError as pe:
            expected = {
                "error_code": PARSE_UNBALANCED_CLOSING_PARENS,
                "position": 48,
                "token_string": ")",
                "token_type": TOKEN_RPAR,
            }
            assert _parse_error_as_dict(pe) == expected

    def test_parse_raise_ExpressionError_when_validating(self):
        expression = "gpl and bsd or lgpl with exception"
        licensing = Licensing()
        try:
            licensing.parse(expression, validate=True)
            self.fail("Exception not raised")
        except ExpressionError as ee:
            assert "Unknown license key(s): gpl, bsd, lgpl, exception" == str(ee)

    def test_parse_raise_ParseError_when_validating_strict(self):
        expression = "gpl and bsd or lgpl with exception"
        licensing = Licensing()
        try:
            licensing.parse(expression, validate=True, strict=True)
            self.fail("Exception not raised")
        except ParseError as pe:
            expected = {
                "error_code": PARSE_INVALID_SYMBOL_AS_EXCEPTION,
                "position": 25,
                "token_string": "exception",
                "token_type": TOKEN_SYMBOL,
            }
            assert _parse_error_as_dict(pe) == expected

    def test_parse_raise_ParseError_when_strict_no_validate(self):
        expression = "gpl and bsd or lgpl with exception"
        licensing = Licensing()
        try:
            licensing.parse(expression, validate=False, strict=True)
            self.fail("Exception not raised")
        except ParseError as pe:
            expected = {
                "error_code": PARSE_INVALID_SYMBOL_AS_EXCEPTION,
                "position": 25,
                "token_string": "exception",
                "token_type": TOKEN_SYMBOL,
            }
            assert _parse_error_as_dict(pe) == expected

    def test_parse_raise_ExpressionError_when_validating_strict_with_unknown(self):
        expression = "gpl and bsd or lgpl with exception"
        licensing = Licensing(symbols=[LicenseSymbol("exception", is_exception=True)])
        try:
            licensing.parse(expression, validate=True, strict=True)
        except ExpressionError as ee:
            assert "Unknown license key(s): gpl, bsd, lgpl" == str(ee)

    def test_parse_in_strict_mode_for_solo_symbol(self):
        expression = "lgpl"
        licensing = Licensing()
        licensing.parse(expression, strict=True)

    def test_parse_invalid_expression_raise_exception(self):
        licensing = Licensing()
        expr = "wrong"
        licensing.parse(expr)

    def test_parse_not_invalid_expression_rais_not_exception(self):
        licensing = Licensing()
        expr = "l-a AND none"
        licensing.parse(expr)

    def test_parse_invalid_expression_raise_exception3(self):
        licensing = Licensing()
        expr = "(l-a + AND l-b"
        try:
            licensing.parse(expr)
            self.fail("Exception not raised when validating '%s'" % expr)
        except ParseError:
            pass

    def test_parse_invalid_expression_raise_exception4(self):
        licensing = Licensing()
        expr = "(l-a + AND l-b))"
        try:
            licensing.parse(expr)
            self.fail("Exception not raised when validating '%s'" % expr)
        except ParseError:
            pass

    def test_parse_invalid_expression_raise_exception5(self):
        licensing = Licensing()
        expr = "l-a AND"
        try:
            licensing.parse(expr)
            self.fail("Exception not raised when validating '%s'" % expr)
        except ExpressionError as ee:
            assert "AND requires two or more licenses as in: MIT AND BSD" == str(ee)

    def test_parse_invalid_expression_raise_exception6(self):
        licensing = Licensing()
        expr = "OR l-a"
        try:
            licensing.parse(expr)
            self.fail("Exception not raised when validating '%s'" % expr)
            self.fail("Exception not raised")
        except ParseError as pe:
            expected = {
                "error_code": PARSE_INVALID_OPERATOR_SEQUENCE,
                "position": 0,
                "token_string": "OR",
                "token_type": TOKEN_OR,
            }
            assert _parse_error_as_dict(pe) == expected

    def test_parse_not_invalid_expression_raise_no_exception2(self):
        licensing = Licensing()
        expr = "+l-a"
        licensing.parse(expr)

    def test_parse_can_parse(self):
        licensing = Licensing()
        expr = " GPL-2.0 or LGPL2.1 and mit "
        parsed = licensing.parse(expr)
        gpl2 = LicenseSymbol("GPL-2.0")
        lgpl = LicenseSymbol("LGPL2.1")
        mit = LicenseSymbol("mit")
        expected = [gpl2, lgpl, mit]
        self.assertEqual(expected, licensing.license_symbols(parsed))
        self.assertEqual(expected, licensing.license_symbols(expr))
        self.assertEqual("GPL-2.0 OR (LGPL2.1 AND mit)", str(parsed))

        expected = licensing.OR(gpl2, licensing.AND(lgpl, mit))
        assert parsed == expected

    def test_parse_errors_catch_invalid_nesting(self):
        licensing = Licensing()
        try:
            licensing.parse("mit (and LGPL 2.1)")
            self.fail("Exception not raised")
        except ParseError as pe:
            expected = {
                "error_code": PARSE_INVALID_NESTING,
                "position": 4,
                "token_string": "(",
                "token_type": TOKEN_LPAR,
            }
            assert _parse_error_as_dict(pe) == expected

    def test_parse_errors_catch_invalid_expression_with_bare_and(self):
        licensing = Licensing()
        try:
            licensing.parse("and")
            self.fail("Exception not raised")
        except ParseError as pe:
            expected = {
                "error_code": PARSE_INVALID_OPERATOR_SEQUENCE,
                "position": 0,
                "token_string": "and",
                "token_type": TOKEN_AND,
            }
            assert _parse_error_as_dict(pe) == expected

    def test_parse_errors_catch_invalid_expression_with_or_and_no_other(self):
        licensing = Licensing()
        try:
            licensing.parse("or that")
            self.fail("Exception not raised")
        except ParseError as pe:
            expected = {
                "error_code": PARSE_INVALID_OPERATOR_SEQUENCE,
                "position": 0,
                "token_string": "or",
                "token_type": TOKEN_OR,
            }
            assert _parse_error_as_dict(pe) == expected

    def test_parse_errors_catch_invalid_expression_with_empty_parens(self):
        licensing = Licensing()
        try:
            licensing.parse("with ( )this")
            self.fail("Exception not raised")
        except ParseError as pe:
            expected = {
                "error_code": PARSE_INVALID_EXPRESSION,
                "position": 0,
                "token_string": "with",
                "token_type": TOKEN_WITH,
            }
            assert _parse_error_as_dict(pe) == expected

    def test_parse_errors_catch_invalid_non_unicode_byte_strings_on_python3(self):
        py2 = sys.version_info[0] == 2
        py3 = sys.version_info[0] == 3

        licensing = Licensing()

        if py2:
            extra_bytes = bytes(chr(0) + chr(12) + chr(255))
            try:
                licensing.parse("mit (and LGPL 2.1)".encode("utf-8") + extra_bytes)
                self.fail("Exception not raised")
            except ExpressionError as ee:
                assert str(ee).startswith("expression must be a string and")

        if py3:
            extra_bytes = bytes(chr(0) + chr(12) + chr(255), encoding="utf-8")
            try:
                licensing.parse("mit (and LGPL 2.1)".encode("utf-8") + extra_bytes)
                self.fail("Exception not raised")
            except ExpressionError as ee:
                assert str(ee).startswith("Invalid license key")

    def test_parse_errors_does_not_raise_error_on_plain_non_unicode_raw_string(self):
        # plain non-unicode string does not raise error
        licensing = Licensing()
        x = licensing.parse(r"mit and (LGPL-2.1)")
        self.assertTrue(isinstance(x, LicenseExpression))

    def test_parse_simplify_and_contain_and_equal(self):
        licensing = Licensing()

        expr = licensing.parse(" GPL-2.0 or LGPL2.1 and mit ")

        expr2 = licensing.parse(" (mit and LGPL2.1) or GPL-2.0 ")
        self.assertEqual(expr2.simplify(), expr.simplify())
        self.assertEqual(expr2, expr)

        expr3 = licensing.parse("mit and LGPL2.1")
        self.assertTrue(expr3 in expr2)

    def test_parse_simplify_no_sort(self):
        licensing = Licensing()
        expr = licensing.parse("gpl-2.0 OR apache-2.0")
        expr2 = licensing.parse("apache-2.0 OR gpl-2.0")

        self.assertEqual(expr, expr2)
        self.assertEqual(expr.simplify(), expr2.simplify())
        self.assertEqual(expr.simplify(sort=False), expr2.simplify())
        self.assertNotEqual(expr.simplify(sort=False).pretty(), expr2.pretty())

    def test_license_expression_is_equivalent(self):
        lic = Licensing()
        is_equiv = lic.is_equivalent

        self.assertTrue(is_equiv(lic.parse("mit AND gpl"), lic.parse("mit AND gpl")))
        self.assertTrue(is_equiv(lic.parse("mit AND gpl"), lic.parse("gpl AND mit")))
        self.assertTrue(
            is_equiv(lic.parse("mit AND gpl and apache"), lic.parse("apache and gpl AND mit"))
        )
        self.assertTrue(
            is_equiv(lic.parse("mit AND (gpl AND apache)"), lic.parse("(mit AND gpl) AND apache"))
        )

        # same but without parsing:
        self.assertTrue(is_equiv("mit AND gpl", "mit AND gpl"))
        self.assertTrue(is_equiv("mit AND gpl", "gpl AND mit"))
        self.assertTrue(is_equiv("mit AND gpl and apache", "apache and gpl AND mit"))
        self.assertTrue(is_equiv("mit AND (gpl AND apache)", "(mit AND gpl) AND apache"))

        # Real-case example of generated expression vs. stored expression:
        ex1 = """Commercial
            AND apache-1.1 AND apache-2.0 AND aslr AND bsd-new
            AND cpl-1.0 AND epl-1.0
            AND ibm-icu AND ijg AND jdom AND lgpl-2.1
            AND mit-open-group AND mpl-1.1 AND sax-pd AND unicode AND w3c AND
            w3c-documentation"""

        ex2 = """
            apache-1.1 AND apache-2.0 AND aslr AND bsd-new
            AND cpl-1.0 AND epl-1.0
            AND lgpl-2.1 AND ibm-icu AND ijg
            AND jdom AND mit-open-group
            AND mpl-1.1 AND Commercial AND sax-pd AND unicode
            AND w3c-documentation AND w3c"""

        self.assertTrue(is_equiv(lic.parse(ex1), lic.parse(ex2)))
        self.assertFalse(is_equiv(lic.parse("mit AND gpl"), lic.parse("mit OR gpl")))
        self.assertFalse(is_equiv(lic.parse("mit AND gpl"), lic.parse("gpl OR mit")))

    def test_license_expression_license_keys(self):
        licensing = Licensing()
        assert ["mit", "gpl"] == licensing.license_keys(licensing.parse(" ( mit ) and gpl"))
        assert ["mit", "gpl"] == licensing.license_keys(licensing.parse("(mit and gpl)"))
        # these two are surprising for now: this is because the expression is a
        # logical expression so the order may be different on more complex expressions
        assert ["mit", "gpl"] == licensing.license_keys(licensing.parse("mit AND gpl or gpl"))
        assert ["l-a+", "l-b", "+l-c"] == licensing.license_keys(
            licensing.parse("((l-a+ AND l-b) OR (+l-c))")
        )
        # same without parsing
        assert ["mit", "gpl"] == licensing.license_keys("mit AND gpl or gpl")
        assert ["l-a+", "l-b", "l-c+"] == licensing.license_keys("((l-a+ AND l-b) OR (l-c+))")

    def test_end_to_end(self):
        # these were formerly doctest ported to actual real code tests here
        l = Licensing()
        expr = l.parse(" GPL-2.0 or LGPL-2.1 and mit ")
        expected = "GPL-2.0 OR (LGPL-2.1 AND mit)"
        assert str(expr) == expected

        expected = [
            LicenseSymbol("GPL-2.0"),
            LicenseSymbol("LGPL-2.1"),
            LicenseSymbol("mit"),
        ]
        assert l.license_symbols(expr) == expected

    def test_pretty(self):
        l = Licensing()
        expr = l.parse(" GPL-2.0 or LGPL2.1 and mit ")

        expected = """OR(
  LicenseSymbol('GPL-2.0'),
  AND(
    LicenseSymbol('LGPL2.1'),
    LicenseSymbol('mit')
  )
)"""
        assert expr.pretty() == expected

    def test_simplify_and_contains(self):
        l = Licensing()

        expr = l.parse(" GPL-2.0 or LGPL2.1 and mit ")
        expr2 = l.parse(" GPL-2.0 or (mit and LGPL2.1) ")
        assert expr2.simplify() == expr.simplify()
        expr3 = l.parse("mit and LGPL2.1")
        assert expr3 in expr2

    def test_dedup_expressions_can_be_simplified_1(self):
        l = Licensing()
        exp = "mit OR mit AND apache-2.0 AND bsd-new OR mit"
        result = l.dedup(exp)
        expected = l.parse("mit OR (mit AND apache-2.0 AND bsd-new)")
        assert result == expected

    def test_dedup_expressions_can_be_simplified_2(self):
        l = Licensing()
        exp = "mit AND (mit OR bsd-new) AND mit OR mit"
        result = l.dedup(exp)
        expected = l.parse("(mit AND (mit OR bsd-new)) OR mit")
        assert result == expected

    def test_dedup_expressions_multiple_occurrences(self):
        l = Licensing()
        exp = " GPL-2.0 or (mit and LGPL-2.1) or bsd Or GPL-2.0  or (mit and LGPL-2.1)"
        result = l.dedup(exp)
        expected = l.parse("GPL-2.0 OR (mit AND LGPL-2.1) OR bsd")
        assert result == expected

    def test_dedup_expressions_cannot_be_simplified(self):
        l = Licensing()
        exp = l.parse("mit AND (mit OR bsd-new)")
        result = l.dedup(exp)
        expected = l.parse("mit AND (mit OR bsd-new)")
        assert result == expected

    def test_dedup_expressions_single_license(self):
        l = Licensing()
        exp = l.parse("mit")
        result = l.dedup(exp)
        expected = l.parse("mit")
        assert result == expected

    def test_dedup_expressions_WITH(self):
        l = Licensing()
        exp = l.parse("gpl-2.0 with autoconf-exception-2.0")
        result = l.dedup(exp)
        expected = l.parse("gpl-2.0 with autoconf-exception-2.0")
        assert result == expected

    def test_dedup_expressions_WITH_OR(self):
        l = Licensing()
        exp = l.parse("gpl-2.0 with autoconf-exception-2.0 OR gpl-2.0")
        result = l.dedup(exp)
        expected = l.parse("gpl-2.0 with autoconf-exception-2.0 OR gpl-2.0")
        assert result == expected

    def test_dedup_expressions_WITH_AND(self):
        l = Licensing()
        exp = l.parse("gpl-2.0 AND gpl-2.0 with autoconf-exception-2.0 AND gpl-2.0")
        result = l.dedup(exp)
        expected = l.parse("gpl-2.0 AND gpl-2.0 with autoconf-exception-2.0")
        assert result == expected

    def test_dedup_licensexpressions_can_be_simplified_3(self):
        l = Licensing()
        exp = l.parse("mit AND mit")
        result = l.dedup(exp)
        expected = l.parse("mit")
        assert result == expected

    def test_dedup_licensexpressions_works_with_subexpressions(self):
        l = Licensing()
        exp = l.parse("(mit OR gpl-2.0) AND mit AND bsd-new AND (mit OR gpl-2.0)")
        result = l.dedup(exp)
        expected = l.parse("(mit OR gpl-2.0) AND mit AND bsd-new")
        assert result == expected

    def test_simplify_and_equivalent_and_contains(self):
        l = Licensing()
        expr2 = l.parse(" GPL-2.0 or (mit and LGPL-2.1) or bsd Or GPL-2.0  or (mit and LGPL-2.1)")
        # note thats simplification does SORT the symbols such that they can
        # eventually be compared sequence-wise. This sorting is based on license key
        expected = "GPL-2.0 OR bsd OR (LGPL-2.1 AND mit)"
        assert str(expr2.simplify()) == expected

        # Two expressions can be compared for equivalence:
        expr1 = l.parse(" GPL-2.0 or (LGPL-2.1 and mit) ")
        assert "GPL-2.0 OR (LGPL-2.1 AND mit)" == str(expr1)
        expr2 = l.parse(" (mit and LGPL-2.1)  or GPL-2.0 ")
        assert "(mit AND LGPL-2.1) OR GPL-2.0" == str(expr2)
        assert l.is_equivalent(expr1, expr2)

        assert "GPL-2.0 OR (LGPL-2.1 AND mit)" == str(expr1.simplify())
        assert "GPL-2.0 OR (LGPL-2.1 AND mit)" == str(expr2.simplify())
        assert expr1.simplify() == expr2.simplify()

        expr3 = l.parse(" GPL-2.0 or mit or LGPL-2.1")
        assert not l.is_equivalent(expr2, expr3)
        expr4 = l.parse("mit and LGPL-2.1")
        assert expr4.simplify() in expr2.simplify()

        assert l.contains(expr2, expr4)

    def test_contains_works_with_plain_symbol(self):
        l = Licensing()
        assert not l.contains("mit", "mit and LGPL-2.1")
        assert l.contains("mit and LGPL-2.1", "mit")
        assert l.contains("mit", "mit")
        assert not l.contains(l.parse("mit"), l.parse("mit and LGPL-2.1"))
        assert l.contains(l.parse("mit and LGPL-2.1"), l.parse("mit"))

        assert l.contains("mit with GPL", "GPL")
        assert l.contains("mit with GPL", "mit")
        assert l.contains("mit with GPL", "mit with GPL")
        assert not l.contains("mit with GPL", "GPL with mit")
        assert not l.contains("mit with GPL", "GPL and mit")
        assert not l.contains("GPL", "mit with GPL")
        assert l.contains("mit with GPL and GPL and BSD", "GPL and BSD")

    def test_create_from_python(self):
        # Expressions can be built from Python expressions, using bitwise operators
        # between Licensing objects, but use with caution. The behavior is not as
        # well specified that using text expression and parse

        licensing = Licensing()
        expr1 = licensing.LicenseSymbol("GPL-2.0") | (
            licensing.LicenseSymbol("mit") & licensing.LicenseSymbol("LGPL-2.1")
        )
        expr2 = licensing.parse(" GPL-2.0 or (mit and LGPL-2.1) ")

        assert "GPL-2.0 OR (LGPL-2.1 AND mit)" == str(expr1.simplify())
        assert "GPL-2.0 OR (LGPL-2.1 AND mit)" == str(expr2.simplify())

        assert licensing.is_equivalent(expr1, expr2)

        a = licensing.OR(
            LicenseSymbol(key="gpl-2.0"),
            licensing.AND(LicenseSymbol(key="mit"), LicenseSymbol(key="lgpl-2.1")),
        )
        b = licensing.OR(
            LicenseSymbol(key="gpl-2.0"),
            licensing.AND(LicenseSymbol(key="mit"), LicenseSymbol(key="lgpl-2.1")),
        )
        assert a == b

    def test_parse_with_repeated_or_later_does_not_raise_parse_error(self):
        l = Licensing()
        expr = "LGPL2.1+ + and mit"
        parsed = l.parse(expr)
        assert "LGPL2.1+ + AND mit" == str(parsed)

    def test_render_complex(self):
        licensing = Licensing()
        expression = """
        EPL-1.0 AND Apache-1.1 AND Apache-2.0 AND BSD-Modified AND CPL-1.0 AND
        ICU-Composite-License AND JPEG-License AND JDOM-License AND LGPL-2.0 AND
        MIT-Open-Group AND MPL-1.1 AND SAX-PD AND Unicode-Inc-License-Agreement
        AND W3C-Software-Notice and License AND W3C-Documentation-License"""

        result = licensing.parse(expression)
        expected = (
            "EPL-1.0 AND Apache-1.1 AND Apache-2.0 AND BSD-Modified "
            "AND CPL-1.0 AND ICU-Composite-License AND JPEG-License "
            "AND JDOM-License AND LGPL-2.0 AND MIT-Open-Group AND MPL-1.1 "
            "AND SAX-PD AND Unicode-Inc-License-Agreement "
            "AND W3C-Software-Notice AND License AND W3C-Documentation-License"
        )

        assert result.render("{symbol.key}") == expected
        expectedkey = (
            "EPL-1.0 AND Apache-1.1 AND Apache-2.0 AND BSD-Modified AND "
            "CPL-1.0 AND ICU-Composite-License AND JPEG-License AND JDOM-License AND "
            "LGPL-2.0 AND MIT-Open-Group AND MPL-1.1 AND SAX-PD AND "
            "Unicode-Inc-License-Agreement AND W3C-Software-Notice AND License AND"
            " W3C-Documentation-License"
        )
        assert expectedkey == result.render("{symbol.key}")

    def test_render_with(self):
        licensing = Licensing()
        expression = "GPL-2.0 with Classpath-2.0 OR BSD-new"
        result = licensing.parse(expression)

        expected = "GPL-2.0 WITH Classpath-2.0 OR BSD-new"
        assert result.render("{symbol.key}") == expected

        expected_html = (
            '<a href="path/GPL-2.0">GPL-2.0</a> WITH '
            '<a href="path/Classpath-2.0">Classpath-2.0</a> '
            'OR <a href="path/BSD-new">BSD-new</a>'
        )
        assert expected_html == result.render('<a href="path/{symbol.key}">{symbol.key}</a>')

        expected = "GPL-2.0 WITH Classpath-2.0 OR BSD-new"
        assert result.render("{symbol.key}") == expected

    def test_parse_complex(self):
        licensing = Licensing()
        expression = (
            " GPL-2.0 or later with classpath-Exception and mit or  LPL-2.1 and mit or later "
        )
        result = licensing.parse(expression)
        # this may look weird, but we did not provide symbols hence in "or later",
        # "later" is treated as if it were a license
        expected = (
            "GPL-2.0 OR (later WITH classpath-Exception AND mit) OR (LPL-2.1 AND mit) OR later"
        )
        assert result.render("{symbol.key}") == expected

    def test_parse_complex2(self):
        licensing = Licensing()
        expr = licensing.parse(" GPL-2.0 or LGPL-2.1 and mit ")
        expected = [LicenseSymbol("GPL-2.0"), LicenseSymbol("LGPL-2.1"), LicenseSymbol("mit")]
        assert sorted(licensing.license_symbols(expr)) == expected
        expected = "GPL-2.0 OR (LGPL-2.1 AND mit)"
        assert expr.render("{symbol.key}") == expected

    def test_Licensing_can_tokenize_valid_expressions_with_symbols_that_contain_and_with_or(self):
        licensing = Licensing()
        expression = "orgpl or withbsd with orclasspath and andmit or anlgpl and ormit or withme"

        result = list(licensing.tokenize(expression))
        expected = [
            (LicenseSymbol(key="orgpl"), "orgpl", 0),
            (2, "or", 6),
            (
                LicenseWithExceptionSymbol(
                    license_symbol=LicenseSymbol(key="withbsd"),
                    exception_symbol=LicenseSymbol(key="orclasspath"),
                ),
                "withbsd with orclasspath",
                9,
            ),
            (1, "and", 34),
            (LicenseSymbol(key="andmit"), "andmit", 38),
            (2, "or", 45),
            (LicenseSymbol(key="anlgpl"), "anlgpl", 48),
            (1, "and", 55),
            (LicenseSymbol(key="ormit"), "ormit", 59),
            (2, "or", 65),
            (LicenseSymbol(key="withme"), "withme", 68),
        ]

        assert result == expected

    def test_Licensing_can_simple_tokenize_valid_expressions_with_symbols_that_contain_and_with_or(
        self,
    ):
        licensing = Licensing()
        expression = "orgpl or withbsd with orclasspath and andmit or andlgpl and ormit or withme"

        result = [r.string for r in licensing.simple_tokenizer(expression)]
        expected = [
            "orgpl",
            " ",
            "or",
            " ",
            "withbsd",
            " ",
            "with",
            " ",
            "orclasspath",
            " ",
            "and",
            " ",
            "andmit",
            " ",
            "or",
            " ",
            "andlgpl",
            " ",
            "and",
            " ",
            "ormit",
            " ",
            "or",
            " ",
            "withme",
        ]
        assert result == expected

    def test_Licensing_can_parse_valid_expressions_with_symbols_that_contain_and_with_or(self):
        licensing = Licensing()
        expression = "orgpl or withbsd with orclasspath and andmit or anlgpl and ormit or withme"

        result = licensing.parse(expression)
        expected = "orgpl OR (withbsd WITH orclasspath AND andmit) OR (anlgpl AND ormit) OR withme"
        assert result.render("{symbol.key}") == expected

    def test_Licensing_can_parse_valid_expressions_with_symbols_that_contain_spaces(self):
        licensing = Licensing()
        expression = " GPL-2.0 or (mit and LGPL 2.1) or bsd Or GPL-2.0  or (mit and LGPL 2.1)"
        parsed = licensing.parse(expression)
        expected = "GPL-2.0 OR (mit AND LGPL 2.1) OR bsd OR GPL-2.0 OR (mit AND LGPL 2.1)"
        assert str(parsed) == expected

    def test_parse_invalid_expression_with_trailing_or(self):
        licensing = Licensing()
        expr = "mit or"
        try:
            licensing.parse(expr)
            self.fail("Exception not raised when validating '%s'" % expr)
        except ExpressionError as ee:
            assert "OR requires two or more licenses as in: MIT OR BSD" == str(ee)

    def test_parse_invalid_expression_with_trailing_or_and_valid_start_does_not_raise_exception(
        self,
    ):
        licensing = Licensing()
        expression = " mit or mit or "
        parsed = licensing.parse(expression)
        # ExpressionError: OR requires two or more licenses as in: MIT OR BSD
        expected = "mit OR mit"
        assert str(parsed) == expected

    def test_parse_invalid_expression_with_repeated_trailing_or_raise_exception(self):
        licensing = Licensing()
        expression = "mit or mit or or"
        try:
            licensing.parse(expression, simple=False)
            self.fail("Exception not raised")
        except ParseError as pe:
            expected = {
                "error_code": PARSE_INVALID_OPERATOR_SEQUENCE,
                "position": 14,
                "token_string": "or",
                "token_type": TOKEN_OR,
            }
            assert _parse_error_as_dict(pe) == expected

    def test_parse_invalid_expression_drops_single_trailing_or(self):
        licensing = Licensing()
        expression = "mit or mit or"
        e = licensing.parse(expression, simple=False)
        assert str(e) == "mit OR mit"

    def test_parse_invalid_expression_drops_single_trailing_or2(self):
        licensing = Licensing()
        expression = "mit or mit or"
        e = licensing.parse(expression, simple=True)
        assert str(e) == "mit OR mit"

    def test_parse_invalid_expression_with_single_trailing_and_raise_exception(self):
        licensing = Licensing()
        expression = "mit or mit and"
        try:
            licensing.parse(expression, simple=False)
            self.fail("Exception not raised")
        except ExpressionError as ee:
            assert "AND requires two or more licenses as in: MIT AND BSD" == str(ee)

    def test_parse_invalid_expression_with_single_leading_or_raise_exception(self):
        licensing = Licensing()
        expression = "or mit or mit"
        try:
            licensing.parse(expression, simple=False)
            self.fail("Exception not raised")
        except ParseError as pe:
            expected = {
                "error_code": PARSE_INVALID_OPERATOR_SEQUENCE,
                "position": 0,
                "token_string": "or",
                "token_type": TOKEN_OR,
            }
            assert _parse_error_as_dict(pe) == expected

    def test_Licensing_can_parse_expressions_with_symbols_that_contain_a_colon(self):
        licensing = Licensing()
        expression = "DocumentRef-James-1.0:LicenseRef-Eric-2.0"

        result = licensing.parse(expression)
        expected = "DocumentRef-James-1.0:LicenseRef-Eric-2.0"
        assert result.render("{symbol.key}") == expected


class LicensingParseWithSymbolsSimpleTest(TestCase):
    def test_Licensing_with_overlapping_symbols_with_keywords_does_not_raise_Exception(self):
        Licensing(
            [
                "GPL-2.0 or LATER",
                "classpath Exception",
                "something with else+",
                "mit",
                "LGPL 2.1",
                "mit or later",
            ]
        )

    def get_syms_and_licensing(self):
        a = LicenseSymbol("l-a")
        ap = LicenseSymbol("L-a+", ["l-a +"])
        b = LicenseSymbol("l-b")
        c = LicenseSymbol("l-c")
        symbols = [a, ap, b, c]
        return a, ap, b, c, Licensing(symbols)

    def test_parse_license_expression1(self):
        a, _ap, _b, _c, licensing = self.get_syms_and_licensing()
        express_string = "l-a"
        result = licensing.parse(express_string)
        assert express_string == str(result)
        expected = a
        assert result == expected
        assert [] == licensing.unknown_license_keys(result)

    def test_parse_license_expression_with_alias(self):
        _a, ap, _b, _c, licensing = self.get_syms_and_licensing()
        express_string = "l-a +"
        result = licensing.parse(express_string)
        assert "L-a+" == str(result)
        expected = ap
        assert result == expected
        assert [] == licensing.unknown_license_keys(result)

    def test_parse_license_expression3(self):
        _a, ap, _b, _c, licensing = self.get_syms_and_licensing()
        express_string = "l-a+"
        result = licensing.parse(express_string)
        assert "L-a+" == str(result)
        expected = ap
        assert result == expected
        assert [] == licensing.unknown_license_keys(result)

    def test_parse_license_expression4(self):
        _a, _ap, _b, _c, licensing = self.get_syms_and_licensing()
        express_string = "(l-a)"
        result = licensing.parse(express_string)
        assert "l-a" == str(result)
        expected = LicenseSymbol(key="l-a", aliases=())
        assert result == expected
        assert [] == licensing.unknown_license_keys(result)

    def test_parse_license_expression5(self):
        _a, ap, b, c, licensing = self.get_syms_and_licensing()
        express_string = "((l-a+ AND l-b) OR (l-c))"
        result = licensing.parse(express_string)
        assert "(L-a+ AND l-b) OR l-c" == str(result)
        expected = licensing.OR(licensing.AND(ap, b), c)
        assert result == expected
        assert [] == licensing.unknown_license_keys(result)

    def test_parse_license_expression6(self):
        a, _ap, b, _c, licensing = self.get_syms_and_licensing()
        express_string = "l-a and l-b"
        result = licensing.parse(express_string)
        assert "l-a AND l-b" == str(result)
        expected = licensing.AND(a, b)
        assert result == expected
        assert [] == licensing.unknown_license_keys(result)

    def test_parse_license_expression7(self):
        a, _ap, b, _c, licensing = self.get_syms_and_licensing()
        express_string = "l-a or l-b"
        result = licensing.parse(express_string)
        assert "l-a OR l-b" == str(result)
        expected = licensing.OR(a, b)
        assert result == expected
        assert [] == licensing.unknown_license_keys(result)

    def test_parse_license_expression8(self):
        a, _ap, b, c, licensing = self.get_syms_and_licensing()
        express_string = "l-a and l-b OR l-c"
        result = licensing.parse(express_string)
        assert "(l-a AND l-b) OR l-c" == str(result)
        expected = licensing.OR(licensing.AND(a, b), c)
        assert result == expected
        assert [] == licensing.unknown_license_keys(result)

    def test_parse_license_expression8_twice(self):
        _a, _ap, _b, _c, licensing = self.get_syms_and_licensing()
        express_string = "l-a and l-b OR l-c"
        result = licensing.parse(express_string)
        assert "(l-a AND l-b) OR l-c" == str(result)
        # there was some issues with reusing a Licensing
        result = licensing.parse(express_string)
        assert "(l-a AND l-b) OR l-c" == str(result)

    def test_parse_license_expression_with_trailing_space_plus(self):
        symbols = [
            LicenseSymbol("l-a"),
            LicenseSymbol("L-a+", ["l-a +"]),
            LicenseSymbol("l-b"),
            LicenseSymbol("l-c"),
        ]
        licensing = Licensing(symbols)

        expresssion_str = "l-a"
        result = licensing.parse(expresssion_str)
        assert str(result) == expresssion_str
        assert licensing.unknown_license_keys(result) == []

        # plus sign is not attached to the symbol, but an alias
        expresssion_str = "l-a +"
        result = licensing.parse(expresssion_str)
        assert str(result).lower() == "l-a+"
        assert licensing.unknown_license_keys(result) == []

        expresssion_str = "(l-a)"
        result = licensing.parse(expresssion_str)
        assert str(result).lower() == "l-a"
        assert licensing.unknown_license_keys(result) == []

        expresssion_str = "((l-a+ AND l-b) OR (l-c))"
        result = licensing.parse(expresssion_str)
        assert str(result) == "(L-a+ AND l-b) OR l-c"
        assert licensing.unknown_license_keys(result) == []

        expresssion_str = "l-a and l-b"
        result = licensing.parse(expresssion_str)
        assert str(result) == "l-a AND l-b"
        assert licensing.unknown_license_keys(result) == []

        expresssion_str = "l-a or l-b"
        result = licensing.parse(expresssion_str)
        assert str(result) == "l-a OR l-b"
        assert licensing.unknown_license_keys(result) == []

        expresssion_str = "l-a and l-b OR l-c"
        result = licensing.parse(expresssion_str)
        assert str(result) == "(l-a AND l-b) OR l-c"
        assert licensing.unknown_license_keys(result) == []

    def test_parse_of_side_by_side_symbols_raise_exception(self):
        gpl2 = LicenseSymbol("gpl")
        l = Licensing([gpl2])
        try:
            l.parse("gpl mit")
            self.fail("ParseError not raised")
        except ParseError:
            pass

    def test_validate_symbols(self):
        symbols = [
            LicenseSymbol("l-a", is_exception=True),
            LicenseSymbol("l-a"),
            LicenseSymbol("l-b"),
            LicenseSymbol("l-c"),
        ]
        warnings, errors = validate_symbols(symbols)

        expectedw = []
        assert warnings == expectedw

        expectede = [
            "Invalid duplicated license key: 'l-a'.",
        ]
        assert errors == expectede


class LicensingParseWithSymbolsTest(TestCase):
    def test_parse_raise_ParseError_when_validating_strict_with_non_exception_symbols(self):
        licensing = Licensing(["gpl", "bsd", "lgpl", "exception"])

        expression = "gpl and bsd or lgpl with exception"
        try:
            licensing.parse(expression, validate=True, strict=True)
            self.fail("Exception not raised")
        except ParseError as pe:
            expected = {
                "error_code": PARSE_INVALID_SYMBOL_AS_EXCEPTION,
                "position": 25,
                "token_string": "exception",
                "token_type": TOKEN_SYMBOL,
            }
            assert _parse_error_as_dict(pe) == expected

    def test_parse_raise_ParseError_when_validating_strict_with_exception_symbols_in_incorrect_spot(
        self,
    ):
        licensing = Licensing(
            [
                LicenseSymbol("gpl", is_exception=False),
                LicenseSymbol("exception", is_exception=True),
            ]
        )
        licensing.parse("gpl with exception", validate=True, strict=True)
        try:
            licensing.parse("exception with gpl", validate=True, strict=True)
            self.fail("Exception not raised")
        except ParseError as pe:
            expected = {
                "error_code": PARSE_INVALID_EXCEPTION,
                "position": 0,
                "token_string": "exception",
                "token_type": TOKEN_SYMBOL,
            }
            assert _parse_error_as_dict(pe) == expected

        try:
            licensing.parse("gpl with gpl", validate=True, strict=True)
            self.fail("Exception not raised")
        except ParseError as pe:
            expected = {
                "error_code": PARSE_INVALID_SYMBOL_AS_EXCEPTION,
                "position": 9,
                "token_string": "gpl",
                "token_type": TOKEN_SYMBOL,
            }
            assert _parse_error_as_dict(pe) == expected

    def test_with_unknown_symbol_string_contained_in_known_symbol_does_not_crash_with(self):
        l = Licensing(["lgpl-3.0-plus"])
        license_expression = "lgpl-3.0-plus WITH openssl-exception-lgpl-3.0-plus"
        l.parse(license_expression)

    def test_with_unknown_symbol_string_contained_in_known_symbol_does_not_crash_and(self):
        l = Licensing(["lgpl-3.0-plus"])
        license_expression = "lgpl-3.0-plus AND openssl-exception-lgpl-3.0-plus"
        l.parse(license_expression)

    def test_with_unknown_symbol_string_contained_in_known_symbol_does_not_crash_or(self):
        l = Licensing(["lgpl-3.0-plus"])
        license_expression = "lgpl-3.0-plus OR openssl-exception-lgpl-3.0-plus"
        l.parse(license_expression)

    def test_with_known_symbol_string_contained_in_known_symbol_does_not_crash_or(self):
        l = Licensing(["lgpl-3.0-plus", "openssl-exception-lgpl-3.0-plus"])
        license_expression = "lgpl-3.0-plus OR openssl-exception-lgpl-3.0-plus"
        l.parse(license_expression)

    def test_with_known_symbol_string_contained_in_known_symbol_does_not_crash_with(self):
        l = Licensing(["lgpl-3.0-plus", "openssl-exception-lgpl-3.0-plus"])
        license_expression = "lgpl-3.0-plus WITH openssl-exception-lgpl-3.0-plus"
        l.parse(license_expression)


class LicensingSymbolsReplacement(TestCase):
    def get_symbols_and_licensing(self):
        gpl2 = LicenseSymbol("gpl-2.0", ["The GNU GPL 20", "GPL-2.0", "GPL v2.0"])
        gpl2plus = LicenseSymbol(
            "gpl-2.0+", ["The GNU GPL 20 or later", "GPL-2.0 or later", "GPL v2.0 or later"]
        )
        lgpl = LicenseSymbol("LGPL-2.1", ["LGPL v2.1"])
        mit = LicenseSymbol("MIT", ["MIT license"])
        mitand2 = LicenseSymbol("mitand2", ["mitand2", "mitand2 license"])
        symbols = [gpl2, gpl2plus, lgpl, mit, mitand2]
        licensing = Licensing(symbols)
        return gpl2, gpl2plus, lgpl, mit, mitand2, licensing

    def test_simple_substitution(self):
        gpl2, gpl2plus, _lgpl, _mit, _mitand2, licensing = self.get_symbols_and_licensing()
        subs = {gpl2plus: gpl2}

        expr = licensing.parse("gpl-2.0 or gpl-2.0+")
        result = expr.subs(subs)
        assert "gpl-2.0 OR gpl-2.0" == result.render()

    def test_advanced_substitution(self):
        _gpl2, _gpl2plus, lgpl, _mit, _mitand2, licensing = self.get_symbols_and_licensing()
        source = licensing.parse("gpl-2.0+ and mit")
        target = lgpl
        subs = {source: target}

        expr = licensing.parse("gpl-2.0 or gpl-2.0+ and mit")
        result = expr.subs(subs)
        assert "gpl-2.0 OR LGPL-2.1" == result.render()

    def test_multiple_substitutions(self):
        gpl2, gpl2plus, lgpl, mit, _mitand2, licensing = self.get_symbols_and_licensing()

        source1 = licensing.parse("gpl-2.0+ and mit")
        target1 = lgpl

        source2 = licensing.parse("mitand2")
        target2 = mit

        source3 = gpl2
        target3 = gpl2plus

        subs = dict(
            [
                (source1, target1),
                (source2, target2),
                (source3, target3),
            ]
        )

        expr = licensing.parse("gpl-2.0 or gpl-2.0+ and mit")
        # step 1: yields 'gpl-2.0 or lgpl'
        # step 2: yields 'gpl-2.0+ or LGPL-2.1'
        result = expr.subs(subs)
        assert "gpl-2.0+ OR LGPL-2.1" == result.render()

    def test_multiple_substitutions_complex(self):
        gpl2, gpl2plus, lgpl, mit, _mitand2, licensing = self.get_symbols_and_licensing()

        source1 = licensing.parse("gpl-2.0+ and mit")
        target1 = lgpl

        source2 = licensing.parse("mitand2")
        target2 = mit

        source3 = gpl2
        target3 = gpl2plus

        subs = dict(
            [
                (source1, target1),
                (source2, target2),
                (source3, target3),
            ]
        )

        expr = licensing.parse("(gpl-2.0 or gpl-2.0+ and mit) and (gpl-2.0 or gpl-2.0+ and mit)")
        # step 1: yields 'gpl-2.0 or lgpl'
        # step 2: yields 'gpl-2.0+ or LGPL-2.1'
        result = expr.subs(subs)
        assert "(gpl-2.0+ OR LGPL-2.1) AND (gpl-2.0+ OR LGPL-2.1)" == result.render()

        expr = licensing.parse("(gpl-2.0 or mit and gpl-2.0+) and (gpl-2.0 or gpl-2.0+ and mit)")
        # step 1: yields 'gpl-2.0 or lgpl'
        # step 2: yields 'gpl-2.0+ or LGPL-2.1'
        result = expr.subs(subs)
        assert "(gpl-2.0+ OR LGPL-2.1) AND (gpl-2.0+ OR LGPL-2.1)" == result.render()


class LicensingParseWithSymbolsAdvancedTest(TestCase):
    def get_symbols_and_licensing(self):
        gpl2 = LicenseSymbol("gpl-2.0", ["The GNU GPL 20", "GPL-2.0", "GPL v2.0"])
        gpl2plus = LicenseSymbol(
            "gpl-2.0+", ["The GNU GPL 20 or later", "GPL-2.0 or later", "GPL v2.0 or later"]
        )
        lgpl = LicenseSymbol("LGPL-2.1", ["LGPL v2.1"])
        mit = LicenseSymbol("MIT", ["MIT license"])
        mitand2 = LicenseSymbol("mitand2", ["mitand2", "mitand2 license"])
        symbols = [gpl2, gpl2plus, lgpl, mit, mitand2]
        licensing = Licensing(symbols)
        return gpl2, gpl2plus, lgpl, mit, mitand2, licensing

    def test_parse_trailing_char_does_not_raise_exception_without_validate(self):
        _gpl2, _gpl2plus, _lgpl, _mit, _mitand2, licensing = self.get_symbols_and_licensing()
        e = licensing.parse("The GNU GPL 20 or LGPL-2.1 and mit2", validate=False)
        assert "gpl-2.0 OR (LGPL-2.1 AND mit2)" == str(e)

    def test_parse_trailing_char_raise_exception_with_validate(self):
        _gpl2, _gpl2plus, _lgpl, _mit, _mitand2, licensing = self.get_symbols_and_licensing()
        try:
            licensing.parse("The GNU GPL 20 or LGPL-2.1 and mit2", validate=True)
            self.fail("Exception not raised")
        except ExpressionError as ee:
            assert "Unknown license key(s): mit2" == str(ee)

    def test_parse_expression_with_trailing_unknown_should_raise_exception(self):
        gpl2, gpl2plus, lgpl, mit, _mitand2, licensing = self.get_symbols_and_licensing()
        unknown = LicenseSymbol(key="123")

        tokens = list(
            licensing.tokenize(
                "The GNU GPL 20 or later or (LGPL-2.1 and mit) or The GNU GPL 20 or mit 123"
            )
        )
        expected = [
            (gpl2plus, "The GNU GPL 20 or later", 0),
            (TOKEN_OR, "or", 24),
            (TOKEN_LPAR, "(", 27),
            (lgpl, "LGPL-2.1", 28),
            (TOKEN_AND, "and", 37),
            (mit, "mit", 41),
            (TOKEN_RPAR, ")", 44),
            (TOKEN_OR, "or", 46),
            (gpl2, "The GNU GPL 20", 49),
            (TOKEN_OR, "or", 64),
            (mit, "mit", 67),
            (unknown, "123", 71),
        ]
        assert tokens == expected

        try:
            licensing.parse(
                "The GNU GPL 20 or later or (LGPL-2.1 and mit) or The GNU GPL 20 or mit 123"
            )
            self.fail("Exception not raised")
        except ParseError as pe:
            expected = {
                "error_code": PARSE_INVALID_SYMBOL_SEQUENCE,
                "position": 71,
                "token_string": "123",
                "token_type": unknown,
            }
            assert _parse_error_as_dict(pe) == expected

    def test_parse_expression_with_trailing_unknown_should_raise_exception2(self):
        _gpl2, _gpl2_plus, _lgpl, _mit, _mitand2, licensing = self.get_symbols_and_licensing()
        unknown = LicenseSymbol(key="123")
        try:
            licensing.parse("The GNU GPL 20 or mit 123")
            #                01234567890123456789012345
            self.fail("Exception not raised")
        except ParseError as pe:
            expected = {
                "error_code": PARSE_INVALID_SYMBOL_SEQUENCE,
                "position": 22,
                "token_string": "123",
                "token_type": unknown,
            }
            assert _parse_error_as_dict(pe) == expected

    def test_parse_expression_with_WITH(self):
        gpl2, _gpl2plus, lgpl, mit, mitand2, _ = self.get_symbols_and_licensing()
        mitexp = LicenseSymbol("mitexp", ("mit exp",), is_exception=True)
        gpl_20_or_later = LicenseSymbol("GPL-2.0+", ["The GNU GPL 20 or later"])

        symbols = [gpl2, lgpl, mit, mitand2, mitexp, gpl_20_or_later]
        licensing = Licensing(symbols)
        expr = "The GNU GPL 20 or later or (LGPL-2.1 and mit) or The GNU GPL 20 or mit with mit exp"
        tokens = list(licensing.tokenize(expr))
        expected = [
            (gpl_20_or_later, "The GNU GPL 20 or later", 0),
            (TOKEN_OR, "or", 24),
            (TOKEN_LPAR, "(", 27),
            (lgpl, "LGPL-2.1", 28),
            (TOKEN_AND, "and", 37),
            (mit, "mit", 41),
            (TOKEN_RPAR, ")", 44),
            (TOKEN_OR, "or", 46),
            (gpl2, "The GNU GPL 20", 49),
            (TOKEN_OR, "or", 64),
            (LicenseWithExceptionSymbol(mit, mitexp), "mit with mit exp", 67),
        ]

        assert tokens == expected

        parsed = licensing.parse(expr)
        expected = "GPL-2.0+ OR (LGPL-2.1 AND MIT) OR gpl-2.0 OR MIT WITH mitexp"
        assert str(parsed) == expected
        expected = "GPL-2.0+ OR (LGPL-2.1 AND MIT) OR gpl-2.0 OR MIT WITH mitexp"
        assert parsed.render() == expected

    def test_parse_expression_with_WITH_and_unknown_symbol(self):
        gpl2, _gpl2plus, lgpl, mit, mitand2, _ = self.get_symbols_and_licensing()
        mitexp = LicenseSymbol("mitexp", ("mit exp",), is_exception=True)
        gpl_20_or_later = LicenseSymbol("GPL-2.0+", ["The GNU GPL 20 or later"])

        symbols = [gpl2, lgpl, mit, mitand2, mitexp, gpl_20_or_later]
        licensing = Licensing(symbols)
        expr = "The GNU GPL 20 or later or (LGPL-2.1 and mit) or The GNU GPL 20 or mit with 123"
        parsed = licensing.parse(expr)

        assert ["123"] == licensing.unknown_license_keys(parsed)
        assert ["123"] == licensing.unknown_license_keys(expr)

    def test_unknown_keys(self):
        _gpl2, _gpl2plus, _lgpl, _mit, _mitand2, licensing = self.get_symbols_and_licensing()
        expr = "The GNU GPL 20 or LGPL-2.1 and mit"
        parsed = licensing.parse(expr)
        expected = "gpl-2.0 OR (LGPL-2.1 AND MIT)"
        assert str(parsed) == expected
        assert "gpl-2.0 OR (LGPL-2.1 AND MIT)" == parsed.render("{symbol.key}")
        assert [] == licensing.unknown_license_keys(parsed)
        assert [] == licensing.unknown_license_keys(expr)

    def test_unknown_keys_with_trailing_char(self):
        gpl2, _gpl2plus, lgpl, _mit, mitand2, licensing = self.get_symbols_and_licensing()
        expr = "The GNU GPL 20 or LGPL-2.1 and mitand2"
        parsed = licensing.parse(expr)
        expected = [gpl2, lgpl, mitand2]
        assert licensing.license_symbols(parsed) == expected
        assert licensing.license_symbols(licensing.parse(parsed)) == expected
        assert licensing.license_symbols(expr) == expected
        assert [] == licensing.unknown_license_keys(parsed)
        assert [] == licensing.unknown_license_keys(expr)

    def test_unknown_keys_with_trailing_char_2_with_validate(self):
        _gpl2, _gpl2plus, _lgpl, _mit, _mitand2, licensing = self.get_symbols_and_licensing()
        expr = "The GNU GPL 20 or LGPL-2.1 and mitand3"

        try:
            licensing.parse(expr, validate=True)
            self.fail("Exception should be raised")
        except ExpressionError as ee:
            assert "Unknown license key(s): mitand3" == str(ee)

    def test_unknown_keys_with_trailing_char_2_without_validate(self):
        _gpl2, _gpl2plus, _lgpl, _mit, _mitand2, licensing = self.get_symbols_and_licensing()
        expr = "The GNU GPL 20 or LGPL-2.1 and mitand3"
        parsed = licensing.parse(expr, validate=False)
        assert "gpl-2.0 OR (LGPL-2.1 AND mitand3)" == str(parsed)

    def test_parse_with_overlapping_key_without_symbols(self):
        expression = "mit or mit AND zlib or mit or mit with verylonglicense"
        #             1111111111222222222233333333334444444444555555555566666
        #             0123456789012345678901234567890123456789012345678901234

        licensing = Licensing()
        results = str(licensing.parse(expression))
        expected = "mit OR (mit AND zlib) OR mit OR mit WITH verylonglicense"
        assert results == expected

    def test_advanced_tokenizer_tokenize_with_overlapping_key_with_symbols_and_trailing_unknown(
        self,
    ):
        expression = "mit or mit AND zlib or mit or mit with verylonglicense"
        #                       111111111122222222223333333333444444444455555
        #             0123456789012345678901234567890123456789012345678901234

        symbols = [
            LicenseSymbol("MIT", ["MIT license"]),
            LicenseSymbol("LGPL-2.1", ["LGPL v2.1"]),
            LicenseSymbol("zlib", ["zlib"]),
            LicenseSymbol("d-zlib", ["D zlib"]),
            LicenseSymbol("mito", ["mit o"]),
            LicenseSymbol("hmit", ["h verylonglicense"]),
        ]
        licensing = Licensing(symbols)
        results = list(licensing.get_advanced_tokenizer().tokenize(expression))
        expected = [
            Token(0, 2, "mit", LicenseSymbol("MIT", aliases=("MIT license",))),
            Token(4, 5, "or", Keyword(value="or", type=2)),
            Token(7, 9, "mit", LicenseSymbol("MIT", aliases=("MIT license",))),
            Token(11, 13, "AND", Keyword(value="and", type=1)),
            Token(15, 18, "zlib", LicenseSymbol("zlib", aliases=("zlib",))),
            Token(20, 21, "or", Keyword(value="or", type=2)),
            Token(23, 25, "mit", LicenseSymbol("MIT", aliases=("MIT license",))),
            Token(27, 28, "or", Keyword(value="or", type=2)),
            Token(30, 32, "mit", LicenseSymbol("MIT", aliases=("MIT license",))),
            Token(34, 37, "with", Keyword(value="with", type=10)),
            Token(39, 53, "verylonglicense", None),
        ]

        assert results == expected

    def test_advanced_tokenizer_iter_with_overlapping_key_with_symbols_and_trailing_unknown(self):
        expression = "mit or mit AND zlib or mit or mit with verylonglicense"
        #                       111111111122222222223333333333444444444455555
        #             0123456789012345678901234567890123456789012345678901234

        symbols = [
            LicenseSymbol("MIT", ["MIT license"]),
            LicenseSymbol("LGPL-2.1", ["LGPL v2.1"]),
            LicenseSymbol("zlib", ["zlib"]),
            LicenseSymbol("d-zlib", ["D zlib"]),
            LicenseSymbol("mito", ["mit o"]),
            LicenseSymbol("hmit", ["h verylonglicense"]),
        ]
        licensing = Licensing(symbols)
        results = list(licensing.get_advanced_tokenizer().iter(expression, include_unmatched=True))
        expected = [
            Token(0, 2, "mit", LicenseSymbol("MIT", aliases=("MIT license",))),
            Token(4, 5, "or", Keyword(value="or", type=2)),
            Token(7, 9, "mit", LicenseSymbol("MIT", aliases=("MIT license",))),
            Token(11, 13, "AND", Keyword(value="and", type=1)),
            Token(15, 18, "zlib", LicenseSymbol("zlib", aliases=("zlib",))),
            Token(20, 21, "or", Keyword(value="or", type=2)),
            Token(23, 25, "mit", LicenseSymbol("MIT", aliases=("MIT license",))),
            Token(27, 28, "or", Keyword(value="or", type=2)),
            Token(30, 32, "mit", LicenseSymbol("MIT", aliases=("MIT license",))),
            Token(34, 37, "with", Keyword(value="with", type=10)),
            Token(39, 53, "verylonglicense", None),
        ]
        assert results == expected

    def test_advanced_tokenizer_iter_with_overlapping_key_with_symbols_and_trailing_unknown2(self):
        expression = "mit with verylonglicense"
        symbols = [
            LicenseSymbol("MIT", ["MIT license"]),
            LicenseSymbol("hmit", ["h verylonglicense"]),
        ]
        licensing = Licensing(symbols)
        results = list(licensing.get_advanced_tokenizer().iter(expression, include_unmatched=True))
        expected = [
            Token(0, 2, "mit", LicenseSymbol("MIT", aliases=("MIT license",))),
            Token(4, 7, "with", Keyword(value="with", type=10)),
            Token(9, 23, "verylonglicense", None),
        ]
        assert results == expected

    def test_tokenize_with_overlapping_key_with_symbols_and_trailing_unknown(self):
        expression = "mit or mit AND zlib or mit or mit with verylonglicense"
        #             1111111111222222222233333333334444444444555555555566666
        #             0123456789012345678901234567890123456789012345678901234

        symbols = [
            LicenseSymbol("MIT", ["MIT license"]),
            LicenseSymbol("LGPL-2.1", ["LGPL v2.1"]),
            LicenseSymbol("zlib", ["zlib"]),
            LicenseSymbol("d-zlib", ["D zlib"]),
            LicenseSymbol("mito", ["mit o"]),
            LicenseSymbol("hmit", ["h verylonglicense"]),
        ]
        licensing = Licensing(symbols)

        results = list(licensing.tokenize(expression))
        expected = [
            (LicenseSymbol("MIT", aliases=("MIT license",)), "mit", 0),
            (2, "or", 4),
            (LicenseSymbol("MIT", aliases=("MIT license",)), "mit", 7),
            (1, "AND", 11),
            (LicenseSymbol("zlib", aliases=("zlib",)), "zlib", 15),
            (2, "or", 20),
            (LicenseSymbol("MIT", aliases=("MIT license",)), "mit", 23),
            (2, "or", 27),
            (
                LicenseWithExceptionSymbol(
                    license_symbol=LicenseSymbol("MIT", aliases=("MIT license",)),
                    exception_symbol=LicenseSymbol("verylonglicense"),
                ),
                "mit with verylonglicense",
                30,
            ),
        ]

        assert results == expected

        results = str(licensing.parse(expression))
        expected = "MIT OR (MIT AND zlib) OR MIT OR MIT WITH verylonglicense"
        assert results == expected


class LicensingSymbolsTest(TestCase):
    def test_get_license_symbols(self):
        symbols = [LicenseSymbol("GPL-2.0"), LicenseSymbol("mit"), LicenseSymbol("LGPL 2.1")]
        l = Licensing(symbols)
        assert symbols == l.license_symbols(l.parse(" GPL-2.0 and mit or LGPL 2.1 and mit "))

    def test_get_license_symbols2(self):
        symbols = [
            LicenseSymbol("GPL-2.0"),
            LicenseSymbol("LATER"),
            LicenseSymbol("mit"),
            LicenseSymbol("LGPL 2.1+"),
            LicenseSymbol("Foo exception", is_exception=True),
        ]
        l = Licensing(symbols)
        expr = " GPL-2.0 or LATER and mit or LGPL 2.1+ and mit with Foo exception "
        expected = [
            LicenseSymbol("GPL-2.0"),
            LicenseSymbol("LATER"),
            LicenseSymbol("mit"),
            LicenseSymbol("LGPL 2.1+"),
            LicenseSymbol("mit"),
            LicenseSymbol("Foo exception", is_exception=True),
        ]
        assert l.license_symbols(l.parse(expr), unique=False) == expected

    def test_get_license_symbols3(self):
        symbols = [
            LicenseSymbol("mit"),
            LicenseSymbol("LGPL 2.1+"),
            LicenseSymbol("Foo exception", is_exception=True),
            LicenseSymbol("GPL-2.0"),
            LicenseSymbol("LATER"),
        ]
        l = Licensing(symbols)
        expr = "mit or LGPL 2.1+ and mit with Foo exception or GPL-2.0 or LATER "
        assert symbols == l.license_symbols(l.parse(expr))

    def test_get_license_symbols4(self):
        symbols = [
            LicenseSymbol("GPL-2.0"),
            LicenseSymbol("LATER"),
            LicenseSymbol("big exception", is_exception=True),
            LicenseSymbol("mit"),
            LicenseSymbol("LGPL 2.1+"),
            LicenseSymbol("Foo exception", is_exception=True),
        ]
        l = Licensing(symbols)
        expr = (
            " GPL-2.0 or LATER with big exception and mit or "
            "LGPL 2.1+ and mit or later with Foo exception "
        )
        expected = [
            LicenseSymbol("GPL-2.0"),
            LicenseSymbol("LATER"),
            LicenseSymbol("big exception", is_exception=True),
            LicenseSymbol("mit"),
            LicenseSymbol("LGPL 2.1+"),
            LicenseSymbol("mit"),
            LicenseSymbol("LATER"),
            LicenseSymbol("Foo exception", is_exception=True),
        ]

        assert l.license_symbols(l.parse(expr), unique=False) == expected

    def test_license_symbols(self):
        licensing = Licensing(
            [
                "GPL-2.0 or LATER",
                "classpath Exception",
                "something with else+",
                "mit",
                "LGPL 2.1",
                "mit or later",
            ]
        )

        expr = (
            " GPL-2.0 or LATER with classpath Exception and mit and "
            "mit with SOMETHING with ELSE+ or LGPL 2.1 and "
            "GPL-2.0 or LATER with classpath Exception and "
            "mit or later or LGPL 2.1 or mit or GPL-2.0 or LATER "
            "with SOMETHING with ELSE+ and lgpl 2.1"
        )

        gpl2plus = LicenseSymbol(key="GPL-2.0 or LATER")
        cpex = LicenseSymbol(key="classpath Exception")
        someplus = LicenseSymbol(key="something with else+")
        mitplus = LicenseSymbol(key="mit or later")
        mit = LicenseSymbol(key="mit")
        lgpl = LicenseSymbol(key="LGPL 2.1")
        gpl_with_cp = LicenseWithExceptionSymbol(license_symbol=gpl2plus, exception_symbol=cpex)
        mit_with_some = LicenseWithExceptionSymbol(license_symbol=mit, exception_symbol=someplus)
        gpl2_with_someplus = LicenseWithExceptionSymbol(
            license_symbol=gpl2plus, exception_symbol=someplus
        )

        parsed = licensing.parse(expr)
        expected = [
            gpl_with_cp,
            mit,
            mit_with_some,
            lgpl,
            gpl_with_cp,
            mitplus,
            lgpl,
            mit,
            gpl2_with_someplus,
            lgpl,
        ]

        assert licensing.license_symbols(parsed, unique=False, decompose=False) == expected

        expected = [gpl_with_cp, mit, mit_with_some, lgpl, mitplus, gpl2_with_someplus]
        assert licensing.license_symbols(parsed, unique=True, decompose=False) == expected

        expected = [
            gpl2plus,
            cpex,
            mit,
            mit,
            someplus,
            lgpl,
            gpl2plus,
            cpex,
            mitplus,
            lgpl,
            mit,
            gpl2plus,
            someplus,
            lgpl,
        ]
        assert licensing.license_symbols(parsed, unique=False, decompose=True) == expected

        expected = [gpl2plus, cpex, mit, someplus, lgpl, mitplus]
        assert licensing.license_symbols(parsed, unique=True, decompose=True) == expected

    def test_primary_license_symbol_and_primary_license_key(self):
        licensing = Licensing(
            ["GPL-2.0 or LATER", "classpath Exception", "mit", "LGPL 2.1", "mit or later"]
        )

        expr = " GPL-2.0 or LATER with classpath Exception and mit or LGPL 2.1 and mit or later "
        gpl = LicenseSymbol("GPL-2.0 or LATER")
        cpex = LicenseSymbol("classpath Exception")
        expected = LicenseWithExceptionSymbol(gpl, cpex)
        parsed = licensing.parse(expr)
        assert licensing.primary_license_symbol(parsed, decompose=False) == expected
        assert gpl == licensing.primary_license_symbol(parsed, decompose=True)
        assert "GPL-2.0 or LATER" == licensing.primary_license_key(parsed)

        expr = " GPL-2.0 or later with classpath Exception and mit or LGPL 2.1 and mit or later "
        expected = "GPL-2.0 or LATER WITH classpath Exception"
        result = licensing.primary_license_symbol(parsed, decompose=False).render("{symbol.key}")
        assert result == expected

    def test_render_plain(self):
        l = Licensing()
        result = l.parse("gpl-2.0 WITH exception-gpl-2.0-plus or MIT").render()
        expected = "gpl-2.0 WITH exception-gpl-2.0-plus OR MIT"
        assert result == expected

    def test_render_as_readable_does_not_wrap_in_parens_single_with(self):
        l = Licensing()
        result = l.parse("gpl-2.0 WITH exception-gpl-2.0-plus").render_as_readable()
        expected = "gpl-2.0 WITH exception-gpl-2.0-plus"
        assert result == expected

    def test_render_as_readable_wraps_in_parens_with_and_other_subexpressions(self):
        l = Licensing()
        result = l.parse("mit AND gpl-2.0 WITH exception-gpl-2.0-plus").render_as_readable()
        expected = "mit AND (gpl-2.0 WITH exception-gpl-2.0-plus)"
        assert result == expected

    def test_render_as_readable_does_not_wrap_in_parens_if_no_with(self):
        l = Licensing()
        result1 = l.parse("gpl-2.0 and exception OR that").render_as_readable()
        result2 = l.parse("gpl-2.0 and exception OR that").render()
        assert result1 == result2


class SplitAndTokenizeTest(TestCase):
    def test_simple_tokenizer(self):
        expr = (
            " GPL-2.0 or later with classpath Exception and mit and "
            "mit with SOMETHING with ELSE+ or LGPL 2.1 and "
            "GPL-2.0 or LATER with (Classpath Exception and "
            "mit or later) or LGPL 2.1 or mit or GPL-2.0 or LATER "
            "with SOMETHING with ELSE+ and lgpl 2.1"
        )
        licensing = Licensing()
        results = list(licensing.simple_tokenizer(expr))
        expected = [
            Token(0, 0, " ", None),
            Token(1, 7, "GPL-2.0", LicenseSymbol(key="GPL-2.0")),
            Token(8, 8, " ", None),
            Token(9, 10, "or", Keyword(value="or", type=TOKEN_OR)),
            Token(11, 11, " ", None),
            Token(12, 16, "later", LicenseSymbol(key="later")),
            Token(17, 17, " ", None),
            Token(18, 21, "with", Keyword(value="with", type=TOKEN_WITH)),
            Token(22, 22, " ", None),
            Token(23, 31, "classpath", LicenseSymbol(key="classpath")),
            Token(32, 32, " ", None),
            Token(33, 41, "Exception", LicenseSymbol(key="Exception")),
            Token(42, 42, " ", None),
            Token(43, 45, "and", Keyword(value="and", type=TOKEN_AND)),
            Token(46, 46, " ", None),
            Token(47, 49, "mit", LicenseSymbol(key="mit")),
            Token(50, 50, " ", None),
            Token(51, 53, "and", Keyword(value="and", type=TOKEN_AND)),
            Token(54, 54, " ", None),
            Token(55, 57, "mit", LicenseSymbol(key="mit")),
            Token(58, 58, " ", None),
            Token(59, 62, "with", Keyword(value="with", type=TOKEN_WITH)),
            Token(63, 63, " ", None),
            Token(64, 72, "SOMETHING", LicenseSymbol(key="SOMETHING")),
            Token(73, 73, " ", None),
            Token(74, 77, "with", Keyword(value="with", type=TOKEN_WITH)),
            Token(78, 78, " ", None),
            Token(79, 83, "ELSE+", LicenseSymbol(key="ELSE+")),
            Token(84, 84, " ", None),
            Token(85, 86, "or", Keyword(value="or", type=TOKEN_OR)),
            Token(87, 87, " ", None),
            Token(88, 91, "LGPL", LicenseSymbol(key="LGPL")),
            Token(92, 92, " ", None),
            Token(93, 95, "2.1", LicenseSymbol(key="2.1")),
            Token(96, 96, " ", None),
            Token(97, 99, "and", Keyword(value="and", type=TOKEN_AND)),
            Token(100, 100, " ", None),
            Token(101, 107, "GPL-2.0", LicenseSymbol(key="GPL-2.0")),
            Token(108, 108, " ", None),
            Token(109, 110, "or", Keyword(value="or", type=TOKEN_OR)),
            Token(111, 111, " ", None),
            Token(112, 116, "LATER", LicenseSymbol(key="LATER")),
            Token(117, 117, " ", None),
            Token(118, 121, "with", Keyword(value="with", type=TOKEN_WITH)),
            Token(122, 122, " ", None),
            Token(123, 123, "(", Keyword(value="(", type=TOKEN_LPAR)),
            Token(124, 132, "Classpath", LicenseSymbol(key="Classpath")),
            Token(133, 133, " ", None),
            Token(134, 142, "Exception", LicenseSymbol(key="Exception")),
            Token(143, 143, " ", None),
            Token(144, 146, "and", Keyword(value="and", type=TOKEN_AND)),
            Token(147, 147, " ", None),
            Token(148, 150, "mit", LicenseSymbol(key="mit")),
            Token(151, 151, " ", None),
            Token(152, 153, "or", Keyword(value="or", type=TOKEN_OR)),
            Token(154, 154, " ", None),
            Token(155, 159, "later", LicenseSymbol(key="later")),
            Token(160, 160, ")", Keyword(value=")", type=TOKEN_RPAR)),
            Token(161, 161, " ", None),
            Token(162, 163, "or", Keyword(value="or", type=TOKEN_OR)),
            Token(164, 164, " ", None),
            Token(165, 168, "LGPL", LicenseSymbol(key="LGPL")),
            Token(169, 169, " ", None),
            Token(170, 172, "2.1", LicenseSymbol(key="2.1")),
            Token(173, 173, " ", None),
            Token(174, 175, "or", Keyword(value="or", type=TOKEN_OR)),
            Token(176, 176, " ", None),
            Token(177, 179, "mit", LicenseSymbol(key="mit")),
            Token(180, 180, " ", None),
            Token(181, 182, "or", Keyword(value="or", type=TOKEN_OR)),
            Token(183, 183, " ", None),
            Token(184, 190, "GPL-2.0", LicenseSymbol(key="GPL-2.0")),
            Token(191, 191, " ", None),
            Token(192, 193, "or", Keyword(value="or", type=TOKEN_OR)),
            Token(194, 194, " ", None),
            Token(195, 199, "LATER", LicenseSymbol(key="LATER")),
            Token(200, 200, " ", None),
            Token(201, 204, "with", Keyword(value="with", type=TOKEN_WITH)),
            Token(205, 205, " ", None),
            Token(206, 214, "SOMETHING", LicenseSymbol(key="SOMETHING")),
            Token(215, 215, " ", None),
            Token(216, 219, "with", Keyword(value="with", type=TOKEN_WITH)),
            Token(220, 220, " ", None),
            Token(221, 225, "ELSE+", LicenseSymbol(key="ELSE+")),
            Token(226, 226, " ", None),
            Token(227, 229, "and", Keyword(value="and", type=TOKEN_AND)),
            Token(230, 230, " ", None),
            Token(231, 234, "lgpl", LicenseSymbol(key="lgpl")),
            Token(235, 235, " ", None),
            Token(
                236,
                238,
                "2.1",
                LicenseSymbol(
                    key="2.1",
                ),
            ),
        ]
        assert results == expected

    def test_tokenize_can_handle_expressions_with_symbols_that_contain_a_colon(self):
        licensing = Licensing()
        expression = "DocumentRef-James-1.0:LicenseRef-Eric-2.0"

        result = list(licensing.tokenize(expression))
        expected = [
            (
                LicenseSymbol("DocumentRef-James-1.0:LicenseRef-Eric-2.0", is_exception=False),
                "DocumentRef-James-1.0:LicenseRef-Eric-2.0",
                0,
            )
        ]

        assert result == expected

    def test_tokenize_simple_can_handle_expressions_with_symbols_that_contain_a_colon(self):
        licensing = Licensing()
        expression = "DocumentRef-James-1.0:LicenseRef-Eric-2.0"

        result = list(licensing.tokenize(expression, simple=True))
        expected = [
            (
                LicenseSymbol("DocumentRef-James-1.0:LicenseRef-Eric-2.0", is_exception=False),
                "DocumentRef-James-1.0:LicenseRef-Eric-2.0",
                0,
            )
        ]

        assert result == expected

    def test_tokenize_can_handle_expressions_with_tabs_and_new_lines(self):
        licensing = Licensing()
        expression = "this\t \tis \n\n an expression"
        result = list(licensing.tokenize(expression, simple=False))
        expected = [
            (LicenseSymbol("this is an expression", is_exception=False), "this is an expression", 0)
        ]
        assert result == expected

    def test_tokenize_simple_can_handle_expressions_with_tabs_and_new_lines(self):
        licensing = Licensing()
        expression = "this\t \tis \n\n an expression"
        result = list(licensing.tokenize(expression, simple=True))
        expected = [
            (LicenseSymbol("this", is_exception=False), "this", 0),
            (LicenseSymbol("is", is_exception=False), "is", 7),
            (LicenseSymbol("an", is_exception=False), "an", 13),
            (LicenseSymbol("expression", is_exception=False), "expression", 16),
        ]
        assert result == expected

    def test_tokenize_step_by_step_does_not_munge_trailing_symbols(self):
        gpl2 = LicenseSymbol(key="GPL-2.0")
        gpl2plus = LicenseSymbol(key="GPL-2.0 or LATER")
        cpex = LicenseSymbol(key="classpath Exception", is_exception=True)

        mitthing = LicenseSymbol(key="mithing")
        mitthing_with_else = LicenseSymbol(key="mitthing with else+", is_exception=False)

        mit = LicenseSymbol(key="mit")
        mitplus = LicenseSymbol(key="mit or later")

        elsish = LicenseSymbol(key="else")
        elsishplus = LicenseSymbol(key="else+")

        lgpl = LicenseSymbol(key="LGPL 2.1")

        licensing = Licensing(
            [
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
            ]
        )

        expr = (
            " GPL-2.0 or later with classpath Exception and mit and "
            "mit with mitthing with ELSE+ or LGPL 2.1 and "
            "GPL-2.0 or LATER with Classpath Exception and "
            "mit or later or LGPL 2.1 or mit or GPL-2.0 or LATER "
            "with mitthing with ELSE+ and lgpl 2.1 or gpl-2.0"
        )

        # fist tokenize
        tokenizer = licensing.get_advanced_tokenizer()
        result = list(tokenizer.tokenize(expr))
        expected = [
            Token(1, 16, "GPL-2.0 or later", LicenseSymbol("GPL-2.0 or LATER")),
            Token(18, 21, "with", Keyword(value="with", type=10)),
            Token(
                23,
                41,
                "classpath Exception",
                LicenseSymbol("classpath Exception", is_exception=True),
            ),
            Token(43, 45, "and", Keyword(value="and", type=1)),
            Token(47, 49, "mit", LicenseSymbol("mit")),
            Token(51, 53, "and", Keyword(value="and", type=1)),
            Token(55, 57, "mit", LicenseSymbol("mit")),
            Token(59, 62, "with", Keyword(value="with", type=10)),
            Token(64, 82, "mitthing with ELSE+", LicenseSymbol("mitthing with else+")),
            Token(84, 85, "or", Keyword(value="or", type=2)),
            Token(87, 94, "LGPL 2.1", LicenseSymbol("LGPL 2.1")),
            Token(96, 98, "and", Keyword(value="and", type=1)),
            Token(100, 115, "GPL-2.0 or LATER", LicenseSymbol("GPL-2.0 or LATER")),
            Token(117, 120, "with", Keyword(value="with", type=10)),
            Token(
                122,
                140,
                "Classpath Exception",
                LicenseSymbol("classpath Exception", is_exception=True),
            ),
            Token(142, 144, "and", Keyword(value="and", type=1)),
            Token(146, 157, "mit or later", LicenseSymbol("mit or later")),
            Token(159, 160, "or", Keyword(value="or", type=2)),
            Token(162, 169, "LGPL 2.1", LicenseSymbol("LGPL 2.1")),
            Token(171, 172, "or", Keyword(value="or", type=2)),
            Token(174, 176, "mit", LicenseSymbol("mit")),
            Token(178, 179, "or", Keyword(value="or", type=2)),
            Token(181, 196, "GPL-2.0 or LATER", LicenseSymbol("GPL-2.0 or LATER")),
            Token(198, 201, "with", Keyword(value="with", type=10)),
            Token(203, 221, "mitthing with ELSE+", LicenseSymbol("mitthing with else+")),
            Token(223, 225, "and", Keyword(value="and", type=1)),
            Token(227, 234, "lgpl 2.1", LicenseSymbol("LGPL 2.1")),
            Token(236, 237, "or", Keyword(value="or", type=2)),
            Token(239, 245, "gpl-2.0", LicenseSymbol("GPL-2.0")),
        ]

        assert result == expected

        expected_groups = [
            (
                Token(1, 16, "GPL-2.0 or later", LicenseSymbol("GPL-2.0 or LATER")),
                Token(18, 21, "with", Keyword(value="with", type=10)),
                Token(
                    23,
                    41,
                    "classpath Exception",
                    LicenseSymbol("classpath Exception", is_exception=True),
                ),
            ),
            (Token(43, 45, "and", Keyword(value="and", type=1)),),
            (Token(47, 49, "mit", LicenseSymbol("mit")),),
            (Token(51, 53, "and", Keyword(value="and", type=1)),),
            (
                Token(55, 57, "mit", LicenseSymbol("mit")),
                Token(59, 62, "with", Keyword(value="with", type=10)),
                Token(64, 82, "mitthing with ELSE+", LicenseSymbol("mitthing with else+")),
            ),
            (Token(84, 85, "or", Keyword(value="or", type=2)),),
            (Token(87, 94, "LGPL 2.1", LicenseSymbol("LGPL 2.1")),),
            (Token(96, 98, "and", Keyword(value="and", type=1)),),
            (
                Token(100, 115, "GPL-2.0 or LATER", LicenseSymbol("GPL-2.0 or LATER")),
                Token(117, 120, "with", Keyword(value="with", type=10)),
                Token(
                    122,
                    140,
                    "Classpath Exception",
                    LicenseSymbol("classpath Exception", is_exception=True),
                ),
            ),
            (Token(142, 144, "and", Keyword(value="and", type=1)),),
            (Token(146, 157, "mit or later", LicenseSymbol("mit or later")),),
            (Token(159, 160, "or", Keyword(value="or", type=2)),),
            (Token(162, 169, "LGPL 2.1", LicenseSymbol("LGPL 2.1")),),
            (Token(171, 172, "or", Keyword(value="or", type=2)),),
            (Token(174, 176, "mit", LicenseSymbol("mit")),),
            (Token(178, 179, "or", Keyword(value="or", type=2)),),
            (
                Token(181, 196, "GPL-2.0 or LATER", LicenseSymbol("GPL-2.0 or LATER")),
                Token(198, 201, "with", Keyword(value="with", type=10)),
                Token(203, 221, "mitthing with ELSE+", LicenseSymbol("mitthing with else+")),
            ),
            (Token(223, 225, "and", Keyword(value="and", type=1)),),
            (Token(227, 234, "lgpl 2.1", LicenseSymbol("LGPL 2.1")),),
            (Token(236, 237, "or", Keyword(value="or", type=2)),),
            (Token(239, 245, "gpl-2.0", LicenseSymbol("GPL-2.0")),),
        ]
        result_groups = list(build_token_groups_for_with_subexpression(result))
        assert expected_groups == result_groups

        # finally retest it all with tokenize

        gpl2plus_with_cpex = LicenseWithExceptionSymbol(
            license_symbol=gpl2plus, exception_symbol=cpex
        )
        gpl2plus_with_someplus = LicenseWithExceptionSymbol(
            license_symbol=gpl2plus, exception_symbol=mitthing_with_else
        )

        mit_with_mitthing_with_else = LicenseWithExceptionSymbol(
            license_symbol=mit, exception_symbol=mitthing_with_else
        )

        expected = [
            (gpl2plus_with_cpex, "GPL-2.0 or later with classpath Exception", 1),
            (TOKEN_AND, "and", 43),
            (mit, "mit", 47),
            (TOKEN_AND, "and", 51),
            (mit_with_mitthing_with_else, "mit with mitthing with ELSE+", 55),
            (TOKEN_OR, "or", 84),
            (lgpl, "LGPL 2.1", 87),
            (TOKEN_AND, "and", 96),
            (gpl2plus_with_cpex, "GPL-2.0 or LATER with Classpath Exception", 100),
            (TOKEN_AND, "and", 142),
            (mitplus, "mit or later", 146),
            (TOKEN_OR, "or", 159),
            (lgpl, "LGPL 2.1", 162),
            (TOKEN_OR, "or", 171),
            (mit, "mit", 174),
            (TOKEN_OR, "or", 178),
            (gpl2plus_with_someplus, "GPL-2.0 or LATER with mitthing with ELSE+", 181),
            (TOKEN_AND, "and", 223),
            (lgpl, "lgpl 2.1", 227),
            (TOKEN_OR, "or", 236),
            (gpl2, "gpl-2.0", 239),
        ]

        assert list(licensing.tokenize(expr)) == expected


class LicensingExpression(TestCase):
    def test_is_equivalent_with_same_Licensing(self):
        licensing = Licensing()
        parsed1 = licensing.parse("gpl-2.0 AND zlib")
        parsed2 = licensing.parse("gpl-2.0 AND zlib AND zlib")
        assert licensing.is_equivalent(parsed1, parsed2)
        assert Licensing().is_equivalent(parsed1, parsed2)

    def test_is_equivalent_with_same_Licensing2(self):
        licensing = Licensing()
        parsed1 = licensing.parse("(gpl-2.0 AND zlib) or lgpl")
        parsed2 = licensing.parse("lgpl or (gpl-2.0 AND zlib)")
        assert licensing.is_equivalent(parsed1, parsed2)
        assert Licensing().is_equivalent(parsed1, parsed2)

    def test_is_equivalent_with_different_Licensing_and_compound_expression(self):
        licensing1 = Licensing()
        licensing2 = Licensing()
        parsed1 = licensing1.parse("gpl-2.0 AND zlib")
        parsed2 = licensing2.parse("gpl-2.0 AND zlib AND zlib")
        assert Licensing().is_equivalent(parsed1, parsed2)
        assert licensing1.is_equivalent(parsed1, parsed2)
        assert licensing2.is_equivalent(parsed1, parsed2)

    def test_is_equivalent_with_different_Licensing_and_compound_expression2(self):
        licensing1 = Licensing()
        licensing2 = Licensing()
        parsed1 = licensing1.parse("gpl-2.0 AND zlib")
        parsed2 = licensing2.parse("zlib and gpl-2.0")
        assert Licensing().is_equivalent(parsed1, parsed2)
        assert licensing1.is_equivalent(parsed1, parsed2)
        assert licensing2.is_equivalent(parsed1, parsed2)

    def test_is_equivalent_with_different_Licensing_and_simple_expression(self):
        licensing1 = Licensing()
        licensing2 = Licensing()
        parsed1 = licensing1.parse("gpl-2.0")
        parsed2 = licensing2.parse("gpl-2.0")
        assert Licensing().is_equivalent(parsed1, parsed2)
        assert licensing1.is_equivalent(parsed1, parsed2)
        assert licensing2.is_equivalent(parsed1, parsed2)

    def test_is_equivalent_with_symbols_and_complex_expression(self):
        licensing_no_sym = Licensing()
        licensing1 = Licensing(
            [
                "GPL-2.0 or LATER",
                "classpath Exception",
                "agpl+",
                "mit",
                "LGPL 2.1",
            ]
        )
        licensing2 = Licensing(
            [
                "GPL-2.0 or LATER",
                "classpath Exception",
                "agpl+",
                "mit",
                "LGPL 2.1",
            ]
        )

        parsed1 = licensing1.parse(
            " ((LGPL 2.1 or mit) and GPL-2.0 or LATER with classpath Exception) and agpl+"
        )
        parsed2 = licensing2.parse(
            " agpl+ and (GPL-2.0 or LATER with classpath Exception and (mit  or LGPL 2.1))"
        )
        assert licensing1.is_equivalent(parsed1, parsed2)
        assert licensing2.is_equivalent(parsed1, parsed2)
        assert licensing_no_sym.is_equivalent(parsed1, parsed2)

        parsed3 = licensing1.parse(
            " ((LGPL 2.1 or mit) OR GPL-2.0 or LATER with classpath Exception) and agpl+"
        )
        assert not licensing1.is_equivalent(parsed1, parsed3)
        assert not licensing2.is_equivalent(parsed1, parsed3)
        assert not licensing_no_sym.is_equivalent(parsed1, parsed3)

    def test_all_symbol_classes_can_compare_and_sort(self):
        l1 = LicenseSymbol("a")
        l2 = LicenseSymbol("b")
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

        l3 = LicenseSymbolLike(SymLike("b"))
        lx3 = LicenseWithExceptionSymbol(l1, l3)
        assert not (lx < lx3)
        assert not (lx3 < lx)
        assert lx3 == lx
        assert hash(lx3) == hash(lx)
        assert not (lx3 != lx)

        assert l2 == l3
        assert hash(l2) == hash(l3)

        l4 = LicenseSymbolLike(SymLike("c"))

        expected = [l1, lx, lx2, lx3, l3, l2, l4]
        assert sorted([l4, l3, l2, l1, lx, lx2, lx3]) == expected


class MockLicensesTest(TestCase):
    def test_licensing_can_use_mocklicense_tuple(self):
        MockLicense = namedtuple("MockLicense", "key aliases is_exception")

        licenses = [
            MockLicense("gpl-2.0", ["GPL-2.0"], False),
            MockLicense("classpath-2.0", ["Classpath-Exception-2.0"], True),
            MockLicense("gpl-2.0-plus", ["GPL-2.0-or-later", "GPL-2.0 or-later"], False),
            MockLicense("lgpl-2.1-plus", ["LGPL-2.1-or-later"], False),
        ]
        licensing = Licensing(licenses)

        ex1 = "(GPL-2.0-or-later with Classpath-Exception-2.0 or GPL-2.0 or-later) and LGPL-2.1-or-later"
        expression1 = licensing.parse(ex1, validate=False, strict=False)
        assert ["gpl-2.0-plus", "classpath-2.0", "lgpl-2.1-plus"] == licensing.license_keys(
            expression1
        )

        ex2 = "LGPL-2.1-or-later and (GPL-2.0-or-later oR GPL-2.0-or-later with Classpath-Exception-2.0)"
        expression2 = licensing.parse(ex2, validate=True, strict=False)

        ex3 = "LGPL-2.1-or-later and (GPL-2.0-or-later oR GPL-2.0-or-later)"
        expression3 = licensing.parse(ex3, validate=True, strict=False)

        self.assertTrue(licensing.is_equivalent(expression1, expression2))
        self.assertTrue(licensing.is_equivalent(expression2, expression1))
        self.assertFalse(licensing.is_equivalent(expression1, expression3))
        self.assertFalse(licensing.is_equivalent(expression2, expression3))

    def test_and_and_or_is_invalid(self):
        expression = "gpl-2.0 with classpath and and or gpl-2.0-plus"
        licensing = Licensing()
        try:
            licensing.parse(expression)
            self.fail("Exception not raised")
        except ParseError as pe:
            expected = {
                "error_code": PARSE_INVALID_OPERATOR_SEQUENCE,
                "position": 27,
                "token_string": "and",
                "token_type": TOKEN_AND,
            }
            assert _parse_error_as_dict(pe) == expected

    def test_or_or_is_invalid(self):
        expression = "gpl-2.0 with classpath or or or or gpl-2.0-plus"
        licensing = Licensing()
        try:
            licensing.parse(expression)
        except ParseError as pe:
            expected = {
                "error_code": PARSE_INVALID_OPERATOR_SEQUENCE,
                "position": 26,
                "token_string": "or",
                "token_type": TOKEN_OR,
            }
            assert _parse_error_as_dict(pe) == expected

    def test_tokenize_or_or(self):
        expression = "gpl-2.0 with classpath or or or gpl-2.0-plus"
        licensing = Licensing()
        results = list(licensing.tokenize(expression))
        expected = [
            (
                LicenseWithExceptionSymbol(
                    license_symbol=LicenseSymbol("gpl-2.0"),
                    exception_symbol=LicenseSymbol("classpath"),
                ),
                "gpl-2.0 with classpath",
                0,
            ),
            (2, "or", 23),
            (2, "or", 26),
            (2, "or", 29),
            (LicenseSymbol("gpl-2.0-plus"), "gpl-2.0-plus", 32),
        ]

        assert results == expected


class LicensingValidateTest(TestCase):
    licensing = Licensing(
        [
            LicenseSymbol(key="GPL-2.0-or-later", is_exception=False),
            LicenseSymbol(key="MIT", is_exception=False),
            LicenseSymbol(key="Apache-2.0", is_exception=False),
            LicenseSymbol(key="WxWindows-exception-3.1", is_exception=True),
        ]
    )

    def test_validate_simple(self):
        result = self.licensing.validate("GPL-2.0-or-later AND MIT")
        assert result.original_expression == "GPL-2.0-or-later AND MIT"
        assert result.normalized_expression == "GPL-2.0-or-later AND MIT"
        assert result.errors == []
        assert result.invalid_symbols == []

    def test_validation_invalid_license_key(self):
        result = self.licensing.validate("cool-license")
        assert result.original_expression == "cool-license"
        assert not result.normalized_expression
        assert result.errors == ["Unknown license key(s): cool-license"]
        assert result.invalid_symbols == ["cool-license"]

    def test_validate_exception(self):
        result = self.licensing.validate("GPL-2.0-or-later WITH WxWindows-exception-3.1")
        assert result.original_expression == "GPL-2.0-or-later WITH WxWindows-exception-3.1"
        assert result.normalized_expression == "GPL-2.0-or-later WITH WxWindows-exception-3.1"
        assert result.errors == []
        assert result.invalid_symbols == []

    def test_validation_exception_with_choice(self):
        result = self.licensing.validate("GPL-2.0-or-later WITH WxWindows-exception-3.1 OR MIT")
        assert result.original_expression == "GPL-2.0-or-later WITH WxWindows-exception-3.1 OR MIT"
        assert (
            result.normalized_expression == "GPL-2.0-or-later WITH WxWindows-exception-3.1 OR MIT"
        )
        assert result.errors == []
        assert result.invalid_symbols == []

    def test_validation_exception_as_regular_key(self):
        result = self.licensing.validate("GPL-2.0-or-later AND WxWindows-exception-3.1")
        assert result.original_expression == "GPL-2.0-or-later AND WxWindows-exception-3.1"
        assert not result.normalized_expression
        assert result.errors == [
            'A license exception symbol can only be used as an exception in a "WITH exception" statement. for token: "WxWindows-exception-3.1" at position: 21'
        ]
        assert result.invalid_symbols == ["WxWindows-exception-3.1"]

    def test_validation_bad_syntax(self):
        result = self.licensing.validate("Apache-2.0 + MIT")
        assert result.original_expression == "Apache-2.0 + MIT"
        assert not result.normalized_expression
        assert result.errors == [
            'Invalid symbols sequence such as (A B) for token: "+" at position: 11'
        ]
        assert result.invalid_symbols == ["+"]

    def test_validation_invalid_license_exception(self):
        result = self.licensing.validate("Apache-2.0 WITH MIT")
        assert result.original_expression == "Apache-2.0 WITH MIT"
        assert not result.normalized_expression
        assert result.errors == [
            'A plain license symbol cannot be used as an exception in a "WITH symbol" statement. for token: "MIT" at position: 16'
        ]
        assert result.invalid_symbols == ["MIT"]

    def test_validation_invalid_license_exception_strict_false(self):
        result = self.licensing.validate("Apache-2.0 WITH MIT", strict=False)
        assert result.original_expression == "Apache-2.0 WITH MIT"
        assert result.normalized_expression == "Apache-2.0 WITH MIT"
        assert result.errors == []
        assert result.invalid_symbols == []


class UtilTest(TestCase):
    test_data_dir = join(dirname(__file__), "data")

    def test_build_licensing(self):
        test_license_index_location = join(self.test_data_dir, "test_license_key_index.json")
        test_license_index = get_license_index(license_index_location=test_license_index_location)
        result = build_licensing(test_license_index)

        known_symbols = set(result.known_symbols.keys())
        known_symbols_lowercase = set(result.known_symbols_lowercase.keys())
        expected_symbols = {"389-exception", "3com-microcode", "3dslicer-1.0", "aladdin-md5"}

        assert known_symbols == expected_symbols
        assert known_symbols_lowercase == {sym.lower() for sym in expected_symbols}

    def test_build_spdx_licensing(self):
        test_license_index_location = join(self.test_data_dir, "test_license_key_index.json")
        test_license_index = get_license_index(license_index_location=test_license_index_location)
        result = build_spdx_licensing(test_license_index)

        known_symbols = set(result.known_symbols.keys())
        known_symbols_lowercase = set(result.known_symbols_lowercase.keys())
        expected_symbols = {
            "389-exception",
            "LicenseRef-scancode-3com-microcode",
            "LicenseRef-scancode-3dslicer-1.0",
        }

        assert known_symbols == expected_symbols
        assert known_symbols_lowercase == {sym.lower() for sym in expected_symbols}

    def test_get_license_key_info(self):
        test_license_index_location = join(self.test_data_dir, "test_license_key_index.json")
        with open(test_license_index_location) as f:
            expected = json.load(f)
        result = get_license_index(test_license_index_location)
        assert result == expected

    def test_get_license_key_info_vendored(self):
        curr_dir = dirname(abspath(__file__))
        parent_dir = pathlib.Path(curr_dir).parent
        vendored_license_key_index_location = parent_dir.joinpath(
            "src", "license_expression", "data", "scancode-licensedb-index.json"
        )
        with open(vendored_license_key_index_location) as f:
            expected = json.load(f)
        result = get_license_index()
        assert result == expected


class CombineExpressionTest(TestCase):
    def test_combine_expressions_with_empty_input(self):
        assert combine_expressions(None) == None
        assert combine_expressions([]) == None

    def test_combine_expressions_with_regular(self):
        assert str(combine_expressions(["mit", "apache-2.0"])) == "mit AND apache-2.0"

    def test_combine_expressions_with_duplicated_elements(self):
        assert str(combine_expressions(["mit", "apache-2.0", "mit"])) == "mit AND apache-2.0"

    def test_combine_expressions_with_or_relationship(self):
        assert str(combine_expressions(["mit", "apache-2.0"], "OR")) == "mit OR apache-2.0"
