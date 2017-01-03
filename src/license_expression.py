#
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


"""
This module defines a mini language to parse, validate, simplify, normalize and
compare license expressions using a boolean logic engine.

This supports SPDX license expressions and also accepts other license naming
conventions and license identifiers aliases to resolve and normalize licenses.

Using boolean logic, license expressions can be tested for equality, containment,
equivalence and can be normalized or simplified.

The main entry point is the Licensing object.
"""


from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function


# Python 2 and 3 support
try:
    unicode = unicode
except NameError:
    # Python 3
    str = str
    unicode = str
    bytes = bytes
    basestring = (str, bytes)
else:
    str = str
    unicode = unicode
    bytes = str
    basestring = basestring


import collections
from functools import total_ordering
import itertools
import re
import string
import sys

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


py2 = sys.version_info[0] == 2
py3 = sys.version_info[0] == 3


# append new error code to PARSE_ERRORS
PARSE_EXPRESSION_NOT_UNICODE = max(PARSE_ERRORS) + 1
PARSE_ERRORS[PARSE_EXPRESSION_NOT_UNICODE] = 'Expression string must be unicode.'


class ExpressionError(Exception):
    pass



ref_attributes = ['key', 'name', 'aliases', 'is_exception']
class LicenseRef(collections.namedtuple('LicenseRef', ref_attributes)):
    """
    A LicenseRef is used to validate and normalize the licenses found in a license
    expression. This is defined here as a namedtuple but it can be any object with
    the same attributes.

    The attributes are:

    - key: unicode string, lowercase, no spaces. Only alphanumeric ASCII, ".", "_",
      "-" or "+" characters are allowed. Must be unique in a collection of LicenseRef.

    - name: unicode string to use as the name for the representation for this license
      or exception. It can contain mixed case and spaces but leading and trailing
      spaces will be stripped. It must be unique in a collection of LicenseRef. If
      not provided it defaults to the key.

    - aliases: list of aliases (as unicode strings) for the key. Irrespective of an
      original alias value, the string is stripped from leading and trailing spaces,
      spaces are normalized to a single space, and lowercased. An alias cannot
      contain the keywords "or" "and" "not" and "with". It must be unique in a
      collection of LicenseRef.

    - is_exception: boolean set to True if this is an exception to a license, false
      otherwise.
    """
    def __new__(cls, key, name=None, aliases=tuple(), is_exception=False):
        if not name or (name and not name.strip()):
            name = key
        if not aliases:
            aliases = []
        aliases = [a for a in aliases if a and isinstance(a, basestring) and a.strip()]
        return super(LicenseRef, cls).__new__(LicenseRef, key, name, aliases, is_exception)


is_valid_key = re.compile('^[A-Za-z0-9\+\-\_\.\:]*$', re.IGNORECASE).match


def clean_and_validate_refs(license_refs):
    """
    Return a tuple of (keys, aliases, exceptions, errors) given a `license_refs` list
    of LicenseRef-like objects. Keys, names and aliases are cleaned and validated for
    uniqueness. Validation errors are returned in the list of `errors` messages.

    The returned tuple has these members:
    - keys is a mapping of a key to its name value aliases,
    - aliases is a mapping of an alias to a key,
    - exceptions is a set of keys that are exceptions.
    - errors is a list of validation error message (possibly empty if there were no errors).
    """
    keys = {}
    names = set()
    aliases = {}
    exceptions = set()

    # collections to accumulate invalid data and return error messages
    incorrect_data_structure = []
    invalid_keys = set()
    dupe_keys = set()
    dupe_names = set()
    dupe_aliases = collections.defaultdict(list)
    aliases_with_keywords = collections.defaultdict(list)

    for licref in license_refs:
        # ensure that each item has the expected attributes
        if not all(hasattr(licref, attr) for attr in ref_attributes):
            incorrect_data_structure.append(licref)
            continue

        key = licref.key
        if not is_valid_key(key):
            invalid_keys.add(key)

        key = key.strip()
        keyl = key.lower()

        # ensure keys are unique
        if keyl in keys:
            dupe_keys.add(key)

        name = licref.name
        if not name or not name.strip():
            # use the key as a default if there is no name
            name = key

        name = ' '.join(name.split())
        namel = name.lower()
        # ensure names are unique
        if namel in names:
            dupe_names.add(name)
        names.add(namel)

        keys[keyl] = name

        # always alias a key to itself, lowercased
        aliases[keyl] = keyl

        if licref.is_exception:
            exceptions.add(keyl)

        ref_aliases = [' '.join(alias.lower().strip().split()) for alias in licref.aliases]
        for alias in ref_aliases:
            # ensure that an alias cannot be confused for a sub-expression
            if any(kw in alias for kw in (' with ', ' or ', ' and ', ' not ',)):
                if not alias.endswith('or later'):
                    aliases_with_keywords[alias].append(key)

            # ensure that a possibly duplicated alias does not point to another key
            keyal = aliases.get(alias)
            if keyal and keyal != keyl:
                dupe_aliases[alias].append(key)

            aliases[alias] = keyl

    # build errors messages from invalid data
    errors = []
    for ind in sorted(incorrect_data_structure):
        errors.append('Invalid license reference object missing a key, name, aliases or exception attribute: %(ind)r.' % locals())

    for invak in sorted(invalid_keys):
        errors.append('Invalid license key. Can only contain ASCII letters and digits and ".+_-": %(invak)r.' % locals())

    for dupe in sorted(dupe_keys):
        errors.append('Invalid duplicated license key: %(dupe)r.' % locals())

    for nm in sorted(dupe_names):
        errors.append('Invalid duplicated license name: %(nm)r.' % locals())

    for dalias, dkeys in sorted(dupe_aliases.items()):
        errors.append('Invalid duplicated alias: %(dalias)r to keys: %(dkeys)r.' % locals())

    for kalias, kkeys in sorted(aliases_with_keywords.items()):
        errors.append('Invalid alias: cannot contain "WITH", "OR", "AND" or "NOT" keywords: %(kalias)r for keys: %(kkeys)r.' % locals())

    return keys, aliases, exceptions, errors




@total_ordering
class LicenseSymbol(boolean.Symbol):
    """
    A licenseSymbol represents a license as used in a license expression. A symbol
    can be a plain single license or a license "with" an exception.

    Note that a license "with an exception" is not handled as two symbols: it is
    treated as a single atomic symbol that cannot be further decomposed (but with
    an appropriate representation and way to get its underlying license keys).

    A symbol is treated as an a symbol "with an exception" if its string contains the
    "with" keyword. Therefore, do not use license aliases that contain the word "with".
    """
    get_members = re.compile(' with ').split

    # TODO: consider using two subclasses for license and exception with a common base and a factory or metaclass
    def __init__(self, obj):
        if not obj:
            raise ExpressionError('LicenseSymbol value cannot be empty: %(obj)r' % locals())

        if not isinstance(obj, unicode):
            raise ExpressionError('LicenseSymbol value must be a unicode string: %(obj)r' % locals())

        self.original_value = obj
        obj = obj.strip()

        if not obj:
            raise ExpressionError('LicenseSymbol value cannot be blank: %(original_value)r' % locals())

        # normalize spaces and lower
        obj = ' '.join(obj.split()).strip()
        objl = obj.lower()

        if objl.startswith('with ') or objl.endswith(' with'):
            raise ExpressionError(
                'LicenseSymbol value cannot start or end with a "with" keyword: %(original_value)r' % locals())

        self.license = None
        self.exception = None

        # Are we "with exception"? if yes we should have two "members": the license
        # proper and the exception, separated by a "with"
        if ' with ' in objl:
            members = self.get_members(obj)
            if len(members) != 2:
                raise ExpressionError('LicenseSymbol value cannot contain more than '
                                      'one "with" keyword: %(original_value)r' % locals())

            self.license, self.exception = members
            self.license = self.license.strip()
            self.exception = self.exception.strip()
            obj = tuple([self.license, self.exception])
        else:
            self.license = obj

        super(LicenseSymbol, self).__init__(obj)

        # These attributes are updated after resolution (e.g. a call to resolve())

        # True if the value(s) was successfully resolved
        self.is_resolved = False
        # list of unresolved licenses and/or exceptions
        self.unresolved = []
        # after resolution, this contain the names
        self.license_name = None
        self.exception_name = None
        # list of resolution errors if any
        self.resolution_errors = []

    def resolve(self, keys, aliases=None, exceptions=None):
        """
        Resolve this symbol against the `keys` and `aliases` mappings and
        the `exceptions` set. Return a list of error messages or an empty list.

        The resolved value is updated in place in self.obj on success or left
        unchanged if the resolution failed in which case self.unresolved is updated.
        self.is_resolved is set to True in call cases.

        - `keys` is a mapping (key->name).
        - `aliases` is a mapping (alias->key).
        - `exceptions` is a set of exception keys.

        Note that this method resolves only on its first call and its results are
        cached after the first call.

        - Does not resolve if `aliases` is not provided or empty.
        - if the license or exception cannot be resolved against a non empty `aliases`,
          update self.unresolved and self.resolution_errors.
        - If `aliases` and `exceptions` are provided and not
          empty, also resolves the exception if this is an symbol "with" an
          exception. Update self.unresolved if the license or exception or both
          cannot be resolved.

        Resolution of aliases and keys is based on lower cased, stripped and space-
        normalized values therefore the key of the `aliases` mapping must be
        lowercase, stripped and its spaces must be normalized.

        For example the `aliases` mapping could be:
          {'mit license': 'mit ',
           'apache software license': 'apache-2.0',
           'classpath exception': 'classpath-2.0',
           'gnu classpath exception': 'classpath-2.0', ...}

        and the `exceptions` set of key that are exceptions could be:
          set(['classpath-2.0', 'mysql-floss', ...])
        """
        if self.is_resolved:
            return self.resolution_errors

        self.is_resolved = True

        licensel = self.license.lower()
        resolved_lic = aliases.get(licensel)
        if not resolved_lic:
            self.resolution_errors.append('Unknown license: %s' % self.license)
            self.unresolved.append(self.license)
            return self.resolution_errors

        if resolved_lic in exceptions:
            self.resolution_errors.append(
                'Invalid expression: exception: %r cannot be used without a license  and a "WITH" keyword.' % self.license)
            self.unresolved.append(self.license)
            return self.resolution_errors

        lic_name = keys.get(resolved_lic)
        if not lic_name:
            self.resolution_errors.append(
                'Inconsistent license references. Name value missing for license: %s.' % self.license)
            self.unresolved.append(self.license)
            return self.resolution_errors

        # we have sucessfully resolved the license
        self.license = resolved_lic
        self.license_name = lic_name

        if not self.exception:
            self.obj = (self.license, self.exception,)
            return []

        # license with an exception
        exceptionl = self.exception.lower()
        resolved_excep = aliases.get(exceptionl)
        if not resolved_excep:
            self.resolution_errors.append('Unknown expection: %r' % self.exception)
            self.unresolved.append(self.exception)
            return self.resolution_errors

        if exceptions and resolved_excep not in exceptions:
            self.resolution_errors.append('Invalid expression: %r is not an exception.' % self.exception)
            self.unresolved.append(self.exception)
            return self.resolution_errors

        excep_name = keys.get(resolved_excep)
        if not excep_name:
            self.resolution_errors.append('Inconsistent license references. Name value missing for exception: %r.' % self.exception)
            self.unresolved.append(self.exception)
            return self.resolution_errors

        # we have sucessfully resolved the "license with exception"
        self.exception = resolved_excep
        self.exception_name = excep_name
        self.obj = (self.license, self.exception,)
        return []

    def keys(self):
        """
        Return a list of license and exceptions keys for this symbol.
        """
        if self.exception:
            return [self.license, self.exception]
        else:
            return [self.license]

    def __str__(self):
        """
        Custom representation of the symbol depending if this is an exception or
        not. The 'WITH' keyword is always uppercase.
        """
        # use the names if available (e.g. after resolution). Otherwise use plain values.
        lic = self.license_name or self.license
        if not self.exception:
            return lic
        else:
            exc = self.exception_name or self.exception
            return '%(lic)s WITH %(exc)s' % locals()

    def __repr__(self):
        cls = self.__class__.__name__
        lic = str(self)
        return '%(cls)s(%(lic)r)' % locals()


class AND(boolean.AND):
    """
    Custom representation for the AND operator to uppercase.
    """
    def __init__(self, *args):
        super(AND, self).__init__(*args)
        self.operator = ' AND '


class OR(boolean.OR):
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

    An expression can be simplified::

    >>> expr2 = l.parse(" GPL-2.0 or (mit and LGPL 2.1) or bsd Or GPL-2.0  or (mit and LGPL 2.1)")
    >>> str(expr2.simplify())
    'GPL-2.0 OR bsd OR (LGPL 2.1 AND mit)'

    Two expressions can be compared for equivalence and containment::

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

    Expressions can be built from Python expressions, using bitwise operators between
    Licensing objects::

    >>> licensing = Licensing()
    >>> AND = licensing.AND
    >>> OR = licensing.OR
    >>> LicenseSymbol = licensing.LicenseSymbol
    >>> expr1 = LicenseSymbol('GPL-2.0') | (LicenseSymbol('mit') & LicenseSymbol('LGPL 2.1'))
    >>> expr2 = licensing.parse(" GPL-2.0 or (mit and LGPL 2.1) ")
    >>> licensing.is_equivalent(expr1, expr2)
    True
    """
    def __init__(self, license_refs=tuple()):
        """
        Initialize a Licensing with an optional `license_refs` list of LicenseRef-like
        objects with the same attributes as a LicenseRef namedtuple. If provided and
        the list is invalid, raise a ValueError.
        """
        super(Licensing, self).__init__(Symbol_class=LicenseSymbol,
                                        AND_class=AND, OR_class=OR)
        self.LicenseSymbol = self.Symbol

        # These are built from the license_refs:
        # mapping of key -> name
        self.keys = {}
        # mapping of alias -> key
        self.aliases = {}
        # set of exception key
        self.exceptions = set()

        if license_refs:
            self.keys, self.aliases, self.exceptions, errors = clean_and_validate_refs(license_refs)
            if errors:
                raise ValueError('\n'.join(errors))

    def parse(self, expression, resolve=False, simplify=False):
        """
        Return a new license LicenseExpression object by parsing a license expression
        string. Check that the expression is valid and raise an Exception,
        ExpressionError or ParseError on errors.

        If `resolve` is True also attempt to resolve each license and exceptions
        against the `licenses_reference` if provided and update the license symbols
        accordingly with their resolved value.

        If `simplify` is True the return expression is simplified to form suitable
        for comparison.

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

        >>> assert expected == str(p)

        >>> ex = ' GPL-2.0 or later with classpath Exception and mit or  LPL 2.1 and mit or later '
        >>> p = L.parse(ex)
        >>> str(p)
        '(GPL-2.0 or later WITH classpath Exception AND mit) OR (LPL 2.1 AND mit or later)'
        >>> L.license_symbols(ex)
        [LicenseSymbol('GPL-2.0 or later WITH classpath Exception'), LicenseSymbol('mit'), LicenseSymbol('LPL 2.1'), LicenseSymbol('mit or later')]
        >>> keys = L.license_keys(ex)
        >>> assert keys ==['GPL-2.0 or later', 'classpath Exception', 'mit', 'LPL 2.1', 'mit or later']

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
        """
        if expression is None:
            return expression

        if isinstance(expression, basestring):
            if not expression or not expression.strip():
                return expression

            if not isinstance(expression, str):
                try:
                    expression = str(expression)
                except UnicodeDecodeError:
                    raise ParseError(error_code=PARSE_EXPRESSION_NOT_UNICODE)

            try:
                # this will raise a ParseError on errors
                expression = super(Licensing, self).parse(expression, simplify)
            except TypeError as e:
                raise ExpressionError('Invalid expression syntax.' + repr(e))

        if not isinstance(expression, LicenseExpression):
            raise ExpressionError('expression must be a string or an Expression.')

        if resolve:
            expression = self.resolve(expression)
            resolution_errors = self.resolution_errors(expression)
            if resolution_errors:
                msg = '\n'.join(resolution_errors)
                raise ExpressionError(msg)

        return expression

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
        Possibly return the expression as-is if this is not a string or an expression.
        """
        if isinstance(expression, basestring) and expression.strip():
            expression = self.parse(expression)
        if isinstance(expression, LicenseExpression) and simplify:
            expression = expression.simplify()
        return expression

    def is_equivalent(self, expression1, expression2):
        """
        Return True if both `expressions` LicenseExpression are equivalent.
        Expressions are either a string or a LicenseExpression object.
        If a string is provided, it will be parsed and simplified but not resolved.
        """
        ex1 = self.build(expression1, simplify=True)
        ex2 = self.build(expression2, simplify=True)
        if isinstance(ex1, LicenseExpression) and isinstance(ex2, LicenseExpression):
            return ex1 == ex2

    def contains(self, expression1, expression2):
        """
        Return True if expression1 contains expression2.
        Expressions are either a string or a LicenseExpression object.
        If a string is provided, it will be parsed and simplified but not resolved.
        """
        ex1 = self.build(expression1, simplify=True)
        ex2 = self.build(expression2, simplify=True)
        if isinstance(ex1, LicenseExpression) and isinstance(ex2, LicenseExpression):
            return ex2 in ex1

    def primary_license(self, expression):
        """
        Return the left-most license key (or a "key with exception") of an expression
        or None. `expression` is either a string or a LicenseExpression object. If a
        string is provided, it will be parsed but not simplified and not resolved.

        For example:
        >>> l = Licensing()
        >>> expr = " GPL-2.0 with classpath Exception and mit or LGPL 2.1 and mit or later "
        >>> l.primary_license(expr)
        'GPL-2.0 WITH classpath Exception'
        >>> expr = " GPL-2.0 or later and mit or LGPL 2.1 and mit or later "
        >>> l.primary_license(expr)
        'GPL-2.0 or later'
        >>> expr = " GPL-2.0 or later with classpath Exception and mit or LGPL 2.1 and mit or later "
        >>> l.primary_license(expr)
        'GPL-2.0 or later WITH classpath Exception'
        """
        expression = self.build(expression)
        if not isinstance(expression, LicenseExpression):
            return
        license_symbol = self.license_symbols(expression)
        if license_symbol:
            return str(license_symbol[0])

    def license_keys(self, expression):
        """
        Return a list of unique licenses keys used in an expression in the same
        order as they first appear in the expression.

        `expression` is either a string or a LicenseExpression object.
        If a string is provided, it will be parsed.

        For example:
        >>> l = Licensing()
        >>> expr = " GPL-2.0 and mit or later with blabla and mit or LGPL 2.1 and mit and mit or later "
        >>> keys = l.license_keys(expr)
        >>> assert keys == ['GPL-2.0', 'mit or later', 'blabla', 'mit', 'LGPL 2.1']
        """
        expression = self.build(expression)
        if not isinstance(expression, LicenseExpression):
            return []
        keys = list(itertools.chain.from_iterable(ls.keys() for ls in self.license_symbols(expression)))
        return unique(keys)

    def resolve(self, expression):
        """
        Return the `expression` LicenseExpression with LicenseSymbols resolved based
        on this Licensing `licenses_reference`.

        An expression can be validated and license keys resolved::

        >>> license_refs = [
        ...    LicenseRef('gpl-2.0', 'GPL-2.0', ['The GNU GPL 20'], False),
        ...    LicenseRef('lgpl-2.1', 'LGPL-2.1', ['LGPL v2.1'], False),
        ...    LicenseRef('mit', 'MIT', ['MIT license'], False)
        ... ]
        >>> l = Licensing(license_refs)
        >>> expr = l.parse("The GNU GPL 20 or LGPL-2.1 and mit")
        >>> str(expr)
        'The GNU GPL 20 OR (LGPL-2.1 AND mit)'
        >>> expr = l.resolve(expr)
        >>> str(expr)
        'GPL-2.0 OR (LGPL-2.1 AND MIT)'
        >>> expr = l.parse("The GNU GPL 20 or LGPL-2.1 and mit2")
        >>> expr = l.resolve(expr)
        >>> errors = l.resolution_errors(expr)
        >>> assert errors == [u'Unknown license: mit2'] if py2 else ['Unknown license: mit2']
        >>> str(expr)
        'GPL-2.0 OR (LGPL-2.1 AND mit2)'

        >>> license_refs = [
        ...    LicenseRef('gpl-2.0', 'GPL-2.0', ['The GNU GPL 20'], False),
        ...    LicenseRef('lgpl-2.1', 'LGPL-2.1', ['LGPL v2.1'], False),
        ...    LicenseRef('lgpl-2.1-plus', 'LGPL-2.1+', ['LGPL v2.1 or later', 'LGPL-2.1 or later'], False),
        ...    LicenseRef('mit', 'MIT', ['MIT license'], False),
        ...    LicenseRef('classpath-2.0', 'Classpath-2.0', ['Classpath-2.0 Exception'], True)
        ... ]
        >>> l = Licensing(license_refs)
        >>> expr = l.parse("The GNU GPL 20 or LGPL-2.1 and mit")
        >>> str(expr)
        'The GNU GPL 20 OR (LGPL-2.1 AND mit)'
        >>> expr = l.resolve(expr)
        >>> str(expr)
        'GPL-2.0 OR (LGPL-2.1 AND MIT)'

        A license or later or with exception is treated as a single license::

        >>> expr2 = l.parse("LGPL-2.1 or later and mit2")
        >>> l.license_symbols(expr2)
        [LicenseSymbol('LGPL-2.1 or later'), LicenseSymbol('mit2')]
        >>> str(expr2)
        'LGPL-2.1 or later AND mit2'
        >>> repr(expr2)
        "AND(LicenseSymbol('LGPL-2.1 or later'), LicenseSymbol('mit2'))"
        >>> expr2 = l.resolve(expr2)
        >>> keys = l.license_keys(expr2)
        >>> assert keys == ['lgpl-2.1-plus', 'mit2']

        >>> expr2 = l.parse("The GNU GPL 20 with Classpath-2.0 Exception or LGPL-2.1 or later and mit2")
        >>> expr2 = l.resolve(expr2)
        >>> keys = l.license_keys(expr2)
        >>> assert keys == ['gpl-2.0', 'classpath-2.0', 'lgpl-2.1-plus', 'mit2']
        >>> assert ['mit2'] == l.unresolved_keys(expr2)
        >>> errors = l.resolution_errors(expr2)
        >>> assert errors == [u'Unknown license: mit2'] if py2 else ['Unknown license: mit2']
        >>> str(expr2)
        'GPL-2.0 WITH Classpath-2.0 OR (LGPL-2.1+ AND mit2)'

        >>> expr2 = l.parse("LGPL-2.1 or later version and mit2")
        >>> l.license_symbols(expr2)
        [LicenseSymbol('LGPL-2.1 or later version'), LicenseSymbol('mit2')]
        >>> str(expr2)
        'LGPL-2.1 or later version AND mit2'

        By adding a new alias for mit, there are no errors::
        >>> license_refs = [
        ...    LicenseRef('gpl-2.0', 'GPL-2.0', ['The GNU GPL 20'], False),
        ...    LicenseRef('gpl-2.0-plus', 'GPL-2.0+', ['The GNU GPL 20 or later'], False),
        ...    LicenseRef('lgpl-2.1', 'LGPL-2.1', ['LGPL v2.1'], False),
        ...    LicenseRef('lgpl-2.1-plus', 'LGPL-2.1+', ['LGPL v2.1 or later', 'LGPL-2.1 or later'], False),
        ...    LicenseRef('mit', 'MIT', ['MIT license', 'mit2'], False),
        ...    LicenseRef('classpath-2.0', 'Classpath-2.0', ['Classpath-2.0 Exception'], True)
        ... ]
        >>> l = Licensing(license_refs)
        >>> expr = l.parse("The GNU GPL 20 with Classpath-2.0 Exception or LGPL-2.1 or later and mit2", resolve=True)
        >>> l.resolution_errors(expr)
        []
        >>> str(expr)
        'GPL-2.0 WITH Classpath-2.0 OR (LGPL-2.1+ AND MIT)'

        >>> expr = l.parse("The GNU GPL 20 or later with Classpath-2.0 Exception or LGPL-2.1 or later and mit2")
        >>> l.license_symbols(expr)
        [LicenseSymbol('The GNU GPL 20 or later WITH Classpath-2.0 Exception'), LicenseSymbol('LGPL-2.1 or later'), LicenseSymbol('mit2')]
        >>> expr = l.resolve(expr)
        >>> l.resolution_errors(expr)
        []
        >>> str(expr)
        'GPL-2.0+ WITH Classpath-2.0 OR (LGPL-2.1+ AND MIT)'
        """
        expression = self.build(expression)
        if not isinstance(expression, LicenseExpression):
            raise ExpressionError('expression argument is not a LicenseExpression object.')
        for symbol in expression.get_symbols():
            symbol.resolve(self.keys, self.aliases, self.exceptions)
        return expression

    def unresolved_keys(self, expression):
        """
        Return a list of unknown license or exception keys for an `expression` (even
        if it has not been resolved yet so this only makes sense after calling
        resolve()).

        Once resolved, you can get unresolved license and exception keys::
            >>> license_refs = [
            ...    LicenseRef('gpl-2.0', 'GPL-2.0', ['The GNU GPL 20'], False),
            ...    LicenseRef('gpl-2.0+', 'GPL-2.0 or later', ['The GNU GPL 20 or later', 'GPL-2.0 or later', 'GPL v2.0 or later'], False),
            ...    LicenseRef('lgpl-2.1', 'LGPL-2.1', ['LGPL v2.1'], False),
            ...    LicenseRef('mit', 'MIT', ['MIT license'], False)
            ... ]
            >>> l = Licensing(license_refs)
            >>> expr = l.parse("The GNU GPL 20 or LGPL-2.1 and mit")
            >>> str(expr)
            'The GNU GPL 20 OR (LGPL-2.1 AND mit)'
            >>> expr = l.resolve(expr)
            >>> l.unresolved_keys(expr)
            []
            >>> expr = l.parse('The GNU GPL 20 or LGPL-2.1 and mit2')
            >>> expr = l.resolve(expr)
            >>> assert l.unresolved_keys(expr) == ['mit2']
            >>> expr = l.parse("The GNU GPL 20 or later or (LGPL-2.1 and mit) or The GNU GPL 20 or mit 123")
            >>> expr = l.resolve(expr)
            >>> str(expr)
            'GPL-2.0 or later OR (LGPL-2.1 AND MIT) OR GPL-2.0 OR mit 123'
            >>> assert l.unresolved_keys(expr) == ['mit 123']
        """
        expression = self.build(expression)
        if not isinstance(expression, LicenseExpression):
            return []
        unresolved_keys = list(itertools.chain.from_iterable(k.unresolved for k in expression.symbols))
        return unresolved_keys

    def resolution_errors(self, expression):
        """
        Return a list of resolution errors for an expression (even if it has not been
        resolved yet so this only makes sense after calling resolve()).

        Once resolved, you can get resolution errors if any::
            >>> license_refs = [
            ...    LicenseRef('gpl-2.0', 'GPL-2.0', ['The GNU GPL 20'], False),
            ...    LicenseRef('lgpl-2.1', 'LGPL-2.1', ['LGPL v2.1'], False),
            ...    LicenseRef('mit', 'MIT', ['MIT license'], False)
            ... ]
            >>> l = Licensing(license_refs)
            >>> expr = l.parse("The GNU GPL 20 or LGPL-2.1 and mit")
            >>> str(expr)
            'The GNU GPL 20 OR (LGPL-2.1 AND mit)'
            >>> expr = l.resolve(expr)
            >>> l.resolution_errors(expr)
            []
            >>> expr = l.parse("The GNU GPL 20 or LGPL-2.1 and mit2")
            >>> expr = l.resolve(expr)
            >>> errors = l.resolution_errors(expr)
            >>> assert errors == [u'Unknown license: mit2'] if py2 else ['Unknown license: mit2']
        """
        expression = self.build(expression)
        if not isinstance(expression, LicenseExpression):
            return []
        errors = list(itertools.chain.from_iterable(k.resolution_errors for k in expression.symbols))
        return errors

    def license_symbols(self, expression):
        """
        Return a list of unique LicenseSymbol objects used in an expression in
        the same order as they first appear in the expression tree.

        `expression` is either a string or a LicenseExpression object.
        If a string is provided, it will be parsed.

        For example:
        >>> l = Licensing()
        >>> l.license_symbols("GPL-2.0 or LATER")
        [LicenseSymbol('GPL-2.0 or LATER')]

        >>> l.license_symbols(" GPL-2.0 and mit or LGPL 2.1 and mit ")
        [LicenseSymbol('GPL-2.0'), LicenseSymbol('mit'), LicenseSymbol('LGPL 2.1')]
        >>> l.license_symbols(" GPL-2.0 or LATER and mit or LGPL 2.1+ and mit with Foo exception ")
        [LicenseSymbol('GPL-2.0 or LATER'), LicenseSymbol('mit'), LicenseSymbol('LGPL 2.1+'), LicenseSymbol('mit WITH Foo exception')]
        >>> l.license_symbols("mit or LGPL 2.1+ and mit with Foo exception or GPL-2.0 or LATER ")
        [LicenseSymbol('mit'), LicenseSymbol('LGPL 2.1+'), LicenseSymbol('mit WITH Foo exception'), LicenseSymbol('GPL-2.0 or LATER')]
        >>> l.license_symbols(" GPL-2.0 or LATER with big exception and mit or LGPL 2.1+ or later and mit or later with Foo exception ")
        [LicenseSymbol('GPL-2.0 or LATER WITH big exception'), LicenseSymbol('mit'), LicenseSymbol('LGPL 2.1+ or later'), LicenseSymbol('mit or later WITH Foo exception')]
        """
        expression = self.build(expression)
        if not isinstance(expression, LicenseExpression):
            return []
        return unique(expression.get_symbols())

    def tokenize(self, expression):
        """
        Return an iterable of 3-tuple describing each token given an expression
        unicode string.

        Special handling for some special cases:
        - Treat a "+" plus as part of a license key or name.
        - Treat a trailing "or later" as part of a license key or name.
        - Does not treat "with" exception as a special case but during symbol creation.
        """
        # basic tokenization
        tokens = self._split_in_tokens(expression)
        # handle or later special cases
        tokens_or_later = self._merge_or_later(tokens)
        # merge "or later" followed by with and other cases
        tokens_contiguous = self._merge_contiguous(tokens_or_later)
        return tokens_contiguous

    def _merge_or_later(self, tokens):
        """
        Yield a modified tokens stream eventually merging XXX and "or later" tokens
        in a single symbol token.
        """
        tokens = list(tokens)
        ngram_len = 3
        if len(tokens) < ngram_len:
            for tk in tokens:
                yield tk
            return

        # check for "XXX or later" in any subsequence of three tokens and merge these
        # in a single symbol token
        token_ngrams = list(ngrams(tokens, ngram_len))
        token_ngrams_len = len(token_ngrams)

        skip_ngrams = 0
        for i, ((tt1 , tok1, p1), (tt2 , tok2, p2), (tt3 , tok3, p3)) in enumerate(token_ngrams, 1):
            # skip possible ngrams corresponding to tokens merged previously
            if skip_ngrams:
                skip_ngrams -= 1
                continue

            orlater_types = (tt1, tt2, tt3) == (boolean.TOKEN_SYMBOL, boolean.TOKEN_OR, boolean.TOKEN_SYMBOL)
            tk3ls = tok3.lower().strip()
            orlater_values = tk3ls.startswith('later ') or tk3ls == 'later'
            if orlater_types and orlater_values:
                # The t1, t2 and t3 form a construct such as "GPL 2.0 or later".
                # Therefore we re-join the three tokens and yield this as a single symbol
                new_tok = ' '.join([tok1, 'or', tok3])
                yield tt1, new_tok, p1
                # and skip the next two ngram's since we consumed them alright in our joined token
                skip_ngrams = ngram_len - 1
            else:
                # Here we have regular, not "or LATER" tokens.
                # We just reyield the first token.
                # And if this the last token we also yield the second and third tokens
                yield tt1 , tok1, p1
                if i == token_ngrams_len:
                    yield tt2 , tok2, p2
                    yield tt3 , tok3, p3

        # if the last ngram is in the form "later" "and/or" "XXX", do not munge
        # "and/or" "XXX" that were skipped otherwise
        if tt1 == boolean.TOKEN_SYMBOL and tok1.startswith('later ') or tok1 == 'later':
            yield tt2 , tok2, p2
            yield tt3 , tok3, p3

    def _merge_contiguous(self, tokens):
        """
        Yield a modified tokens stream eventually merging any contiguous symbols as a
        single symbol token.
        """
        tokens = list(tokens)
        len_tokens = len(tokens)
        if len_tokens == 1:
            for tk in tokens:
                yield tk
            return

        # check for any contiguous symbol tokens resulting from previous merges
        # and merge them in one token
        previous = None
        for token in tokens:
            if not previous:
                previous = token
                continue

            ptt , ptok, ppos = previous
            tt , tok, _pos = token

            if ptt == boolean.TOKEN_SYMBOL and tt == boolean.TOKEN_SYMBOL:
                previous = (boolean.TOKEN_SYMBOL , ' '.join([ptok, tok]), ppos,)
            else:
                yield previous
                previous = token

        if previous:
            yield previous

    def _split_in_tokens(self, expression):
        """
        Return an iterable of 3-tuple describing each token given an expression
        unicode string as (token type, token value, token position).
        Derived from the original boolean.py tokenize() method.
        """
        if not expression:
            return

        if not isinstance(expression, str):
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

            # license symbols start with a char defined as a license char
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
