===============================
license-expression
===============================

license-expression is small utility library to parse, compare, simplify and normalize
license expressions (e.g. SPDX license expressions) using boolean logic such as:
`GPL-2.0 or later WITH Classpath Exception AND MIT`.


See also for details:
https://spdx.org/sites/cpstandard/files/pages/files/spdxversion2.1.pdf#page=95&zoom=auto

license: apache-2.0

Python: 2.7 and 3.4+


Build and tests status
======================

+-------+-------------------------------------------------------------------------------+-------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------------+
|Branch |                         **Linux (Travis)**                                    |                         **MacOSX (Travis)**                                   |                         **Windows (AppVeyor)**                                                              |
+=======+===============================================================================+===============================================================================+=============================================================================================================+
|       |.. image:: https://api.travis-ci.org/nexB/license-expression.png?branch=master |.. image:: https://api.travis-ci.org/nexB/license-expression.png?branch=master |.. image:: https://ci.appveyor.com/api/projects/status/github/nexB/license-expression?svg=true               |
|Master |   :target: https://travis-ci.org/nexB/license-expression                      |   :target: https://travis-ci.org/nexB/license-expression                      |   :target: https://ci.appveyor.com/project/nexB/license-expression                                          |
|       |   :alt: Linux Master branch tests status                                      |   :alt: MacOSX Master branch tests status                                     |   :alt: Windows Master branch tests status                                                                  |
+-------+-------------------------------------------------------------------------------+-------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------------+


Source code and download
========================

* https://github.com/nexB/license-expression.git
* https://pypi.python.org/pypi/license-expression

Support
=======

Submit bugs and questions at:

* https://github.com/nexB/license-expression/issues

Description
===========
This module defines a mini language to parse, validate, simplify, normalize and
compare license expressions using a boolean logic engine.

This supports SPDX license expressions and also accepts other license naming
conventions and license identifiers aliases to resolve and normalize licenses.

Using boolean logic, license expressions can be tested for equality, containment,
equivalence and can be normalized or simplified.

The main entry point is the Licensing object.


Usage examples
==============

Parse an expression, then simplify and compare::

    >>> from license_expression import Licensing
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

An expression can be validated and normalized using a list of reference license keys
(or ids), names and aliases::

    >>> from license_expression import LicenseRef, Licensing
    >>> license_refs = [
    ...    LicenseRef('gpl-2.0', 'GPL-2.0', ['The GNU GPL 20'], False),
    ...    LicenseRef('gpl-2.0+', 'GPL-2.0+', ['The GNU GPL 20 or later'], False),
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

The cases of a license with an exception or  "or later version" are handled correctly::

    >>> expr = l.parse("The GNU GPL 20 or later with Classpath-2.0 Exception or LGPL-2.1 or later and mit2")
    >>> l.license_symbols(expr)
    [LicenseSymbol('The GNU GPL 20 or later WITH Classpath-2.0 Exception'), LicenseSymbol('LGPL-2.1 or later'), LicenseSymbol('mit2')]
    >>> expr = l.resolve(expr)
    >>> l.unresolved_keys(expr) == ['mit2']
    True
    >>> str(expr)
    'GPL-2.0+ WITH Classpath-2.0 OR (LGPL-2.1+ AND mit2)'
        
Here if we add `mit2` as an alias, the expression resolves alright::

    >>> license_refs = [
    ...    LicenseRef('gpl-2.0', 'GPL-2.0', ['The GNU GPL 20'], False),
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

    
Development
===========

* Checkout a clone from https://github.com/nexB/license-expression.git
* Then run `./configure` (or `configure.bat`) and then `source bin/activate`. This will
  install all vendored dependencies in a local virtualenv, including development deps.
* To run the tests, run `py.test -vvs`
