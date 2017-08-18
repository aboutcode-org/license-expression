let assert = require('assert')

let license_expression = require('../src/license_expression.js/__javascript__/__init__.js')

// Transcrypt uses '__init__.py' to derive the name of the top-level object
// If you want it to be called 'license_expression', rename '__init__.py' file
license_expression = license_expression.__init__

let Function = license_expression.Function
let Licensing = license_expression.Licensing

let LicenseSymbol = license_expression.LicenseSymbol
let LicenseWithExceptionSymbol = license_expression.LicenseWithExceptionSymbol

let TOKEN_OR = license_expression.TOKEN_OR
let TOKEN_AND = license_expression.TOKEN_AND
let TOKEN_LPAR = license_expression.TOKEN_LPAR
let TOKEN_RPAR = license_expression.TOKEN_RPAR

 describe('LicenseSymbol', function() {
    it('should compare equal to itself', function() {
        let license_symbol = LicenseSymbol(key='MIT')

        assert.ok(license_symbol == license_symbol)
        assert.ok(license_symbol === license_symbol)

        assert.equal(license_symbol, license_symbol)
        assert.deepEqual(license_symbol, license_symbol)
    })

    it('should have a .key property with the name of the license', function() {
        let license_symbol = LicenseSymbol(key='MIT')

        assert.ok(license_symbol.key)
        assert.equal('MIT', license_symbol.key)
    })

    it('should support license aliases (one)', function() {
        let license_symbol = LicenseSymbol(key='MIT', aliases=['MIT license'])

        assert.ok(license_symbol.aliases)
        assert.equal('MIT license', license_symbol.aliases)
    })

    it('should support license aliases (two)', function() {
        let license_symbol = LicenseSymbol(
            key='MIT', aliases=['MIT license', "Tim's license"]
        )

        assert.ok(license_symbol.aliases)
        assert.ok(license_symbol.aliases.includes('MIT license'))
        assert.ok(license_symbol.aliases.includes("Tim's license"))
        assert.equal(false, license_symbol.aliases.includes('Not here'))
    })

    it('should support a license with is_exception being false', function() {
        let license_symbol = LicenseSymbol(key='MIT')

        assert.equal(false, license_symbol.is_exception)
    })

    it.skip('should support a license with is_exception being true', function() {
        let license_symbol = LicenseSymbol(key='MIT', is_exception=true)

        assert.ok(license_symbol.is_exception)
    })

    it('should compare equal if the same license .key', function() {
        let license_symbol0 = LicenseSymbol(key='MIT')
        let license_symbol1 = LicenseSymbol(key='MIT')

        assert.ok(license_symbol0.__eq__(license_symbol1))
    })

    it('should compare not equal if different licenses', function() {
        let license_symbol0 = LicenseSymbol(key='MIT')
        let license_symbol1 = LicenseSymbol(key='GPL')

        assert.ok(!license_symbol0.__eq__(license_symbol1))
    })
})

describe('LicenseWithExceptionSymbol', function() {
    it.skip('should throw if no arguments', function() {
        let license_symbol_with_exception = LicenseWithExceptionSymbol()
    })

    it.skip('should support two LicenseSymbol-like arguments', function() {
        let license_symbol0 = LicenseSymbol(key='MIT', is_exeption=true)
        let license_symbol1 = LicenseSymbol(key='GPL')

        let license_symbol_with_exception = LicenseWithExceptionSymbol(
            license_symbol = license_symbol0, exception_symbol = license_symbol1
        )
    })

    it.skip('should compare equal if the same license .key', function() {
        let license_symbol0 = LicenseSymbol(key='MIT', is_exeption=true)
        let license_symbol1 = LicenseSymbol(key='GPL')

        let license_symbol_with_exception0 = LicenseWithExceptionSymbol(
            license_symbol = license_symbol0, exception_symbol = license_symbol1
        )

        let license_symbol_with_exception1 = LicenseWithExceptionSymbol(
            license_symbol = license_symbol0, exception_symbol = license_symbol1
        )

        assert.ok(
            license_symbol_with_exception0.__eq__(license_symbol_with_exception1)
        )
    })
})

describe('Licensing', function() {
    describe('tokenize', function() {
        let licensing

        beforeEach(function() {
            licensing = Licensing()
        })

        it('should tokenize a single license', function() {
            tokens = []
            for (let token of licensing.tokenize('MIT')) {
                tokens.push(token)
            }

            assert.ok(tokens.length === 1)
            assert.ok(tokens[0].length === 3)

            // token itself, token string and token position
            let [tok, str, pos] = tokens[0]

            assert.equal('MIT', tok.key)
            assert.equal('MIT', str)
            assert.equal(0    , pos)
        })

        it('should tokenize a single OR expression', function() {
            tokens = []
            for (let token of licensing.tokenize('mit or gpl')) {
                tokens.push(token)
            }

            assert.ok(tokens.length === 3)
            for (let token of tokens) {
                assert.ok(token.length === 3)
            }

            assert.equal('mit', tokens[0][0].key)
            assert.equal('mit', tokens[0][1])
            assert.equal(0    , tokens[0][2])

            assert.equal(TOKEN_OR, tokens[1][0])
            assert.equal('or'    , tokens[1][1])
            assert.equal(4       , tokens[1][2])

            assert.equal('gpl', tokens[2][0].key)
            assert.equal('gpl', tokens[2][1])
            assert.equal(7    , tokens[2][2])
        })

        it('should tokenize a double OR expression', function() {
            tokens = []
            for (let token of licensing.tokenize('mit or gpl or apache')) {
                tokens.push(token)
            }

            assert.ok(tokens.length === 5)
            for (let token of tokens) {
                assert.ok(token.length === 3)
            }

            assert.equal('mit', tokens[0][0].key)
            assert.equal('mit', tokens[0][1])
            assert.equal(0    , tokens[0][2])

            assert.equal(TOKEN_OR, tokens[1][0])
            assert.equal('or'    , tokens[1][1])
            assert.equal(4       , tokens[1][2])

            assert.equal('gpl', tokens[2][0].key)
            assert.equal('gpl', tokens[2][1])
            assert.equal(7    , tokens[2][2])

            assert.equal(TOKEN_OR, tokens[3][0])
            assert.equal('or'    , tokens[3][1])
            assert.equal(11      , tokens[3][2])

            assert.equal('apache', tokens[4][0].key)
            assert.equal('apache', tokens[4][1])
            assert.equal(14      , tokens[4][2])
        })

        it('should tokenize a single AND expression', function() {
            tokens = []
            for (let token of licensing.tokenize('mit and gpl')) {
                tokens.push(token)
            }

            assert.ok(tokens.length === 3)
            for (let token of tokens) {
                assert.ok(token.length === 3)
            }

            assert.equal('mit', tokens[0][0].key)
            assert.equal('mit', tokens[0][1])
            assert.equal(0    , tokens[0][2])

            assert.equal(TOKEN_AND, tokens[1][0])
            assert.equal('and'    , tokens[1][1])
            assert.equal(4       , tokens[1][2])

            assert.equal('gpl', tokens[2][0].key)
            assert.equal('gpl', tokens[2][1])
            assert.equal(8    , tokens[2][2])
        })

        it('should tokenize a double AND expression', function() {
            tokens = []
            for (let token of licensing.tokenize('mit and gpl and apache')) {
                tokens.push(token)
            }

            assert.ok(tokens.length === 5)
            for (let token of tokens) {
                assert.ok(token.length === 3)
            }

            assert.equal('mit', tokens[0][0].key)
            assert.equal('mit', tokens[0][1])
            assert.equal(0    , tokens[0][2])

            assert.equal(TOKEN_AND, tokens[1][0])
            assert.equal('and'    , tokens[1][1])
            assert.equal(4        , tokens[1][2])

            assert.equal('gpl', tokens[2][0].key)
            assert.equal('gpl', tokens[2][1])
            assert.equal(8    , tokens[2][2])

            assert.equal(TOKEN_AND, tokens[3][0])
            assert.equal('and'    , tokens[3][1])
            assert.equal(12       , tokens[3][2])

            assert.equal('apache', tokens[4][0].key)
            assert.equal('apache', tokens[4][1])
            assert.equal(16      , tokens[4][2])
        })

        it('should tokenize a single license with parenthesis', function() {
            tokens = []
            for (let token of licensing.tokenize('(MIT)')) {
                tokens.push(token)
            }

            assert.ok(tokens.length === 3)
            for (let token of tokens) {
                assert.ok(token.length === 3)
            }

            assert.equal(TOKEN_LPAR, tokens[0][0])
            assert.equal('('       , tokens[0][1])
            assert.equal(0         , tokens[0][2])

            assert.equal('MIT', tokens[1][0].key)
            assert.equal('MIT', tokens[1][1])
            assert.equal(1    , tokens[1][2])

            assert.equal(TOKEN_RPAR, tokens[2][0])
            assert.equal(')'       , tokens[2][1])
            assert.equal(4         , tokens[2][2])
        })

        it('should tokenize a single OR expression with parenthesis', function() {
            tokens = []
            for (let token of licensing.tokenize('mit or ( gpl )')) {
                tokens.push(token)
            }

            assert.ok(tokens.length === 5)
            for (let token of tokens) {
                assert.ok(token.length === 3)
            }

            assert.equal('mit', tokens[0][0].key)
            assert.equal('mit', tokens[0][1])
            assert.equal(0    , tokens[0][2])

            assert.equal(TOKEN_OR, tokens[1][0])
            assert.equal('or'    , tokens[1][1])
            assert.equal(4       , tokens[1][2])

            assert.equal(TOKEN_LPAR, tokens[2][0])
            assert.equal('('       , tokens[2][1])
            assert.equal(7         , tokens[2][2])

            assert.equal('gpl', tokens[3][0].key)
            assert.equal('gpl', tokens[3][1])
            assert.equal(9    , tokens[3][2])

            assert.equal(TOKEN_RPAR, tokens[4][0])
            assert.equal(')'       , tokens[4][1])
            assert.equal(13        , tokens[4][2])
        })

        it('should tokenize a double OR expression with parenthesis', function() {
            tokens = []
            for (let token of licensing.tokenize('mit or (gpl or apache)')) {
                tokens.push(token)
            }

            assert.ok(tokens.length === 7)
            for (let token of tokens) {
                assert.ok(token.length === 3)
            }

            assert.equal('mit', tokens[0][0].key)
            assert.equal('mit', tokens[0][1])
            assert.equal(0    , tokens[0][2])

            assert.equal(TOKEN_OR, tokens[1][0])
            assert.equal('or'    , tokens[1][1])
            assert.equal(4       , tokens[1][2])

            assert.equal(TOKEN_LPAR, tokens[2][0])
            assert.equal('('       , tokens[2][1])
            assert.equal(7         , tokens[2][2])

            assert.equal('gpl', tokens[3][0].key)
            assert.equal('gpl', tokens[3][1])
            assert.equal(8    , tokens[3][2])

            assert.equal(TOKEN_OR, tokens[4][0])
            assert.equal('or'    , tokens[4][1])
            assert.equal(12      , tokens[4][2])

            assert.equal('apache', tokens[5][0].key)
            assert.equal('apache', tokens[5][1])
            assert.equal(15      , tokens[5][2])

            assert.equal(TOKEN_RPAR, tokens[6][0])
            assert.equal(')'       , tokens[6][1])
            assert.equal(21        , tokens[6][2])
        })

        it('should tokenize a single AND expression with parenthesis', function() {
            tokens = []
            for (let token of licensing.tokenize('( mit) and gpl')) {
                tokens.push(token)
            }

            assert.ok(tokens.length === 5)
            for (let token of tokens) {
                assert.ok(token.length === 3)
            }

            assert.equal(TOKEN_LPAR, tokens[0][0])
            assert.equal('('       , tokens[0][1])
            assert.equal(0         , tokens[0][2])

            assert.equal('mit', tokens[1][0].key)
            assert.equal('mit', tokens[1][1])
            assert.equal(2    , tokens[1][2])

            assert.equal(TOKEN_RPAR, tokens[2][0])
            assert.equal(')'       , tokens[2][1])
            assert.equal(5         , tokens[2][2])

            assert.equal(TOKEN_AND, tokens[3][0])
            assert.equal('and'    , tokens[3][1])
            assert.equal(7        , tokens[3][2])

            assert.equal('gpl', tokens[4][0].key)
            assert.equal('gpl', tokens[4][1])
            assert.equal(11   , tokens[4][2])
        })

        it('should tokenize a double AND expression with parenthsis', function() {
            tokens = []
            for (let token of licensing.tokenize('( mit and gpl ) and apache')) {
                tokens.push(token)
            }

            assert.ok(tokens.length === 7)
            for (let token of tokens) {
                assert.ok(token.length === 3)
            }

            assert.equal(TOKEN_LPAR, tokens[0][0])
            assert.equal('('       , tokens[0][1])
            assert.equal(0         , tokens[0][2])

            assert.equal('mit', tokens[1][0].key)
            assert.equal('mit', tokens[1][1])
            assert.equal(2    , tokens[1][2])

            assert.equal(TOKEN_AND, tokens[2][0])
            assert.equal('and'    , tokens[2][1])
            assert.equal(6        , tokens[2][2])

            assert.equal('gpl', tokens[3][0].key)
            assert.equal('gpl', tokens[3][1])
            assert.equal(10    , tokens[3][2])

            assert.equal(TOKEN_RPAR, tokens[4][0])
            assert.equal(')'       , tokens[4][1])
            assert.equal(14        , tokens[4][2])

            assert.equal(TOKEN_AND, tokens[5][0])
            assert.equal('and'    , tokens[5][1])
            assert.equal(16       , tokens[5][2])

            assert.equal('apache', tokens[6][0].key)
            assert.equal('apache', tokens[6][1])
            assert.equal(20      , tokens[6][2])
        })

        it('should tokenize a mixed OR-AND expression', function() {
            let tokens = []
            for (let token of licensing.tokenize('mit or (bsd and bsd)')) {
                tokens.push(token)
            }

            assert.ok(tokens.length === 7)
            for (let token of tokens) {
                assert.ok(token.length === 3)
            }

            assert.equal('mit', tokens[0][0].key)
            assert.equal('mit', tokens[0][1])
            assert.equal(0    , tokens[0][2])

            assert.equal(TOKEN_OR, tokens[1][0])
            assert.equal('or'    , tokens[1][1])
            assert.equal(4       , tokens[1][2])

            assert.equal(TOKEN_LPAR, tokens[2][0])
            assert.equal('('       , tokens[2][1])
            assert.equal(7         , tokens[2][2])

            assert.equal('bsd', tokens[3][0].key)
            assert.equal('bsd', tokens[3][1])
            assert.equal(8    , tokens[3][2])

            assert.equal(TOKEN_AND, tokens[4][0])
            assert.equal('and'    , tokens[4][1])
            assert.equal(12       , tokens[4][2])

            assert.equal('bsd', tokens[5][0].key)
            assert.equal('bsd', tokens[5][1])
            assert.equal(16   , tokens[5][2])

            assert.equal(TOKEN_RPAR, tokens[6][0])
            assert.equal(')'       , tokens[6][1])
            assert.equal(19        , tokens[6][2])
        })

        it.skip('should tokenize gpl with classpath (an exception)', function() {
            let tokens = []
            for (let token of licensing.tokenize('gpl with classpath')) {
                tokens.push(token)
            }
        })
    })

    describe('tokenize with symbols', function() {
        let gpl_20, gpl_20_plus

        beforeEach(function() {
            gpl_20 = LicenseSymbol('GPL-2.0', ['The GNU GPL 20'])
            gpl_20_plus = LicenseSymbol(
                'gpl-2.0+', [
                    'The GNU GPL 20 or later'
                    , 'GPL-2.0 or later'
                    , 'GPL v2.0 or later'
                ]
            )
        })

        describe('should work with one predefined symbol (as a string)', function () {
            let licensing, tokens
            let expressions = ['mit', 'gpl-2.0']
            let operations = [' OR ', ' AND ', ' or ', ' and ']
            let identifiers = [TOKEN_OR, TOKEN_AND, TOKEN_OR, TOKEN_AND]

            beforeEach(function() {
                tokens = []
                licensing = Licensing(['gpl-2.0'])
            })

            for (let expression of expressions) {
                it('should tokenize a single license: ' + expression, function() {
                    for (let token of licensing.tokenize(expression)) {
                        tokens.push(token)
                    }

                    assert.equal(1, tokens.length)
                    for (let token of tokens) {
                        assert.equal(3, token.length)
                    }

                    assert.equal(expression, tokens[0][0].key)
                    assert.equal(expression, tokens[0][1])
                    assert.equal(0         , tokens[0][2])
                })
            }

            operations.forEach((operation, i) => {
                let identifier = identifiers[i]
                let expression = expressions[0] + operation + expressions[1]

                it('should tokenize a simple expression: ' + expression, function() {
                    for (let token of licensing.tokenize(expression)) {
                        tokens.push(token)
                    }

                    assert.equal(3, tokens.length)
                    for (let token of tokens) {
                        assert.equal(3, token.length)
                    }

                    let lft = expressions[0], rgt = expressions[1]

                    assert.equal(lft, tokens[0][0].key)
                    assert.equal(lft, tokens[0][1])
                    assert.equal(0             , tokens[0][2])

                    assert.equal(identifier, tokens[1][0])
                    assert.equal(operation , tokens[1][1])
                    assert.equal(lft.length, tokens[1][2])

                    assert.equal(rgt                          , tokens[2][0].key)
                    assert.equal(rgt                          , tokens[2][1])
                    assert.equal(lft.length + operation.length, tokens[2][2])
                })
            })
        })

        describe('should work with one predefined symbol (as a LicenseSymbol)', function() {
            let licensing, tokens
            let licenses = ['mit', 'gpl-2.0', 'The GNU GPL 20']
            let expected = ['mit', 'GPL-2.0', 'GPL-2.0']
            let operations = [' OR ', ' AND ', ' or ', ' and ']
            let identifiers = [TOKEN_OR, TOKEN_AND, TOKEN_OR, TOKEN_AND]

            beforeEach(function() {
                tokens = [], licensing = Licensing([gpl_20])
            })

            licenses.forEach((license, i) => {
                it('should tokenize a single license: ' + license, function() {
                    for (let token of licensing.tokenize(license)) {
                        tokens.push(token)
                    }

                    assert.equal(1, tokens.length)
                    for (let token of tokens) {
                        assert.equal(3, token.length)
                    }

                    assert.equal(expected[i], tokens[0][0].key)
                    assert.equal(license    , tokens[0][1])
                    assert.equal(0          , tokens[0][2])
                })
            })

            for (let i = 0; i != licenses.length; ++i) {
                for (let j = i + 1; j != licenses.length; ++j) {
                    operations.forEach((operation, k) => {
                        let expression = licenses[i] + operation + licenses[j]

                        it('should tokenize a simple expression: ' + expression, function() {
                            for (let token of licensing.tokenize(expression)) {
                                tokens.push(token)
                            }

                            assert(3, tokens.length)
                            for (let token of tokens) {
                                assert(3, token.length)
                            }

                            assert(expected[i], tokens[0][0].key)
                            assert(licenses[i], tokens[0][1])

                            assert(identifiers[k], tokens[1][0])
                            assert(operation     , tokens[1][1])

                            assert(expected[j], tokens[2][0].key)
                            assert(licenses[j], tokens[2][1])
                        })
                    })
                }
            }
        })

        describe('should work with several predefined symbols', function() {
            let licensing, tokens
            let operations = [' OR ', ' AND ', ' or ', ' and ']
            let identifiers = [TOKEN_OR, TOKEN_AND, TOKEN_OR, TOKEN_AND]

            beforeEach(function() {
                tokens = []
                licensing = Licensing([gpl_20, gpl_20_plus])
            })

            operations.forEach((operation, i) => {
                let expression = 'gpl-2.0' + operation + 'gpl-2.0+'
                it('should tokenize a simple expression: ' + expression, function() {
                    for (let token of licensing.tokenize(expression)) {
                        tokens.push(token)
                    }

                    assert(3, tokens.length)
                    assert(gpl_20.key     , tokens[0][0].key)
                    assert(identifiers[i] , tokens[1][0])
                    assert(gpl_20_plus.key, tokens[2][0].key)
                })
            })

            it('should tokenize a mixed OR-AND with parenthesis', function() {
                let expression = '(gpl-2.0 or gpl-2.0) and mit'

                for (let token of licensing.tokenize(expression)) {
                    tokens.push(token)
                }

                assert(7, tokens.length)
                assert(TOKEN_LPAR     , tokens[0][0])
                assert(gpl_20.key     , tokens[1][0].key)
                assert(TOKEN_OR       , tokens[2][0])
                assert(gpl_20_plus.key, tokens[3][0].key)
                assert(TOKEN_RPAR     , tokens[4][0])
                assert(TOKEN_AND      , tokens[5][0])
                assert('mit'          , tokens[6][0].key)
            })
        })
    })

    describe('parse', function() {
        let licensing;

        beforeEach(function() {
            licensing = Licensing()
        })

        it('should parse an empty string', function() {
            assert.equal(undefined, licensing.parse(''))
        })

        it('should parse a single license', function() {
            assert.equal('MIT', licensing.parse('MIT').toString())
        })

        it('should parse a single OR expression', function() {
            let expression = licensing.parse('MIT or GPL')

            assert.ok(expression.__name__ === 'OR')

            assert.ok(expression.args.length === 2)
            assert.ok(expression.args[0].key === 'MIT')
            assert.ok(expression.args[1].key === 'GPL')
        })

        it('should parse a double OR expression', function() {
            let expression = licensing.parse('mit or bsd or gpl')

            assert.ok(expression.__name__ === 'OR')

            assert.ok(expression.args.length === 3)
            assert.ok(expression.args[0].key === 'mit')
            assert.ok(expression.args[1].key === 'bsd')
            assert.ok(expression.args[2].key === 'gpl')
        })

        it('should parse a single AND expression', function() {
            let expression = licensing.parse('MIT and GPL')

            assert.ok(expression.__name__ === 'AND')

            assert.ok(expression.args.length === 2)
            assert.ok(expression.args[0].key === 'MIT')
            assert.ok(expression.args[1].key === 'GPL')
        })

        it('should parse a double AND expression', function() {
            let expression = licensing.parse('mit and bsd and gpl')

            assert.ok(expression.__name__ === 'AND')

            assert.ok(expression.args.length === 3)
            assert.ok(expression.args[0].key === 'mit')
            assert.ok(expression.args[1].key === 'bsd')
            assert.ok(expression.args[2].key === 'gpl')
        })

        it('should parse a single license with parenthesis', function() {
            assert.equal('MIT', licensing.parse('(MIT)').toString())
        })

        it('should parse a single OR expression with parenthesis', function() {
            let expression = licensing.parse('(MIT)')

            assert.ok(expression.key === 'MIT')
        })

        it('should parse a double OR expression with parenthesis', function() {
            let expression = licensing.parse('(MIT or GPL) or BSD')

            assert.ok(expression.__name__ === 'OR')

            assert.ok(expression.args.length === 2)
            assert.ok(expression.args[0].__name__ === 'OR')
            assert.ok(expression.args[1].key === 'BSD')

            expression = expression.args[0]
            assert.ok(expression.args.length === 2)
            assert.ok(expression.args[0].key === 'MIT')
            assert.ok(expression.args[1].key === 'GPL')
        })

        it('should parse a single AND expression with parenthesis', function() {
            let expression = licensing.parse('MIT and (GPL)')

            assert.ok(expression.__name__ === 'AND')

            assert.ok(expression.args.length === 2)
            assert.ok(expression.args[0].key === 'MIT')
            assert.ok(expression.args[1].key === 'GPL')
        })

        it('should parse a double AND expression with parenthesis', function() {
            let expression = licensing.parse('mit and (gpl and bsd)')

            assert.ok(expression.__name__ === 'AND')

            assert.ok(expression.args.length === 2)
            assert.ok(expression.args[0].key === 'mit')
            assert.ok(expression.args[1].__name__ === 'AND')

            expression = expression.args[1]
            assert.ok(expression.args.length === 2)
            assert.ok(expression.args[0].key === 'gpl')
            assert.ok(expression.args[1].key === 'bsd')
        })

        it('should parse a mixed OR-AND expression', function() {
            let expression = licensing.parse('mit or (bsd and bsd)')

            assert.ok(expression.__name__ === 'OR')

            assert.ok(expression.args.length === 2)
            assert.ok(expression.args[0].key === 'mit')
            assert.ok(expression.args[1].__name__ === 'AND')

            expression = expression.args[1]
            assert.ok(expression.args.length === 2)
            assert.ok(expression.args[0].key === 'bsd')
            assert.ok(expression.args[1].key === 'bsd')
        })
    })

    describe('parse with symbols', function() {
        let gpl_20, gpl_20_plus

        beforeEach(function() {
            gpl_20 = LicenseSymbol('GPL-2.0', ['The GNU GPL 20'])
            gpl_20_plus = LicenseSymbol(
                'gpl-2.0+', [
                    'The GNU GPL 20 or later'
                    , 'GPL-2.0 or later'
                    , 'GPL v2.0 or later'
                ]
            )
        })

        it('should work with predefined symbols (one)', function() {
            let licensing = Licensing(['gpl-2.0'])

            let expression = licensing.parse('gpl-2.0')

            assert.equal('gpl-2.0', expression.key)
        })
    })
})
