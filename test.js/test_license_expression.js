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

    it.skip('should compare equal if the same license .key', function() {
        let license_symbol0 = LicenseSymbol(key='MIT')
        let license_symbol1 = LicenseSymbol(key='MIT')

        assert.equal(license_symbol0, license_symbol1)
    })

    it('should compare not equal if different licenses', function() {
        let license_symbol0 = LicenseSymbol(key='MIT')
        let license_symbol1 = LicenseSymbol(key='GPL')

        assert.notEqual(license_symbol0, license_symbol1)
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

        assert.equal(
            license_symbol_with_exception0, license_symbol_with_exception1
        )
    })
})

describe('Licensing', function() {
    describe('tokenize', function() {
        it('should tokenize a single license', function() {
            let licensing = Licensing()

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

        it('should tokenize a single license in parenthesis', function() {
            let licensing = Licensing()

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

        it('should tokenize a single OR expression', function() {
            let licensing = Licensing()

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

        it('should tokenize a single OR expression with parenthesis', function() {
            let licensing = Licensing()

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

        it('should tokenize a single AND expression', function() {
            let licensing = Licensing()

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

        it('should tokenize a single AND expression with parenthesis', function() {
            let licensing = Licensing()

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

        it('should tokenize a double OR expression', function() {
            let licensing = Licensing()

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

        // it('should tokenize a double OR expression with parenthesis', function() {
        //     let licensing = Licensing()
        //
        //     tokens = []
        //     for (let token of licensing.tokenize('mit')) {
        //         tokens.push(token)
        //     }
        //
        //     for (let token of tokens) {
        //         console.log(token)
        //     }

            // assert.equal('mit', tokens[0][0].key)
            // assert.equal('mit', tokens[0][1])
            // assert.equal(0    , tokens[0][2])
            //
            // assert.equal(TOKEN_OR, tokens[1][0])
            // assert.equal('or'    , tokens[1][1])
            // assert.equal(4       , tokens[1][2])
            //
            // assert.equal('gpl', tokens[2][0].key)
            // assert.equal('gpl', tokens[2][1])
            // assert.equal(7    , tokens[2][2])
            //
            // assert.equal(TOKEN_OR, tokens[3][0])
            // assert.equal('or'    , tokens[3][1])
            // assert.equal(11      , tokens[3][2])
            //
            // assert.equal('apache', tokens[4][0].key)
            // assert.equal('apache', tokens[4][1])
            // assert.equal(14      , tokens[4][2])
        // })

        it('should tokenize a double AND expression', function() {
            let licensing = Licensing()

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
    })

    describe('parse', function() {
        it('should parse a single license', function() {
            let licensing = Licensing()

            assert.equal('MIT', licensing.parse('MIT').toString())
        })

        it('should parse a bracketed license', function() {
            let licensing = Licensing()

            assert.equal('MIT', licensing.parse('(MIT)').toString())
        })

        it.skip('should parse an "OR" expression', function() {
            let licensing = Licensing()

            let expression = licensing.parse('MIT or GPL')

            assert.ok(expression instanceof license_expression.OR)
        })
    })
})
