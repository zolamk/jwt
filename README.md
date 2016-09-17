<a href="https://code.dlang.org/packages/jwt" title="Go to jwt"><img src="https://img.shields.io/dub/v/jwt.svg" alt="Dub version"></a>

# JWT

A Simple D implementation of JSON Web Tokens.

# Supported Algorithms
- none
- HS256
- HS384
- HS512

#### This library uses [semantic versioning 2.0.0][3]

# What's New
- removed `verify` function that doesn't take algorithm type, see why [here][4]
- changed `verify` function to take an array of algorithms to support multiple algorithms
- renamed `InvalidSignature` to `InvalidSignatureException`

# How To Use
## Encoding

    import jwt.jwt;
    import jwt.algorithms;

    void main() {

        Token token = new Token(JWTAlgorithm.HS512);

        token.claims.exp = Clock.currTime.toUnixTime();

        token.claims.set("id", 60119);

        string encodedToken = token.encode("supersecret");

        // work with the encoded token

    }

## Verifying

    import jwt.jwt;
    import jwt.exceptions;
    import jwt.algorithms;

    void main() {

        // get encoded token from header or ...

        try {

            Token token = verify(encodedToken, "supersecret", [JWTAlgorithm.HS512, JWTAlgorithm.HS256]);

            writeln(token.claims.getInt("id"));

        } catch (InvalidAlgorithmException e) {

            writeln("token has an invalid algorithm");

        } catch (InvalidSignatureException e) {

            writeln("This token has been tampered with");

        } catch (NotBeforeException e) {

            writeln("Token is not valid yet");

        } catch (ExpiredException e) {

            writeln("Token has expired");

        }

    }

## Encoding without signature


    import jwt.jwt;
    import jwt.algorithms;

    void main() {

        Token token = new Token(JWTAlgorithm.NONE);

        token.claims.exp = Clock.currTime.toUnixTime();

        token.claims.set("id", 60119);

        string encodedToken = token.encode();

        // work with the encoded token

    }

## Verifying without signature

    import jwt.jwt;
    import jwt.exceptions;
    import jwt.algorithms;

    void main() {

        // get encoded token from header or ...

        try {

            Token token = verify(encodedToken);

            writeln(token.claims.getInt("id"));

        } catch (NotBeforeException e) {

            writeln("Token is not valid yet");

        } catch (ExpiredException e) {

            writeln("Token has expired");

        }

    }

# Limitations

- ##### Since Phobos doesn't(hopefully yet) support RSA algorithms this library only provides HMAC signing.
- ##### Currently this library only supports primitive data types(bool, string, int, float, double, null) in claims(working to remedy the situation)

# Note
this library uses code and ideas from [jwtd][1] and [jwt-go][2]

[1]: https://github.com/olehlong/jwtd
[2]: https://github.com/dgrijalva/jwt-go
[3]: http://semver.org
[4]: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/