<a href="https://code.dlang.org/packages/jwt" title="Go to jwt"><img src="https://img.shields.io/dub/v/jwt.svg" alt="Dub version"></a>

# JWT

A Simple D implementation of JSON Web Tokens.

# Supported Algorithms
- none
- HS256
- HS384
- HS512

# What's New
- added nbf(not before) validation.

# How To Use
## Encoding

    import jwt.jwt;
    import jwt.exceptions;
    import jwt.algorithms;
    import std.json;
    import std.datetime;

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

            Token token = verify(encodedToken, "supersecret", JWTAlgorithm.HS512);

            writeln(token.claims.getInt("id"));

        } catch (InvalidSignature e) {

            writeln("This token has been tampered with");

        } catch (NotBeforeException e) {

            writeln("Token is not valid yet");

        } catch (ExpiredException e) {

            writeln("Token has expired");

        }

    }

# Limitations

- ##### Since Phobos doesn't support RSA algorithms this library only provides HMAC signing.
- ##### Currently this library only supports primitive data types(bool, string, int, float, double, null) in claims(working to remedy the situation)

# Note
this library uses code and ideas from [jwtd][1] and [jwt-go][2]

[1]: https://github.com/olehlong/jwtd
[2]: https://github.com/dgrijalva/jwt-go
