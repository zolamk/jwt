module jwt.exceptions;

/**
* thrown when there are issues with token verification
*/
class VerifyException : Exception {
    this(string s) {
        super(s);
    }
}

/**
* thrown when attempting to encode or decode a token with an unsupported algorithm
*/
class UnsupportedAlgorithmException : Exception {
    this(string s) {
        super(s);
    }
}

/**
* thrown when there are issues with the token
*/
class InvalidTokenException : VerifyException {
    this(string s) {
        super(s);
    }
}

/**
* thrown when the tokens signature doesn't match the data signature
*/
class InvalidSignatureException : VerifyException {
    this(string s) {
        super(s);
    }
}

/**
* thrown when the algorithm used to sign the token is invalid
*/
class InvalidAlgorithmException : VerifyException {
    this(string s) {
        super(s);
    }
}

/**
* thrown when the tokens is expired
*/
class ExpiredException : VerifyException {
    this(string s) {
        super(s);
    }
}

/**
* thrown when the token is not valid yet
* or in other words when the nbf claim time is before the current time
*/
class NotBeforeException : VerifyException {
    this(string s) {
        super(s);
    }
}

/**
* thrown when the token has an incorrect format
*/
class MalformedToken : InvalidTokenException {
    this(string s) {
        super(s);
    }
}

/**
* thrown when the tokens will expire before it becomes valid
* usually when the nbf claim is greater than the exp claim
*/
class ExpiresBeforeValidException : Exception {
    this(string s) {
        super(s);
    }
}