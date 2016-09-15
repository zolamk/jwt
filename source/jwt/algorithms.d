module jwt.algorithms;

import std.digest.hmac;
import std.digest.sha;
import std.string : representation;
import std.base64;
import std.stdio;

import jwt.exceptions;

/**
* string literal used to represent signing algorithm type
*/
enum JWTAlgorithm : string {
    NONE  = "none",     // string representation of the none algorithm
    HS256 = "HS256",   // string representation of hmac algorithm with sha256
    HS384 = "HS384",  // string representation of hmac algorithm with sha348
    HS512 = "HS512"  //string representation of hmac algorithm with sha512
}

/**
* an alias for base64 encoding that is url safe and removes the '=' padding character
*/
alias URLSafeBase64 = Base64Impl!('-', '_', Base64.NoPadding);

/**
* signs the given data with the secret using the given algorithm
* Params:
*       secret = the secret used to sign the data
*       data = the data that is to be signed
*       alg = the algorithm to be used to sign the data
* Returns: signature of the data
*/
string sign(string secret, string data, JWTAlgorithm alg) {

    switch(alg) {

        case JWTAlgorithm.HS256:
            auto signature = HMAC!SHA256(secret.representation);
            signature.put(data.representation);
            return URLSafeBase64.encode(signature.finish());

        case JWTAlgorithm.HS384:
            auto signature = HMAC!SHA384(secret.representation);
            signature.put(data.representation);
            return URLSafeBase64.encode(signature.finish());

        case JWTAlgorithm.HS512:
            auto signature = HMAC!SHA512(secret.representation);
            signature.put(data.representation);
            return URLSafeBase64.encode(signature.finish());

        case JWTAlgorithm.NONE:
            return "";

        default:
            throw new UnsupportedAlgorithmException(alg ~ " algorithm is not supported!");

    }

}
///
unittest {

    string secret = "supersecret";

    string data = "an unstoppable force crashes into an unmovable body";

    string signature = sign(secret, data, JWTAlgorithm.HS512);

    assert(signature.length > 0);

    signature = sign(secret, data, JWTAlgorithm.NONE);

    assert(signature.length == 0);

}