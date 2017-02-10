module jwt.jwt;

import std.json;
import std.base64;
import std.stdio;
import std.conv;
import std.string;
import std.datetime;
import std.exception;
import std.array : split;
import std.algorithm : count;

import jwt.algorithms;
import jwt.exceptions;

private class Component {

    abstract @property string json();

    @property string base64() {

        ubyte[] data = cast(ubyte[])this.json;

        return URLSafeBase64.encode(data);

    }

}

private class Header : Component {

public:
    JWTAlgorithm alg;
    string typ;

    this(in JWTAlgorithm alg, in string typ) {

        this.alg = alg;
        this.typ = typ;
    }

    this(in JSONValue headers) {

        try {

            this.alg = to!(JWTAlgorithm)(toUpper(headers["alg"].str()));

        } catch (Exception e) {

            throw new UnsupportedAlgorithmException(alg ~ " algorithm is not supported!");

        }

        this.typ = headers["typ"].str();

    }

    @property override string json() {

        JSONValue headers = ["alg": cast(string)this.alg, "typ": this.typ];

        return headers.toString();

    }

}

/**
* represents the claims component of a JWT
*/
private class Claims : Component {
private:
    JSONValue data;

    this(in JSONValue claims) {

        this.data = claims;

    }

public:

    this() {

        this.data = JSONValue(["iat": JSONValue(Clock.currTime.toUnixTime())]);

    }

    void set(T)(string name, T data) {
        this.data.object[name] = JSONValue(data);
    }

    /**
    * Params:
    *       name = the name of the claim
    * Returns: returns a string representation of the claim if it exists and is a string or an empty string if doesn't exist or is not a string
    */
    string get(string name) {

        try {

            return this.data[name].str();

        } catch (JSONException e) {

            return string.init;

        }

    }

    /**
    * Params:
    *       name = the name of the claim
    * Returns: an array of JSONValue
    */
    JSONValue[] getArray(string name) {

        try {

            return this.data[name].array();

        } catch (JSONException e) {

            return JSONValue.Store.array.init;

        }

    }


    /**
    * Params:
    *       name = the name of the claim
    * Returns: a JSONValue
    */
    JSONValue[string] getObject(string name) {

        try {

            return this.data[name].object();

        } catch (JSONException e) {

            return JSONValue.Store.object.init;

        }

    }

    /**
    * Params:
    *       name = the name of the claim
    * Returns: returns a long representation of the claim if it exists and is an
    *          integer or the initial value for long if doesn't exist or is not an integer
    */
    long getInt(string name) {

        try {

            return this.data[name].integer();

        } catch (JSONException e) {

            return long.init;

        }

    }

    /**
    * Params:
    *       name = the name of the claim
    * Returns: returns a double representation of the claim if it exists and is a
    *          double or the initial value for double if doesn't exist or is not a double
    */
    double getDouble(string name) {

        try {

            return this.data[name].floating();

        } catch (JSONException e) {

            return double.init;

        }

    }

    /**
    * Params:
    *       name = the name of the claim
    * Returns: returns a boolean representation of the claim if it exists and is a
    *          boolean or the initial value for bool if doesn't exist or is not a boolean
    */
    bool getBool(string name) {

        try {

            return this.data[name].type == JSON_TYPE.TRUE;

        } catch (JSONException e) {

            return bool.init;

        }

    }

    /**
    * Params:
    *       name = the name of the claim
    * Returns: returns a boolean value if the claim exists and is null or
    *          the initial value for bool it it doesn't exist or is not null
    */
    bool isNull(string name) {

        try {

            return this.data[name].isNull();

        } catch (JSONException) {

            return bool.init;

        }

    }

    @property void iss(string s) {
        this.data.object["iss"] = s;
    }


    @property string iss() {

        try {

            return this.data["iss"].str();

        } catch (JSONException e) {

            return "";

        }

    }

    @property void sub(string s) {
        this.data.object["sub"] = s;
    }

    @property string sub() {

        try {

            return this.data["sub"].str();

        } catch (JSONException e) {

            return "";

        }

    }

    @property void aud(string s) {
        this.data.object["aud"] = s;
    }

    @property string aud() {

        try {

            return this.data["aud"].str();

        } catch (JSONException e) {

            return "";

        }

    }

    @property void exp(long n) {
        this.data.object["exp"] = n;
    }

    @property long exp() {

        try {

            return this.data["exp"].integer;

        } catch (JSONException) {

            return 0;

        }

    }

    @property void nbf(long n) {
        this.data.object["nbf"] = n;
    }

    @property long nbf() {

        try {

            return this.data["nbf"].integer;

        } catch (JSONException) {

            return 0;

        }

    }

    @property void iat(long n) {
        this.data.object["iat"] = n;
    }

    @property long iat() {

        try {

            return this.data["iat"].integer;

        } catch (JSONException) {

            return 0;

        }

    }

    @property void jit(string s) {
        this.data.object["jit"] = s;
    }

    @property string jit() {

        try {

            return this.data["jit"].str();

        } catch(JSONException e) {

            return "";

        }

    }

    /**
    * gives json encoded claims
    * Returns: json encoded claims
    */
    @property override string json() {

        return this.data.toString();

    }

}

/**
* represents a token
*/
class Token {

private:
    Claims _claims;
    Header _header;

    this(Claims claims, Header header) {
        this._claims = claims;
        this._header = header;
    }

    @property string data() {
        return this.header.base64 ~ "." ~ this.claims.base64;
    }


public:

    this(in JWTAlgorithm alg, in string typ = "JWT") {

        this._claims = new Claims();

        this._header = new Header(alg, typ);

    }

    @property Claims claims() {
        return this._claims;
    }

    @property Header header() {
        return this._header;
    }

    /**
    * used to get the signature of the token
    * Parmas:
    *       secret = the secret key used to sign the token
    * Returns: the signature of the token
    */
    string signature(string secret) {

        return sign(secret, this.data, this.header.alg);

    }

    /**
    * encodes the token
    * Params:
    *       secret = the secret key used to sign the token
    *Returns: base64 representation of the token including signature
    */
    string encode(string secret) {

        if ((this.claims.exp != ulong.init && this.claims.iat != ulong.init) && this.claims.exp < this.claims.iat) {
            throw new ExpiredException("Token has already expired");
        }

        if ((this.claims.exp != ulong.init && this.claims.nbf != ulong.init) && this.claims.exp < this.claims.nbf) {
            throw new ExpiresBeforeValidException("Token will expire before it becomes valid");
        }

        return this.data ~ "." ~ this.signature(secret);

    }
    ///
    unittest {

        Token token = new Token(JWTAlgorithm.HS512);

        long now = Clock.currTime.toUnixTime();

        string secret = "super_secret";

        token.claims.exp = now - 3600;

        assertThrown!ExpiredException(token.encode(secret));

        token.claims.exp = now + 3600;

        token.claims.nbf = now + 7200;

        assertThrown!ExpiresBeforeValidException(token.encode(secret));

    }

    /**
    * overload of the encode(string secret) function to simplify encoding of token without algorithm none
    * Returns: base64 representation of the token
    */
    string encode() {
        assert(this.header.alg == JWTAlgorithm.NONE);
        return this.encode("");
    }

}

private Token decode(string encodedToken) {

    string[] tokenParts = split(encodedToken, ".");

    if(tokenParts.length != 3) {
        throw new MalformedToken("Malformed Token");
    }

    string component = tokenParts[0];

    string jsonComponent = cast(string)URLSafeBase64.decode(component);

    JSONValue parsedComponent = parseJSON(jsonComponent);

    Header header = new Header(parsedComponent);

    component = tokenParts[1];

    jsonComponent = cast(string)URLSafeBase64.decode(component);

    parsedComponent = parseJSON(jsonComponent);

    Claims claims = new Claims(parsedComponent);

    return new Token(claims, header);

}

/**
* verifies the tokens is valid, using the algorithm given instead of the alg field in the claims
* Params:
*       encodedToken = the encoded token
*       secret = the secret key used to sign the token
*       alg = the algorithm to be used to verify the token
* Returns: a decoded Token
*/
Token verify(string encodedToken, string secret, JWTAlgorithm[] algs) {

    Token token = decode(encodedToken);

    long now = Clock.currTime.toUnixTime();

    bool algorithmAllowed = false;

    foreach(index, alg; algs) {

        if(token.header.alg == alg) {
            algorithmAllowed = true;
        }

    }

    if (!algorithmAllowed) {
        throw new InvalidAlgorithmException("Algorithm " ~ token.header.alg ~ " is not in the allowed algorithms field");
    }

    string signature = split(encodedToken, ".")[2];

    if (signature != token.signature(secret)) {
        throw new InvalidSignatureException("Signature Match Failed");
    }

    if (token.header.alg == JWTAlgorithm.NONE) {
        throw new VerifyException("Algorithm set to none while secret is provided");
    }

    if (token.claims.exp != ulong.init && token.claims.exp < now) {
        throw new ExpiredException("Token has expired");
    }

    if (token.claims.nbf != ulong.init && token.claims.nbf > now) {
        throw new NotBeforeException("Token is not valid yet");
    }

    return token;

}

unittest {

    string secret = "super_secret";

    long now = Clock.currTime.toUnixTime();

    Token token = new Token(JWTAlgorithm.HS512);

    token.claims.nbf = now + (60 * 60);

    string encodedToken = token.encode(secret);

    assertThrown!NotBeforeException(verify(encodedToken, secret, [JWTAlgorithm.HS512]));

    token = new Token(JWTAlgorithm.HS512);

    token.claims.iat = now - 3600;

    token.claims.exp = now - 60;

    encodedToken = token.encode(secret);

    assertThrown!ExpiredException(verify(encodedToken, secret, [JWTAlgorithm.HS512]));

    token = new Token(JWTAlgorithm.NONE);

    encodedToken = token.encode(secret);

    assertThrown!VerifyException(verify(encodedToken, secret, [JWTAlgorithm.HS512]));

    token = new Token(JWTAlgorithm.HS512);

    encodedToken = token.encode(secret) ~ "we_are";

    assertThrown!InvalidSignatureException(verify(encodedToken, secret, [JWTAlgorithm.HS512]));

    token = new Token(JWTAlgorithm.HS512);

    encodedToken = token.encode(secret);

    assertThrown!InvalidAlgorithmException(verify(encodedToken, secret, [JWTAlgorithm.HS256, JWTAlgorithm.HS384]));

}

/**
* verifies the tokens is valid, used in case the token was signed with "none" as algorithm
* Params:
*       encodedToken = the encoded token
* Returns: a decoded Token
*/
Token verify(string encodedToken) {

    Token token = decode(encodedToken);

    long now = Clock.currTime.toUnixTime();

    if (token.claims.exp != ulong.init && token.claims.exp < now) {
        throw new ExpiredException("Token has expired");
    }

    if (token.claims.nbf != ulong.init && token.claims.nbf > now) {
        throw new NotBeforeException("Token is not valid yet");
    }

    return token;

}
///
unittest {

    long now = Clock.currTime.toUnixTime();

    Token token = new Token(JWTAlgorithm.NONE);

    token.claims.nbf = now + (60 * 60);

    string encodedToken = token.encode();

    assertThrown!NotBeforeException(verify(encodedToken));

    token = new Token(JWTAlgorithm.NONE);

    token.claims.iat = now - 3600;

    token.claims.exp = now - 60;

    encodedToken = token.encode();

    assertThrown!ExpiredException(token = verify(encodedToken));

}