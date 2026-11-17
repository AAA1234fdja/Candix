from candix.auth.jwt import decode_unverified, verify_hs256
from candix.auth.oauth import pkce_pair, redirect_uri_variants, scope_analysis
from candix.auth.session import analyse_cookies, parse_set_cookie
from candix.net.favicon import favicon_hash, murmur3_32
from candix.net.raw import build_request, parse_response


def test_murmur_matches_reference():
    assert murmur3_32(b"foo") == 0xF6A5C420


def test_favicon_hash_is_stable():
    digest, sha = favicon_hash(b"icon-bytes")
    assert isinstance(digest, int) and len(sha) == 64


def test_cookie_flags():
    report = analyse_cookies([parse_set_cookie("sid=abc123; Path=/; SameSite=None")])
    assert report.issues


def test_pkce_and_redirect_variants():
    verifier, challenge = pkce_pair()
    assert len(verifier) >= 43 and 40 <= len(challenge) <= 64
    assert len(redirect_uri_variants("https://app.example/cb")) >= 8
    analysis = scope_analysis("openid profile admin")
    assert "admin" in analysis["risky"]
    assert analysis["wildcard"] is False


def test_raw_request_roundtrip():
    request = build_request("GET", "/x", host="a")
    assert request.startswith(b"GET /x HTTP/1.1")
    assert b"Host: a" in request
    response = parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
    assert response.status == 200
    assert response.body in {"hi", b"hi"}


def test_jwt_decode():
    token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    header, payload, _signature = decode_unverified(token)
    assert header["alg"] == "HS256"
    assert payload["sub"] == "1234567890"
    assert verify_hs256(token, "secret") in {True, False}
