from collections.abc import Callable
from flask import (
    Response,
    jsonify
)

class FlaskDualAuthError(Exception):
    pass

class NoValidAuthType(FlaskDualAuthError):
    pass

class NoValidCookieSub(FlaskDualAuthError):
    pass

class AuthorizationMissing(FlaskDualAuthError):
    pass

class AuthorizationInvalid(FlaskDualAuthError):
    pass

class TokenExpired(FlaskDualAuthError):
    pass

class TokenInvalid(FlaskDualAuthError):
    pass

class TokenDecodeFailure(FlaskDualAuthError):
    pass

class UserNotFound(FlaskDualAuthError):
    pass

def no_valid_auth_type_default_handler(e: NoValidAuthType) -> tuple[Response, int]:
    return jsonify({'msg': 'Authorization-Type header is missing or invalid'}), 400

def no_valid_cookie_sub_default_handler(e: NoValidCookieSub) -> tuple[Response, int]:
    return jsonify({'msg': 'Cookie subject is missing or expired'}), 401

def authorization_missing_default_handler(e: AuthorizationMissing) -> tuple[Response, int]:
    return jsonify({'msg': 'Authorization header is missing'}), 401

def authorization_invalid_default_handler(e: AuthorizationInvalid) -> tuple[Response, int]:
    return jsonify({'msg': 'Authorization header is invalid'}), 401

def token_expired_default_handler(e: TokenExpired) -> tuple[Response, int]:
    return jsonify({'msg': 'Token has expired'}), 401

def token_invalid_default_handler(e: TokenInvalid) -> tuple[Response, int]:
    return jsonify({'msg': 'Token is invalid'}), 401

def token_decode_failure_default_handler(e: TokenDecodeFailure) -> tuple[Response, int]:
    return jsonify({'msg': 'Token decoding failed'}), 500

def user_not_found_default_handler(e: UserNotFound) -> tuple[Response, int]:
    return jsonify({'msg': 'User not found for subject'}), 404

DEFAULT_ERROR_HANDLERS: dict[type[FlaskDualAuthError], Callable] = {
    NoValidAuthType: no_valid_auth_type_default_handler,
    NoValidCookieSub: no_valid_cookie_sub_default_handler,
    AuthorizationMissing: authorization_missing_default_handler,
    AuthorizationInvalid: authorization_invalid_default_handler,
    TokenExpired: token_expired_default_handler,
    TokenInvalid: token_invalid_default_handler,
    TokenDecodeFailure: token_decode_failure_default_handler,
    UserNotFound: user_not_found_default_handler
}
