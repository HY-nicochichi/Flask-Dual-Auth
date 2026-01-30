from typing import Callable, Self
from jwt import (
    ExpiredSignatureError,
    InvalidTokenError
)
from flask import (
    Flask,
    Response
)
from .errors import (
    TOKEN_EXPIRED,
    TOKEN_INVALID,
    TOKEN_DECODE_FAILURE
)

class AuthManager:
    def __init__(self, app: Flask|None = None) -> None:
        self._user_loader: Callable|None = None
        self._error_responses: dict[str, tuple[str|dict|Response, int]] = {}
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        if app.config.get('SECRET_KEY', None) is None:
            raise RuntimeError('Flask-Dual-Auth: SECRET_KEY is missing')
        app.config.setdefault('AUTHORIZATION_TYPE', 'dual')
        if app.config['AUTHORIZATION_TYPE'] not in ['cookie', 'token', 'dual']:
            raise RuntimeError('Flask-Dual-Auth: AUTHORIZATION_TYPE must be "cookie", "token", or "dual"')
        app.config.setdefault('PERMANENT_SESSION_LIFETIME', None)
        if app.config['AUTHORIZATION_TYPE'] != 'token':
            if app.config['PERMANENT_SESSION_LIFETIME'] is None:
                raise RuntimeError('Flask-Dual-Auth: PERMANENT_SESSION_LIFETIME is missing')
            app.config.setdefault('SESSION_COOKIE_HTTPONLY', True)
            app.config.setdefault('SESSION_COOKIE_SECURE', True)
            app.config.setdefault('SESSION_COOKIE_SAMESITE', 'Strict')
        if app.config['AUTHORIZATION_TYPE'] != 'cookie':
            app.config.setdefault('TOKEN_LIFETIME', app.config['PERMANENT_SESSION_LIFETIME'])
            if app.config['TOKEN_LIFETIME'] is None:
                raise RuntimeError('Flask-Dual-Auth: TOKEN_LIFETIME is missing')
        app.extensions['Flask-Dual-Auth'] = self

    def user_loader(self, func: Callable) -> None:
        self._user_loader = func

    def error_responses(self, responses: dict[str, tuple[str|dict|Response, int]]) -> None:
        self._error_responses = responses

class TokenErrorHandler:
    def __init__(self, auth_manager: AuthManager|None = None) -> None:
        if auth_manager is None:
            raise RuntimeError('Flask-Dual-Auth: TokenErrorHandler.__init__ requires auth_manager')
        self._auth_manager: AuthManager = auth_manager
        self._default_error_responses: dict[str, tuple[dict[str, str], int]] = {
            TOKEN_EXPIRED: ({'msg': 'Token has expired'}, 401),
            TOKEN_INVALID: ({'msg': 'Token is invalid'}, 401),
            TOKEN_DECODE_FAILURE: ({'msg': 'Token decoding failed'}, 500)
        }
        self.error_response: tuple[str|dict|Response, int]|None = None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: type[BaseException]|None = None, *args) -> bool:
        if exc_type is not None:
            error: str = {
                ExpiredSignatureError: TOKEN_EXPIRED,
                InvalidTokenError: TOKEN_INVALID
            }.get(exc_type, TOKEN_DECODE_FAILURE)
            self.error_response = self._auth_manager._error_responses.get(
                error, self._default_error_responses.get(error)
            )
        return True
