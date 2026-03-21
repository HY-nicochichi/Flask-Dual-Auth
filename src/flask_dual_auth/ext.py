from collections.abc import Callable
from flask import Flask
from .errors import (
    FlaskDualAuthError,
    DEFAULT_ERROR_HANDLERS
)

class AuthManager:
    def __init__(
        self,
        app: Flask|None = None,
        custom_error_handlers: dict[type[FlaskDualAuthError], Callable] = {}
    ) -> None:
        self._user_loader: Callable|None = None
        self._error_handlers: dict[type[FlaskDualAuthError], Callable] = DEFAULT_ERROR_HANDLERS.copy()
        self.custom_error_handlers(custom_error_handlers)
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        if app.config.get('SECRET_KEY', None) is None:
            raise FlaskDualAuthError('Flask-Dual-Auth: SECRET_KEY is missing')
        app.config.setdefault('AUTHORIZATION_TYPE', 'dual')
        if app.config['AUTHORIZATION_TYPE'] not in ['cookie', 'token', 'dual']:
            raise FlaskDualAuthError('Flask-Dual-Auth: AUTHORIZATION_TYPE must be "cookie", "token", or "dual"')
        app.config.setdefault('PERMANENT_SESSION_LIFETIME', None)
        if app.config['AUTHORIZATION_TYPE'] != 'token':
            if app.config['PERMANENT_SESSION_LIFETIME'] is None:
                raise FlaskDualAuthError('Flask-Dual-Auth: PERMANENT_SESSION_LIFETIME is missing')
            app.config.setdefault('SESSION_COOKIE_HTTPONLY', True)
            app.config.setdefault('SESSION_COOKIE_SECURE', True)
            app.config.setdefault('SESSION_COOKIE_SAMESITE', 'Strict')
        if app.config['AUTHORIZATION_TYPE'] != 'cookie':
            app.config.setdefault('TOKEN_LIFETIME', app.config['PERMANENT_SESSION_LIFETIME'])
            if app.config['TOKEN_LIFETIME'] is None:
                raise FlaskDualAuthError('Flask-Dual-Auth: TOKEN_LIFETIME is missing')
        for Error, handler in self._error_handlers.items():
            app.register_error_handler(Error, handler)
        app.extensions['Flask-Dual-Auth'] = self

    def user_loader(self, func: Callable) -> None:
        self._user_loader = func

    def custom_error_handlers(
        self,
        handlers: dict[type[FlaskDualAuthError], Callable] = {}
    ) -> None:
        self._error_handlers.update(handlers)
