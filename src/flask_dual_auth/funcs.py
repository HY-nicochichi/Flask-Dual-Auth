from datetime import (
    datetime,
    UTC
)
from functools import wraps
from typing import Any
from collections.abc import Callable
from contextlib import contextmanager
from jwt import (
    ExpiredSignatureError,
    InvalidTokenError,
    decode,
    encode
)
from flask import (
    g,
    current_app,
    session,
    request,
    Response
)
from .ext import AuthManager
from .errors import (
    FlaskDualAuthError,
    NoValidAuthType,
    NoValidCookieSub,
    AuthorizationMissing,
    AuthorizationInvalid,
    TokenExpired,
    TokenInvalid,
    TokenDecodeFailure,
    UserNotFound
)

def login_cookie(sub: str) -> None:
    session['sub'] = sub
    session.permanent = True

def logout_cookie() -> None:
    session.pop('sub', None)

def create_token(sub: str) -> str:
    return encode(
        payload = {
            'sub': sub,
            'exp': datetime.now(UTC) + current_app.config['TOKEN_LIFETIME']
        },
        key = current_app.config['SECRET_KEY'],
        algorithm = 'HS256'
    )

def create_refresh_token(sub: str) -> str:
    refresh_token_lifetime = current_app.config.get('REFRESH_TOKEN_LIFETIME', None)
    if refresh_token_lifetime is None:
        raise FlaskDualAuthError('Flask-Dual-Auth: REFRESH_TOKEN_LIFETIME is missing')
    return encode(
        payload = {
            'sub': sub,
            'exp': datetime.now(UTC) + refresh_token_lifetime
        },
        key = current_app.config['SECRET_KEY'],
        algorithm = 'HS256'
    )

def get_token_sub(token: str) -> str:
    return decode(
        jwt = token,
        key = current_app.config['SECRET_KEY'],
        algorithms = ['HS256'],
        options = {
            'require_sub': True,
            'require_exp': True
        }
    )['sub']

def get_current_user() -> Any|None:
    return g.get('current_user', None)

@contextmanager
def token_decode_context():
    try:
        yield
    except ExpiredSignatureError:
        raise TokenExpired
    except InvalidTokenError:
        raise TokenInvalid
    except Exception:
        raise TokenDecodeFailure

def auth_required(func: Callable) -> Callable:
    @wraps(func)
    def decorated(*args, **kwargs) -> tuple[str|dict|Response, int]:
        auth_manager: AuthManager|None = current_app.extensions.get('Flask-Dual-Auth', None)
        if auth_manager is None:
            raise FlaskDualAuthError('Flask-Dual-Auth: AuthManager.init_app is not called')
        if auth_manager._user_loader is None:
            raise FlaskDualAuthError('Flask-Dual-Auth: AuthManager.user_loader is not called')
        auth_type: str|None = current_app.config['AUTHORIZATION_TYPE']
        if auth_type == 'dual':
            auth_type = request.headers.get('Authorization-Type', None)
        sub: str|None = None
        if auth_type == 'cookie':
            sub = session.get('sub', None)
            if sub is None:
                raise NoValidCookieSub
        elif auth_type == 'token':
            authorization = request.headers.get('Authorization', None)
            if authorization is None:
                raise AuthorizationMissing
            auth_split = authorization.split(' ')
            if len(auth_split) != 2 or auth_split[0] != 'Bearer' or auth_split[1] == '':
                raise AuthorizationInvalid
            token = auth_split[1]
            with token_decode_context():
                sub = get_token_sub(token)
        else:
            raise NoValidAuthType
        user: Any|None = auth_manager._user_loader(sub)
        if user is None:
            raise UserNotFound
        g.current_user = user
        return func(*args, **kwargs)
    return decorated
