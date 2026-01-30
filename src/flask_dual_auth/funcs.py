from datetime import (
    datetime,
    UTC
)
from functools import wraps
from typing import (
    Any,
    Callable
)
from jwt import (
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
from .models import (
    AuthManager,
    TokenErrorHandler
)
from .errors import (
    NO_VALID_AUTH_TYPE,
    NO_VALID_COOKIE_SUB,
    AUTHORIZATION_MISSING,
    AUTHORIZATION_INVALID,
    USER_NOT_FOUND
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
        raise RuntimeError('Flask-Dual-Auth: REFRESH_TOKEN_LIFETIME is missing')
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

def get_auth_manager() -> AuthManager:
    auth_manager: AuthManager|None = current_app.extensions.get('Flask-Dual-Auth', None)
    if auth_manager is None:
        raise RuntimeError('Flask-Dual-Auth: AuthManager.init_app is not called')
    if auth_manager._user_loader is None:
        raise RuntimeError('Flask-Dual-Auth: user_loader is not called')
    return auth_manager

def auth_required(func: Callable) -> Callable:
    @wraps(func)
    def decorated(*args, **kwargs) -> tuple[str|dict|Response, int]:
        auth_manager: AuthManager = get_auth_manager()
        auth_type: str|None = current_app.config['AUTHORIZATION_TYPE']
        if auth_type == 'dual':
            auth_type = request.headers.get('Authorization-Type', None)
        sub: str|None = None
        if auth_type == 'cookie':
            sub = session.get('sub', None)
            if sub is None:
                return auth_manager._error_responses.get(
                    NO_VALID_COOKIE_SUB, ({'msg': 'Cookie subject is missing or expired'}, 401)
                )
        elif auth_type == 'token':
            authorization = request.headers.get('Authorization', None)
            if authorization is None:
                return auth_manager._error_responses.get(
                    AUTHORIZATION_MISSING, ({'msg': 'Authorization header is missing'}, 401)
                )
            auth_split = authorization.split(' ')
            if len(auth_split) != 2 or auth_split[0] != 'Bearer' or auth_split[1] == '':
                return auth_manager._error_responses.get(
                    AUTHORIZATION_INVALID, ({'msg': 'Authorization header is invalid'}, 401)
                )
            token = auth_split[1]
            with TokenErrorHandler(auth_manager) as handler:
                sub = get_token_sub(token)
            if handler.error_response:
                return handler.error_response
        else:
            return auth_manager._error_responses.get(
                NO_VALID_AUTH_TYPE, ({'msg': 'Authorization-Type header is missing or invalid'}, 400)
            )
        user: Any|None = auth_manager._user_loader(sub)
        if user is None:
            return auth_manager._error_responses.get(
                USER_NOT_FOUND, ({'msg': 'User not found for subject'}, 404)
            )
        g.current_user = user
        return func(*args, **kwargs)
    return decorated
