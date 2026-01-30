## Flask-Dual-Auth

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.13%2B-blue)](https://www.python.org/downloads/)

A simple dual auth (cookie & token) extension for Flask


## Installation

Install from GitHub
```bash
pip install git+https://github.com/HY-nicochichi/Flask-Dual-Auth.git
```


## Usage

app.py
```python
from datetime import timedelta
from dataclasses import dataclass
from werkzeug.local import LocalProxy
from flask import (
    Flask,
    request
)
from flask_dual_auth import (
    AuthManager,
    auth_required,
    get_current_user,
    create_token,
    login_cookie,
    logout_cookie
)

@dataclass
class User:
    id: str
    email: str
    password: str
    name: str

users: list[User] = [
    User(id='11111', email='taro@email.com', password='Taro1234', name='Taro'),
    User(id='22222', email='jiro@email.com', password='Jiro1234', name='Jiro')
]

def find_user_by_id(id: str) -> User|None:
    return next((user for user in users if user.id == id), None)

def find_user_by_email(email: str) -> User|None:
    return next((user for user in users if user.email == email), None)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=3.0)

auth_manager = AuthManager(app)

@auth_manager.user_loader
def load_user(sub: str) -> User|None:
    return find_user_by_id(sub)

current_user: User = LocalProxy(get_current_user)

@app.post('/token')
def token() -> tuple[dict, int]:
    json: dict = request.get_json()
    email: str|None = json.get('email', None)
    password: str|None = json.get('password', None)
    user: User|None = find_user_by_email(email)
    if user and user.password == password:
        token: str = create_token(user.id)
        return {'token': token}, 200
    else:
        return {'msg': 'Invalid email or password'}, 401

@app.post('/login')
def login() -> tuple[dict, int]:
    json: dict = request.get_json()
    email: str|None = json.get('email', None)
    password: str|None = json.get('password', None)
    user: User|None = find_user_by_email(email)
    if user and user.password == password:
        login_cookie(user.id)
        return {'msg': 'Login success'}, 200
    else:
        return {'msg': 'Invalid email or password'}, 401

@app.get('/logout')
@auth_required
def logout() -> tuple[dict, int]:
    logout_cookie()
    return {'msg': 'Logout success'}, 200

@app.get('/me')
@auth_required
def me() -> tuple[dict, int]:
    return {'email': current_user.email, 'name': current_user.name}, 200

if __name__ == '__main__':
    app.run(host='localhost', port=8000)
```

client.py
```python
from requests import (
    get,
    post,
    Session
)

def token_auth():
    print('--- Token Authentication ---')
    resp1 = post(
        'http://localhost:8000/token',
        json = {
            'email': 'taro@email.com',
            'password': 'Taro1234'
        }
    )
    print(f'POST /token => {resp1.status_code}')
    json1 = resp1.json()
    print(json1)
    resp2 = get(
        'http://localhost:8000/me',
        headers = {
            'Authorization-Type': 'token',
            'Authorization': f'Bearer {json1['token']}'
        }
    )
    print(f'GET /me => {resp2.status_code}')
    json2 = resp2.json()
    print(json2)

def cookie_auth():
    with Session() as session:
        print('--- Cookie Authentication ---')
        resp1 = session.post(
            'http://localhost:8000/login',
            json = {'email': 'taro@email.com', 'password': 'Taro1234'}
        )
        print(f'POST /login => {resp1.status_code}')
        json1 = resp1.json()
        print(json1)
        resp2 = session.get(
            'http://localhost:8000/me',
            headers = {'Authorization-Type': 'cookie'}
        )
        print(f'GET /me => {resp2.status_code}')
        json2 = resp2.json()
        print(json2)
        resp3 = session.get(
            'http://localhost:8000/logout',
            headers = {'Authorization-Type': 'cookie'}
        )
        print(f'GET /logout => {resp3.status_code}')
        json3 = resp3.json()
        print(json3)

if __name__ == '__main__':
    token_auth()
    cookie_auth()
```


## Advanced Usage

app.py
```python
from datetime import timedelta
from dataclasses import dataclass
from werkzeug.local import LocalProxy
from flask import (
    Flask,
    request
)
from flask_dual_auth import (
    AuthManager,
    TokenErrorHandler,
    auth_required,
    get_current_user,
    get_auth_manager,
    create_token,
    create_refresh_token,
    get_token_sub,
    login_cookie,
    logout_cookie
)

@dataclass
class User:
    id: str
    email: str
    password: str
    name: str

users: list[User] = [
    User(id='11111', email='taro@email.com', password='Taro1234', name='Taro'),
    User(id='22222', email='jiro@email.com', password='Jiro1234', name='Jiro')
]

def find_user_by_id(id: str) -> User|None:
    return next((user for user in users if user.id == id), None)

def find_user_by_email(email: str) -> User|None:
    return next((user for user in users if user.email == email), None)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=3.0)
app.config['TOKEN_LIFETIME'] = timedelta(minutes=30.0)
app.config['REFRESH_TOKEN_LIFETIME'] = timedelta(days=10.0)

auth_manager = AuthManager(app)

@auth_manager.user_loader
def load_user(sub: str) -> User|None:
    return find_user_by_id(sub)

current_user: User = LocalProxy(get_current_user)

@app.post('/token')
def token() -> tuple[dict, int]:
    json: dict = request.get_json()
    email: str|None = json.get('email', None)
    password: str|None = json.get('password', None)
    user: User|None = find_user_by_email(email)
    if user and user.password == password:
        return {
            'token': create_token(user.id),
            'refresh_token': create_refresh_token(user.id)
        }, 200
    else:
        return {'msg': 'Invalid email or password'}, 401

@app.post('/token/refresh')
def token_refresh() -> tuple[dict, int]:
    json: dict = request.get_json()
    refresh_token: str|None = json.get('refresh_token', None)
    if refresh_token is None:
        return {'msg': 'Refresh token is missing'}, 401
    with TokenErrorHandler(get_auth_manager()) as handler:
        sub: str = get_token_sub(refresh_token)
    if handler.error_response:
        return handler.error_response
    return {'token': create_token(sub)}, 200

@app.post('/login')
def login() -> tuple[dict, int]:
    json: dict = request.get_json()
    email: str|None = json.get('email', None)
    password: str|None = json.get('password', None)
    user: User|None = find_user_by_email(email)
    if user and user.password == password:
        login_cookie(user.id)
        return {'msg': 'Login success'}, 200
    else:
        return {'msg': 'Invalid email or password'}, 401

@app.get('/logout')
@auth_required
def logout() -> tuple[dict, int]:
    logout_cookie()
    return {'msg': 'Logout success'}, 200

@app.get('/me')
@auth_required
def me() -> tuple[dict, int]:
    return {'email': current_user.email, 'name': current_user.name}, 200

if __name__ == '__main__':
    app.run(host='localhost', port=8000)
```


## Custom Error Responses

app.py
```python
from flask import (
    Response,
    redirect,
    render_template,
    jsonify
)
from flask_dual_auth import AuthManager
from flask_dual_auth.errors import (
    NO_VALID_AUTH_TYPE,
    NO_VALID_COOKIE_SUB,
    AUTHORIZATION_MISSING,
    AUTHORIZATION_INVALID,
    TOKEN_EXPIRED,
    TOKEN_INVALID,
    TOKEN_DECODE_FAILURE, 
    USER_NOT_FOUND 
)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=3.0)

auth_manager = AuthManager(app)

with app.app_context():
    auth_manager.error_responses({
        NO_VALID_AUTH_TYPE: ({'msg': 'Authorization-Type header is missing or invalid'}, 200),
        NO_VALID_COOKIE_SUB: (jsonify({'msg': 'Cookie subject is missing or expired'}), 200),
        AUTHORIZATION_MISSING: ('Authorization header is missing', 200),
        AUTHORIZATION_INVALID: ('<h1>Authorization header is invalid</h1>', 200),
        TOKEN_EXPIRED: (render_template('login.html'), 200),
        TOKEN_INVALID: (redirect('/login'), 302),
        TOKEN_DECODE_FAILURE: (Response(
            '<?xml version="1.0"?><error><msg>Token decoding failed</msg></error>',
            mimetype='application/xml'
        ), 200)
        # USER_NOT_FOUND is unset, so default error response is returned
    })
```
