from flask import Flask
from flask import redirect
from flask import url_for
from flask import abort
from flask import session

from functools import wraps

from models import User


app = Flask(__name__)

app.secret_key = 'asdjf1923'


def current_user():
    uid = session.get('user_id')
    if uid is not None:
        user = User.query.filter_by(id=uid).first()
        return user
    else:
        return None


def is_current_user(user):
    if user is None:
        return False
    else:
        uid = session.get('user_id')
        return user.id == uid


def is_administrator(user):
    if user is None:
        return False
    else:
        return user.role_id == 1


def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        # f 是被装饰的函数
        # 所以下面两行会先于被装饰的函数内容调用
        print('debug, requires_login')
        user = current_user()
        if is_current_user(user):
            return f(*args, **kwargs)
        else:
            return redirect(url_for('login_view'))
    return wrapped


def admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        # f 是被装饰的函数
        # 所以下面两行会先于被装饰的函数内容调用
        print('debug, requires_login')
        u = current_user()
        if is_administrator(u):
            return f(*args, **kwargs)
        else:
            return abort(401)
    return wrapped
