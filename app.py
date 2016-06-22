from flask import Flask
from flask import render_template
from flask import redirect
from flask import url_for
from flask import request
from flask import make_response
from flask import send_from_directory
from flask import abort


import uuid

from models import Channel
from models import Post
from models import User
from models import Comment


app = Flask(__name__)

cookie_dict = {}


def current_user():
    cid = request.cookies.get('cookie_id')
    user = cookie_dict.get(cid, None)
    return user


def is_current_user(user):
    if user is None:
        return False
    else:
        return user is current_user()


def is_administrator(user):
    if user is None:
        return False
    else:
        return user.role == 1


@app.route('/')
def index():
    return redirect(url_for('channels'))


@app.route('/channel/list')
def channels():
    channels = Channel.query.all()
    c_rows = []
    for c in channels:
        cr = c.channel_row()
        c_rows.append(cr)
    user = current_user()
    is_admin = is_administrator(user)
    return render_template('channels.html', channels=c_rows, is_admin=is_admin)


@app.route('/channel/add', methods=['POST'])
def channel_add():
    c = Channel(request.form)
    c.save()
    # print('channel_add: ', c)
    return redirect(url_for('channels'))


@app.route('/channel/delete/<channel_id>')
def channel_delete(channel_id):
    user = current_user()
    is_admin = is_administrator(user)
    if is_admin:
        c = Channel.query.filter_by(id=channel_id).first()
        if c is not None:
            c.delete()
        return redirect(url_for('channels'))
    else:
        abort(401)


@app.route('/channel/<channel_id>')
def channel_view(channel_id):
    c = Channel.query.filter_by(id=channel_id).first()
    cs = Channel.query.all()
    # print('channel view: ', c)
    plist = c.post_list()
    # print('post list: ', plist)
    user = current_user()
    can_del = False
    if is_current_user(user) or is_administrator(user):
        can_del = True
    return render_template('channel.html', channels=cs, channel=c, posts=plist, can_delete=can_del)


@app.route('/post/add', methods=['POST'])
def post_add():
    p = Post(request.form)
    p.save()
    # print('post_add: ', p)
    cid = p.channel_id
    # print('Post_add channel_id', cid)
    return redirect(url_for('channel_view', channel_id=cid))


@app.route('/post/delete/<post_id>')
def post_delete(post_id):
    p = Post.query.filter_by(id=post_id).first()
    user = current_user()
    can_delete = is_current_user(user) or is_administrator(user)
    if can_delete:
        p.delete()
        return redirect(url_for('channel_view', channel_id=p.channel_id))
    else:
        abort(401)


@app.route('/post/<post_id>')
def post_view(post_id):
    p = Post.query.filter_by(id=post_id).first()
    user = current_user()
    is_curr = user is not None
    return render_template('post.html', post=p, is_current_user=is_curr)


@app.route('/post/<post_id>/comment/add', methods=['POST'])
def comment_add(post_id):
    user = current_user()
    post = Post.query.filter_by(id=post_id).first()
    print('comment-post: ', post)
    if user is None:
        return redirect(url_for('login_view'))
    else:
        c = Comment(request.form)
        c.user = user
        c.post = post
        c.save()
        return redirect(url_for('post_view', post_id=post.id))


@app.route('/post/<post_id>/comment/delete/<comment_id>')
def comment_delete(post_id, comment_id):
    c = Comment.query.filter_by(id=comment_id).first()
    user = current_user()
    can_delete = is_current_user(user) or is_administrator(user)
    if can_delete:
        c.delete()
        return redirect(url_for('post_view', post_id=post_id))
    else:
        abort(401)


@app.route('/login', methods=['POST'])
def login():
    u = User(request.form)
    user = User.query.filter_by(username=u.username).first()
    print(user)
    if u.validate_login(user):
        print('用户登录成功, user_id: ', user.id)
        r = make_response(redirect(url_for('user_view', user_id=user.id)))
        cookie_id = str(uuid.uuid4())
        cookie_dict[cookie_id] = user
        r.set_cookie('cookie_id', cookie_id)
        return r
    else:
        print('用户登录失败')
        return redirect(url_for('login_view'))


@app.route('/login')
def login_view():
    return render_template('login.html')


@app.route('/register', methods=['POST'])
def register():
    u = User(request.form)
    if u.validate_register():
        # print('用户注册成功')
        u.save()
        return redirect(url_for('login_view'))
    else:
        # print('注册失败', request.form)
        return redirect(url_for('login_view'))


@app.route('/user/<user_id>')
def user_view(user_id):
    u = User.query.filter_by(id=user_id).first()
    print ('user-view:', u)
    show_update = False
    if is_current_user(u) or is_administrator(u):
        show_update = True
    print('show_update: ', show_update)
    html = render_template('user.html', user=u, show_update=show_update)
    print('user.html: ', html)
    return html


@app.route('/admin/users')
def admin_users_view():
    users = User.query.all()
    return render_template('admin_users.html', users=users)


@app.route('/admin/users/delete/<user_id>')
def user_delete(user_id):
    u = User.query.filter_by(id=user_id).first()
    user = current_user()
    if user is not None and is_administrator(user):
        u.delete()
        return redirect(url_for('admin_users_view'))
    else:
        abort(401)


@app.route('/admin/users/update/<user_id>')
def user_update_view(user_id):
    u = User.query.filter_by(id=user_id).first()
    return render_template('user_update.html', user=u)


@app.route('/admin/users/update/<user_id>', methods=['POST'])
def user_update(user_id):
    u = User.query.filter_by(id=user_id).first()
    print('user-update user: ', u)
    print('Is administrator?', is_administrator(u))
    print('Is current user?', is_current_user(u))
    if is_administrator(u) or is_current_user(u):
        u.update(request.form)
        u.save()
        return redirect(url_for('user_view', user_id=user_id))
    else:
        abort(401)


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               filename)


if __name__ == '__main__':
    host, port = '0.0.0.0', 9000
    args = {
        'host': host,
        'port': port,
        'debug': True,
    }
    app.run(**args)
