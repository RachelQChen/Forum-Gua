from flask import Flask
from flask import render_template
from flask import redirect
from flask import url_for
from flask import request
from flask import make_response
from flask import send_from_directory
from flask import abort


import uuid
from flask import json

from models import Channel
from models import Post
from models import User
from models import Comment
from models import Role


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
        return user.role_id == 1


@app.route('/')
def index():
    return redirect(url_for('channels'))


@app.route('/admin')
def admin_view():
    rs = Role.query.all()
    cs = Channel.query.all()
    user = current_user()
    if is_administrator(user):
        return render_template('admin.html', roles=rs, channels=cs)
    else:
        abort(401)


@app.route('/admin', methods=['POST'])
def admin():
    user = current_user()
    is_admin = is_administrator(user)
    print('Is admin?', is_admin)
    if is_admin:
        option_json = request.json
        Channel.update_roles(option_json)
        response_data = []
        cs = Channel.query.all()
        for c in cs:
            rs = c.roles.all()
            for r in rs:
                data = {
                    'channel_id': c.id,
                    'role_id': r.id,
                }
                response_data.append(data)
        return json.dumps(response_data, indent=2)
    else:
        abort(401)



# @app.route('/random', methods=['POST'])
# def random():
#     # d = request.get_data()
#     # d = json.loads(d.decode('utf-8'))
#     d = request.json
#     print('random', type(d), d)
#     d['fuck'] = 'sb'
#     d['fuck-er'] = 'sbor'
#     return json.dumps(d, indent=2)
#     # return str(d)


@app.route('/role/add', methods=['POST'])
def role_add():
    user = current_user()
    is_admin = is_administrator(user)
    print('Is admin?', is_admin)
    if is_admin:
        j = request.json
        print('role-add json', type(j), j)
        r = Role(j)
        print('new role: ', r)
        r.save()
        responseData = {
            'role_name': r.name,
            'role_id': r.id,
        }
        return json.dumps(responseData, indent=2)
    else:
        abort(401)


@app.route('/role/<role_id>')
def role_delete(role_id):
    user = current_user()
    is_admin = is_administrator(user)
    if is_admin:
        r = Role.query.filter_by(id=role_id).first()
        if r is not None:
            r.delete()
        return redirect(url_for('admin_view'))
    else:
        abort(401)


@app.route('/channel/list')
def channels():
    user = current_user()
    if user is not None:
        role = user.role
        channels = role.channels.all()
        c_rows = []
        for c in channels:
            cr = c.channel_row()
            c_rows.append(cr)
        return render_template('channels.html', channels=c_rows)
    else:
        return redirect(url_for('login_view'))


@app.route('/channel/add', methods=['POST'])
def channel_add():
    user = current_user()
    is_admin = is_administrator(user)
    print('Is admin? ', is_admin)
    if is_admin:
        j = request.json
        c = Channel(j)
        c.save()
        responseData = {
            'channel_name': c.name,
            'channel_id': c.id,
        }
        return json.dumps(responseData, indent=2)
    else:
        abort(401)


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
    plist = c.post_list()
    user = current_user()
    if user is not None:
        role = user.role
        cs = role.channels.all()
        return render_template('channel.html',
                               channels=cs, channel=c,
                               posts=plist, user=user)
    else:
        return redirect(url_for('login_view'))


@app.route('/post/add', methods=['POST'])
def post_add():
    user = current_user()
    if user is None:
        return redirect(url_for('login_view'))
    else:
        p = Post(request.form)
        p.user = user
        p.save()
        cid = p.channel_id
        return redirect(url_for('channel_view', channel_id=cid))


@app.route('/post/delete/<post_id>')
def post_delete(post_id):
    p = Post.query.filter_by(id=post_id).first()
    cid = p.channel_id
    user = current_user()
    can_delete = p.is_author()(user) or is_administrator(user)
    # print('post-delete User: ', user)
    # print('Can delete? ', can_delete)
    if can_delete:
        p.delete()
        return redirect(url_for('channel_view', channel_id=cid))
    else:
        abort(401)


@app.route('/post/<post_id>')
def post_view(post_id):
    p = Post.query.filter_by(id=post_id).first()
    u = current_user()
    is_admin = is_administrator(u)
    return render_template('post.html', post=p, user=u, is_admin=is_admin)


@app.route('/comment/add', methods=['POST'])
def comment_add():
    user = current_user()
    if user is None:
        return redirect(url_for('login_view'))
    else:
        c = Comment(request.form)
        c.user = user
        c.save()
        # print('comment-post by form:', c.post)
        return redirect(url_for('post_view', post_id=c.post_id))


@app.route('/comment/delete/<comment_id>')
def comment_delete(comment_id):
    c = Comment.query.filter_by(id=comment_id).first()
    pid = c.post_id
    user = current_user()
    can_delete = c.is_author()(user) or is_administrator(user)
    if can_delete:
        c.delete()
        return redirect(url_for('post_view', post_id=pid))
    else:
        abort(401)


@app.route('/login', methods=['POST'])
def login():
    u = User(request.form)
    user = User.query.filter_by(username=u.username).first()
    # print(user)
    if u.validate_login(user):
        # print('用户登录成功, user_id: ', user.id)
        r = make_response(redirect(url_for('user_view', user_id=user.id)))
        cookie_id = str(uuid.uuid4())
        cookie_dict[cookie_id] = user
        r.set_cookie('cookie_id', cookie_id)
        return r
    else:
        # print('用户登录失败')
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
    # print ('user-view:', u)
    show_update = False
    if is_current_user(u) or is_administrator(u):
        show_update = True
    # print('show_update: ', show_update)
    html = render_template('user.html', user=u, show_update=show_update)
    # print('user.html: ', html)
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
    # print('user-update user: ', u)
    # print('Is administrator?', is_administrator(u))
    # print('Is current user?', is_current_user(u))
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
