from flask import Flask
from flask import render_template
from flask import redirect
from flask import url_for
from flask import request
from flask import make_response
from flask import abort
from flask import flash
from flask import session


import uuid
from flask import json

from models import Channel
from models import Post
from models import User
from models import Comment
from models import Role

from rlog import log

app = Flask(__name__)


app.secret_key = 'asdjf1923'
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


def cid_rid_for_cookie():
    cid_rid_list = []
    channels = Channel.query.all()
    for c in channels:
        roles = c.roles
        for r in roles:
            cid_rid = '#id-{}-{}'.format(c.id, r.id)
            data = {
                'cid-rid': cid_rid,
            }
            cid_rid_list.append(data)
    cookie_dict['cid_rid_list'] = cid_rid_list
    log('含有cid-rid的cookie_dict: ', cookie_dict)
    return cid_rid_list



@app.route('/')
def index():
    return redirect(url_for('channels_roles'))


@app.route('/admin')
def admin_view():
    rs = Role.query.all()
    cs = Channel.query.all()
    user = current_user()
    if is_administrator(user):
        data = cid_rid_for_cookie()
        log('cid_rid_list: ', data)
        json_data = json.dumps(data)
        log('json_data: ', json_data)
        r = make_response(render_template('admin.html', roles=rs, channels=cs))
        log('响应r: ', r)
        r.set_cookie('cid_rid_list', json_data)
        return r
    else:
        # flash('不好意思,你没有权限访问此页.')
        abort(401)


@app.route('/admin', methods=['POST'])
def admin():
    user = current_user()
    is_admin = is_administrator(user)
    log('Is admin?', is_admin)
    if is_admin:
        option_json = request.json
        Channel.update_roles(option_json)
        response_data = cid_rid_for_cookie()
        return json.dumps(response_data, indent=2)
    else:
        abort(401)


# @app.route('/random', methods=['POST'])
# def random():
#     # d = request.get_data()
#     # d = json.loads(d.decode('utf-8'))
#     d = request.json
#     log('random', type(d), d)
#     d['fuck'] = 'sb'
#     d['fuck-er'] = 'sbor'
#     return json.dumps(d, indent=2)
#     # return str(d)


@app.route('/role/add', methods=['POST'])
def role_add():
    user = current_user()
    is_admin = is_administrator(user)
    log('Is admin?', is_admin)
    if is_admin:
        j = request.json
        log('role-add json', type(j), j)
        r = Role(j)
        log('new role: ', r)
        r.save()
        responseData = {
            'role_name': r.name,
            'role_id': r.id,
        }
        return json.dumps(responseData, indent=2)
    else:
        abort(401)


@app.route('/role/delete/<role_id>')
def role_delete(role_id):
    user = current_user()
    is_admin = is_administrator(user)
    if is_admin:
        r = Role.query.filter_by(id=role_id).first()
        if r is not None:
            r.delete()
        return redirect(url_for('channels_roles'))
    else:
        # flash('不好意思,你没有权限访问此页.')
        abort(401)


@app.route('/channel/list')
def channels_roles():
    user = current_user()
    if user is not None:
        roles = Role.query.all()
        # role = user.role
        # channels = role.channels
        # c_rows = []
        # for c in channels:
        #     cr = c.channel_row()
        #     c_rows.append(cr)
        return render_template('channels.html', roles=roles)
    else:
        return redirect(url_for('login_view'))


@app.route('/channel/add', methods=['POST'])
def channel_add():
    user = current_user()
    is_admin = is_administrator(user)
    log('Is admin? ', is_admin)
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
        return redirect(url_for('channels_roles'))
    else:
        # flash('不好意思,你没有权限访问此页.')
        abort(401)


@app.route('/channel/<channel_id>')
def channel_view(channel_id):
    c = Channel.query.filter_by(id=channel_id).first()
    plist = c.post_list()
    user = current_user()
    if user is not None:
        role = user.role
        cs = role.channels.all()
        is_admin = is_administrator(user)
        return render_template('channel.html',
                               channels=cs, channel=c, posts=plist,
                               user=user, is_admin=is_admin)
    else:
        return redirect(url_for('login_view'))


@app.route('/post/add', methods=['POST'])
def post_add():
    user = current_user()
    if user is None:
        return redirect(url_for('login_view'))
    else:
        p = Post(request.json)
        p.user = user
        p.save()
        cid = p.channel_id
        # responseData = {
        #     'channel_name': c.name,
        #     'channel_id': c.id,
        # }
        # return json.dumps(responseData, indent=2)
        return redirect(url_for('channel_view', channel_id=cid))



@app.route('/post/delete/<post_id>')
def post_delete(post_id):
    p = Post.query.filter_by(id=post_id).first()
    cid = p.channel_id
    user = current_user()
    can_delete = p.is_author()(user) or is_administrator(user)
    # log('post-delete User: ', user)
    # log('Can delete? ', can_delete)
    if can_delete:
        p.delete()
        return redirect(url_for('channel_view', channel_id=cid))
    else:
        # flash('不好意思,你没有权限访问此页.')
        abort(401)


@app.route('/post/<post_id>')
def post_view(post_id):
    p = Post.query.filter_by(id=post_id).first()
    post = p.post_row()
    # u = current_user()
    # is_admin = is_administrator(u)
    return render_template('post.html', post=post)


@app.route('/comment/add', methods=['POST'])
def comment_add():
    user = current_user()
    if user is None:
        return redirect(url_for('login_view'))
    else:
        c = Comment(request.form)
        c.user = user
        c.save()
        # log('comment-post by form:', c.post)
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
        # flash('不好意思,你没有权限访问此页.')
        abort(401)


@app.route('/login', methods=['POST'])
def login():
    u = User(request.form)
    user = User.query.filter_by(username=u.username).first()
    log('login-user: ', user)
    if user is not None:
        u.salt = user.salt
        u.hash_password(request.form)
        if u.validate_login(user):
            log('用户登录成功, user_id: ', user.id)
            # flash('您已成功登录!')
            r = make_response(redirect(url_for('user_view', user_id=user.id)))
            cookie_id = str(uuid.uuid4())
            cookie_dict[cookie_id] = user
            r.set_cookie('cookie_id', cookie_id)
            return r
    else:
        log('用户登录失败')
        flash('登录失败,请检查您的用户名和密码.')
        return redirect(url_for('login_view'))


@app.route('/login')
def login_view():
    return render_template('login.html')


@app.route('/register', methods=['POST'])
def register():
    form = request.form
    print('注册form: ', form)
    u = User(form)
    u.hash_password(form)
    if u.validate_register():
        log('用户注册成功')
        u.save()
        flash('恭喜,您已注册成功.')
        return redirect(url_for('login_view'))
    else:
        log('注册失败', request.form)
        flash('抱歉, 注册失败, 请重试.')
        return redirect(url_for('login_view'))


@app.route('/user/<user_id>')
def user_view(user_id):
    u = User.query.filter_by(id=user_id).first()
    log ('user-view:', u)
    can_edit = False
    if is_current_user(u) or is_administrator(u):
        can_edit = True
    log('can_edit: ', can_edit)
    html = render_template('user.html', user=u, can_edit=can_edit)
    log('user.html: ', html)
    return html

@app.route('/user/<user_id>/post/list')
def user_posts(user_id):
    u = User.query.filter_by(id=user_id).first()
    posts = u.post_list()
    return render_template('posts.html', posts=posts)


@app.route('/user/<user_id>/comment/list')
def user_comments(user_id):
    u = User.query.filter_by(id=user_id).first()
    comments = u.comments
    return render_template('comments.html', comments=comments)


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
        # flash('不好意思,你没有权限访问此页.')
        abort(401)


@app.route('/admin/users/update/<user_id>')
def user_update_view(user_id):
    u = User.query.filter_by(id=user_id).first()
    return render_template('user_update.html', user=u)


@app.route('/admin/users/update/<user_id>', methods=['POST'])
def user_update(user_id):
    u = User.query.filter_by(id=user_id).first()
    # log('user-update user: ', u)
    # log('Is administrator?', is_administrator(u))
    # log('Is current user?', is_current_user(u))
    if is_administrator(u) or is_current_user(u):
        u.update(request.form)
        u.save()
        return redirect(url_for('user_view', user_id=user_id))
    else:
        abort(401)


# @app.route('/uploads/<filename>')
# def uploaded_file(filename):
#     return send_from_directory(app.config['UPLOAD_FOLDER'],
#
#                             filename)
@app.context_processor
def args_for_base():
    """Add args to base.html"""
    user = current_user()
    is_admin = is_administrator(user)
    c_rows = []
    if user is not None:
        role = user.role
        channels = role.channels
        for c in channels:
            cr = c.channel_row()
            c_rows.append(cr)
    args = {
        'channels': c_rows,
        'current_user': user,
        'is_admin': is_admin,
    }
    return dict(**args)



if __name__ == '__main__':
    host, port = '0.0.0.0', 9000
    args = {
        'host': host,
        'port': port,
        'debug': True,
    }
    app.run(**args)
