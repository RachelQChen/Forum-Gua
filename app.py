from flask import Flask
from flask import render_template
from flask import redirect
from flask import url_for
from flask import request
from flask import make_response
from flask import abort
from flask import flash
from flask import session

from flask import json

from models import Channel
from models import Post
from models import User
from models import Comment
from models import Role

from rlog import log
from decorators import login_required
from decorators import admin_required
from decorators import current_user
from decorators import is_administrator
from decorators import is_current_user
from jinjia_filters import from_now
from jinjia_filters import formatted_time
from jinjia_filters import short_time

app = Flask(__name__)

app.secret_key = 'asdjf1923'


app.jinja_env.filters['from_now'] = from_now
app.jinja_env.filters['formatted_time'] = formatted_time
app.jinja_env.filters['short_time'] = short_time


# cookie 实时存入对应权限的channel id, role id, 发送给前端解析.
# #保证刷新,注销之后,页面保持勾选状态.
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
    return cid_rid_list


@app.route('/')
def index():
    return redirect(url_for('channels_roles'))


@app.route('/admin')
@admin_required
def admin_view():
    rs = Role.query.all()
    cs = Channel.query.all()
    data = cid_rid_for_cookie()
    log('cid_rid_list: ', data)
    json_data = json.dumps(data)
    log('json_data: ', json_data)
    r = make_response(render_template('admin.html', roles=rs, channels=cs))
    log('响应r: ', r)
    r.set_cookie('cid_rid_list', json_data)
    return r


@app.route('/admin', methods=['POST'])
@admin_required
def admin():
    option_json = request.json
    Channel.update_roles(option_json)
    response_data = cid_rid_for_cookie()
    return json.dumps(response_data, indent=2)


@app.route('/role/add', methods=['POST'])
@admin_required
def role_add():
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


@app.route('/role/delete/<role_id>')
@admin_required
def role_delete(role_id):
    r = Role.query.filter_by(id=role_id).first()
    if r is not None:
        r.delete()
    return redirect(url_for('channels_roles'))


@app.route('/role/update/<role_id>', methods=['POST'])
@admin_required
def role_update(role_id):
    r = Role.query.filter_by(id=role_id).first()
    r.update(request.form)
    r.save()
    return redirect(url_for('channels_roles'))


@app.route('/channel/list')
@login_required
def channels_roles():
    roles = Role.query.all()
    return render_template('channels.html', roles=roles)


@app.route('/channel/add', methods=['POST'])
@admin_required
def channel_add():
    j = request.json
    c = Channel(j)
    c.save()
    responseData = {
        'channel_name': c.name,
        'channel_id': c.id,
    }
    return json.dumps(responseData, indent=2)



@app.route('/channel/delete/<channel_id>')
@admin_required
def channel_delete(channel_id):
    c = Channel.query.filter_by(id=channel_id).first()
    if c is not None:
        c.delete()
    return redirect(url_for('channels_roles'))


@app.route('/channel/<channel_id>')
@login_required
def channel_view(channel_id):
    c = Channel.query.filter_by(id=channel_id).first()
    plist = c.post_list()
    return render_template('channel.html', channel=c, posts=plist)


@app.route('/channel/update/<channel_id>', methods=['POST'])
@admin_required
def channel_update(channel_id):
    c = Channel.query.filter_by(id=channel_id).first()
    c.update(request.form)
    c.save()
    return redirect(url_for('channels_roles'))


@app.route('/post/add', methods=['POST'])
@login_required
def post_add():
    p = Post(request.json)
    p.user = current_user()
    p.save()
    post = p.post_row()
    log('post add, dict: ', post)
    response_data = {
        'id': post.get('id', ''),
        'link': post.get('link', ''),
        'time': post.get('time', ''),
        'part_content': post.get('part_content', ''),
        'author_link': post.get('author_link', ''),
        'is_author': True,
    }
    return json.dumps(response_data, indent=2)


@app.route('/post/delete/<post_id>')
@login_required
def post_delete(post_id):
    p = Post.query.filter_by(id=post_id).first()
    pid = p.id
    user = current_user()
    can_delete = p.is_author()(user) or is_administrator(user)
    if can_delete:
        p.delete()
        data = {'pid': pid}
        return json.dumps(data, indent=2)
    else:
        abort(401)


@app.route('/post/<post_id>')
def post_view(post_id):
    p = Post.query.filter_by(id=post_id).first()
    post = p.post_row()
    return render_template('post.html', post=post)


@app.route('/comment/add', methods=['POST'])
@login_required
def comment_add():
    c = Comment(request.json)
    log('comment request.json:', request.json)
    c.user = current_user()
    c.save()
    comment = c.comment_row()
    log('新增Comment:', c)
    log('comment add, dict: ', comment)
    response_data = {
        'id': comment.get('id', ''),
        'user_link': comment.get('user_link', ''),
        'time': comment.get('time', ''),
        'content': comment.get('content', ''),
    }
    return json.dumps(response_data, indent=2)


@app.route('/comment/delete/<comment_id>')
@login_required
def comment_delete(comment_id):
    c = Comment.query.filter_by(id=comment_id).first()
    cid = c.id
    user = current_user()
    can_delete = c.is_author()(user) or is_administrator(user)
    if can_delete:
        c.delete()
        data = {'cid': cid}
        return json.dumps(data, indent=2)
    else:
        abort(401)


@app.route('/login', methods=['POST'])
def login():
    u = User(request.form)
    user = User.query.filter_by(username=u.username).first()
    log('login-user: ', user)
    if user is None:
        log('用户登录失败')
        flash('用户名不存在.')
        return redirect(url_for('login_view'))
    else:
        u.salt = user.salt
        u.hash_password(request.form)
        if u.validate_login(user):
            log('用户登录成功, user_id: ', user.id)
            session['user_id'] = user.id
            return redirect(url_for('user_view', user_id=user.id))
        else:
            log('用户登录失败')
            flash('登录失败,请检查您的用户名和密码.')
            return redirect(url_for('login_view'))


@app.route('/signout/<user_id>')
@login_required
def signout(user_id):
    uid = session.get('user_id')
    log('session user id:', uid)
    log('current user id:', user_id)
    log('sid==cid? ', str(uid)==user_id)
    if user_id == str(uid):
        session['user_id'] = None
        log('signed out?', session.get('user_id') is None)
        return redirect(url_for('login_view'))
    else:
        abort(401)


@app.route('/login')
def login_view():
    return render_template('login.html')


@app.route('/register', methods=['POST'])
def register():
    form = request.form
    log('注册form: ', form)
    log('空username({})'.format(form.get('username')))
    log('若输入为空,得到的是什么类型?',type(form.get('username')))
    log('注册dict(form):', dict(form))

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
    log('user-view:', u)
    user = current_user()
    can_edit = False
    if is_current_user(u) or is_administrator(user):
        can_edit = True
    log('can_edit: ', can_edit)
    return render_template('user.html', user=u, can_edit=can_edit)


@app.route('/user/list')
@admin_required
def users():
    users = User.query.all()
    return render_template('users.html', users=users)


@app.route('/user/<user_id>/post/list')
def user_posts(user_id):
    u = User.query.filter_by(id=user_id).first()
    posts = u.post_list()
    return render_template('posts.html', posts=posts)


@app.route('/user/<user_id>/comment/list')
def user_comments(user_id):
    u = User.query.filter_by(id=user_id).first()
    comments = u.comment_list()
    return render_template('comments.html', comments=comments)


@app.route('/user/delete/<user_id>')
@admin_required
def user_delete(user_id):
    u = User.query.filter_by(id=user_id).first()
    u.delete()
    return redirect(url_for('admin_users_view'))


@app.route('/user/update/<user_id>')
@login_required
def user_update_view(user_id):
    user = current_user()
    uid = user.id
    can_edit = user_id == str(uid) or is_administrator(user)
    log('user_id == uid ?', user_id == str(uid))
    log('is_administrator(user)?', is_administrator(user))
    log('can edit?', can_edit)
    return render_template('user_update.html', can_edit=can_edit)


@app.route('/user/update/<user_id>', methods=['POST'])
@login_required
def user_update(user_id):
    u = User.query.filter_by(id=user_id).first()
    if is_administrator(u) or is_current_user(u):
        u.update(request.form)
        u.save()
        return redirect(url_for('user_view', user_id=user_id))
    else:
        abort(401)


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
