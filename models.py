from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy import sql

import hashlib
import time
import shutil
import uuid

from rlog import log

db_path = 'models.db'
app = Flask(__name__)
app.secret_key = 'asdjf1923'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///{}'.format(db_path)

db = SQLAlchemy(app)


def password_salt():
    random = str(uuid.uuid4())
    salt = random[:6]
    return salt


class Model(object):
    def save(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def __repr__(self):
        class_name = self.__class__.__name__
        properties = (u'{0} = {1}'.format(k, v) for k, v in self.__dict__.items())
        return u'\n<{0}:\n  {1}\n'.format(class_name, '\n   '.join(properties))


admins = db.Table(
    'admins',
    db.Column('channel_id', db.Integer, db.ForeignKey('channels.id')),
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id'))
)


class Role(db.Model, Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String())
    users = db.relationship('User', backref='role', lazy='dynamic')


    def __init__(self, form):
        super(Role, self).__init__()
        # init 里 get 和 验证
        self.name = form.get('name', '')

    # def add_channel(self, form):
    #     channels_id = form.getlist(self.name)
    #     print('在加channels id: ', channels_id)
    #     for cid in channels_id:
    #         print('在加cid: ', cid)
    #         c = Channel.query.filter_by(id=cid).first()
    #         print('在加 channel: ', c.name)
    #         self.channels.append(c)
    #
    # def remove_channel(self, channel):
    #     self.channels.remove(channel)


class Channel(db.Model, Model):
    __tablename__ = 'channels'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String())
    created_time = db.Column(db.DateTime(timezone=True), default=sql.func.now())
    roles = db.relationship('Role',
                            secondary=admins,
                            backref=db.backref('channels', lazy='dynamic'),
                            lazy='dynamic')


    def __init__(self, form):
        super(Channel, self).__init__()
        # init 里 get 和 验证
        self.name = form.get('name', '')

    def channel_row(self):
        cr = {
            'id': self.id,
            'name': self.name,
            'link': '<a href="/channel/{}">{}</a>'.format(self.id, self.name),
            'time': self.created_time,
        }
        return cr

    def post_list(self):
        posts = Post.query.filter_by(channel_id=self.id).all()
        plist = []
        for p in posts:
            plist.append(p.post_row())
        return plist

    @staticmethod
    def update_roles(option_json):
        for option in option_json:
            cid = option.get('channel_id')
            rid = option.get('role_id')
            # print('role id:  ', rid)
            checked_status = option.get('checked_status')
            c = Channel.query.filter_by(id=cid).first()
            # print('channel: ', c)
            r = Role.query.filter_by(id=rid).first()
            # print('role:    ', r)
            if checked_status:
                if r not in c.roles:
                    c.roles.append(r)
                    print('增加role in channel:', c, r)
            else:
                if r in c.roles:
                    c.roles.remove(r)
                    print('删除该channel里的role:', c, r)
        db.session.commit()



class Post(db.Model, Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    channel_id = db.Column(db.String())
    created_time = db.Column(db.DateTime(timezone=True), default=sql.func.now())
    title = db.Column(db.String())
    content= db.Column(db.String())
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    comments = db.relationship('Comment', backref='post', lazy='dynamic')

    def __init__(self, form):
        super(Post, self).__init__()
        # init 里 get 和 验证
        self.title = form.get('title', '')
        self.content = form.get('content', '')
        self.channel_id = form.get('channel_id', '')

    def post_row(self):
        u = self.user
        plink = u'<a href="/post/{}">{}</a>'.format(self.id, self.title)
        author_link = u'<a href="/user/{}">{}</a>'.format(u.id, u.username)
        part_content = self.content[:200]
        pr = {
            'id': self.id,
            'link': plink,
            'time': self.created_time,
            'part_content': part_content,
            'author_link': author_link,
            'is_author': self.is_author(),
            'content': self.content,
            'comment_list': self.comment_list(),
        }
        return pr

    def comment_list(self):
        comments = Comment.query.filter_by(post_id=self.id)
        clist = []
        for c in comments:
            clist.append(c.comment_row())
        return clist

    def is_author(self):
        def func(user):
            if user is None:
                return False
            else:
                return self.user_id == user.id
        return func


class Comment(db.Model, Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String())
    created_time = db.Column(db.DateTime(timezone=True), default=sql.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'))

    def __init__(self, form):
        super(Comment, self).__init__()
        self.content = form.get('content', '')
        self.post_id = form.get('post_id', None)

    def comment_row(self):
        u = User.query.filter_by(id=self.user_id).first()
        user_link = u'<a href="/user/{}">{}</a>'.format(u.id, u.username)
        c = {
            'id': self.id,
            'user_link': user_link,
            'content': self.content,
            'is_author': self.is_author(),
        }
        return c

    def is_author(self):
        def func(user):
            if user is None:
                return False
            else:
                return self.user_id == user.id
        return func


class User(db.Model, Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String())
    password_hash = db.Column(db.String())
    salt = db.Column(db.String())
    created_time = db.Column(db.DateTime(timezone=True), default=sql.func.now())
    sex = db.Column(db.String())
    note = db.Column(db.String())
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), default=2)
    posts = db.relationship('Post', backref='user', lazy='dynamic')
    comments = db.relationship('Comment', backref='user', lazy='dynamic')

    def __init__(self, form):
        super(User, self).__init__()
        self.username = form.get('username', '')
        self.sex = form.get('sex', 'male')
        self.note = form.get('note', '')
        self.salt = password_salt()


    def hash_password(self, form):
        print('hash-form: ', form)
        psw = form.get('password', '')
        print('password: ', psw)
        hash1 = hashlib.md5(psw.encode('ascii')).hexdigest()
        hash2 = hashlib.md5((hash1 + self.salt).encode('ascii')).hexdigest()
        self.password_hash = hash2

    @property
    def posts_link(self):
        posts_link = u'<a href="/user/{}/post/list">文章</a>'.format(self.id)
        return posts_link

    @property
    def comments_link(self):
        comments_link = u'<a href="/user/{}/comment/list">评论</a>'.format(self.id)
        return comments_link

    def update(self, form):
        self.username = form.get('username', self.username)
        psw = form.get('password', self.password)
        self.password_hash = self.hash_password(psw)
        self.sex = form.get('sex', self.sex)
        self.note = form.get('note', self.note)

    def validate_username(self):
        if User.query.filter_by(username=self.username).first() is None:
            return True
        else:
            return False


    def validate_register(self):
        username_len = len(self.username) >= 6
        password_len = len(self.password_hash) > 0
        if self.validate_username():
            return username_len and password_len
        else:
            return False

    def validate_login(self, user):
        log('刚输入的username: ', self.username)
        log('被对比的username: ', user.username)
        log('刚输入的psw-hash: ', self.password_hash)
        log('被对比的psw-hash: ', user.password_hash)
        if isinstance(user, User):
            username_equals = self.username == user.username
            password_equals = self.password_hash == user.password_hash
            return username_equals and password_equals
        else:
            return False


def backup_db():
    backup_path = '{}.{}'.format(time.time(), db_path)
    shutil.copyfile(db_path, backup_path)


def rebuild_db():
    backup_db()
    db.drop_all()
    db.create_all()
    print('rebuild database')


if __name__ == '__main__':
    rebuild_db()
