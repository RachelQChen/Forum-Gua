from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy import sql

import time
import shutil

db_path = 'models.db'
app = Flask(__name__)
app.secret_key = 'asdjf1923'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///{}'.format(db_path)

db = SQLAlchemy(app)


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


class Channel(db.Model, Model):
    __tablename__ = 'channels'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String())
    created_time = db.Column(db.DateTime(timezone=True), default=sql.func.now())

    def __init__(self, form):
        super(Channel, self).__init__()
        # init 里 get 和 验证
        self.name = form.get('name', '')

    def channel_row(self):
        cr = {
            'id': self.id,
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


class Post(db.Model, Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    channel_id = db.Column(db.String())
    created_time = db.Column(db.DateTime(timezone=True), default=sql.func.now())
    title = db.Column(db.String())
    body = db.Column(db.String())
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    comments = db.relationship('Comment', backref='post', lazy='dynamic')

    def __init__(self, form):
        super(Post, self).__init__()
        # init 里 get 和 验证
        self.title = form.get('title', '')
        self.body = form.get('body', '')
        self.channel_id = form.get('channel_id', '')

    def post_row(self):
        plink = '<a href="/post/{}">{}</a>'.format(self.id, self.title)
        pr = {
            'link': plink,
            'time': self.created_time,
        }
        return pr

    def comment_list(self):
        comments = Comment.query.filter_by(post_id=self.id)
        clist = []
        for c in comments:
            clist.append(c.comment_row())
        return clist


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

    def comment_row(self):
        u = User.query.filter_by(id=self.user_id).first()
        user_link = u'<a href="/user/{}">{}</a>'.format(u.id, u.username)
        c = {
            'user_link': user_link,
            'content': self.content,
        }
        return c



class User(db.Model, Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String())
    password = db.Column(db.String())
    created_time = db.Column(db.DateTime(timezone=True), default=sql.func.now())
    sex = db.Column(db.String())
    note = db.Column(db.String())
    role = db.Column(db.Integer, default=2)
    posts = db.relationship('Post', backref='user', lazy='dynamic')
    comments = db.relationship('Comment', backref='user', lazy='dynamic')

    def __init__(self, form):
        super(User, self).__init__()
        self.username = form.get('username', '')
        self.password = form.get('password', '')
        self.sex = form.get('sex', 'male')
        self.note = form.get('note', '')

    def update(self, form):
        self.username = form.get('username', self.username)
        self.password = form.get('password', self.password)
        self.sex = form.get('sex', self.sex)
        self.note = form.get('note', self.note)

    def validate_register(self):
        username_len = len(self.username) >= 6
        password_len = len(self.password) >= 3
        return username_len and password_len

    def validate_login(self, user):
        if isinstance(user, User):
            username_equals = self.username == user.username
            password_equals = self.password == user.password
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
