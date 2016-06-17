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

    def __repr__(self):
        class_name = self.__class__.__name__
        properties = (u'{0} = {1}'.format(k, v) for k, v in self.__dict__.items())
        return u'\n<{0}:\n  {1}\n'.format(class_name, '\n   '.join(properties))


class Channel(db.Model, Model):
    __tablename__ = 'channel'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String())
    created_time = db.Column(db.DateTime(timezone=True), default=sql.func.now())

    def __init__(self, form):
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
    __tablename__ = 'post'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String())
    channel_id = db.Column(db.String())
    created_time = db.Column(db.DateTime(timezone=True), default=sql.func.now())

    def __init__(self, form):
        # init 里 get 和 验证
        self.body = form.get('body', '')
        self.channel_id = form.get('channel_id', '')

    def post_row(self):
        plink = '<a href="/post/{}">{}</a>'.format(self.id, self.body)
        pr = {
            'link': plink,
            'time': self.created_time,
        }
        return pr


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
