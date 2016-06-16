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


class Channel(db.Model):
    __tablename__ = 'channel'
    id = db.Column(db.Integer, primary_key=True)
    link = db.Column(db.String())
    created_time = db.Column(db.DateTime(timezone=True), default=sql.func.now())

    def __init__(self, form):
        # init 里 get 和 验证
        self.link = form.get('link', '')

    def __repr__(self):
        return u'<{} {} {}>'.format(self.__class__.__name__, self.id, self.link)

    def save(self):
        db.session.add(self)
        db.session.commit()


class Problem(db.Model):
    __tablename__ = 'problem'
    id = db.Column(db.Integer, primary_key=True)
    link = db.Column(db.String())
    timestamp = db.Column(db.DateTime(timezone=True), default=sql.func.now())

    def __init__(self, form):
        # init 里 get 和 验证
        self.link = form.get('link', '')

    def __repr__(self):
        return u'<{} {} {}>'.format(self.__class__.__name__, self.id, self.link)

    def save(self):
        db.session.add(self)
        db.session.commit()


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
