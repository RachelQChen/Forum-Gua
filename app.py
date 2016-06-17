from flask import Flask
from flask import render_template
from flask import redirect
from flask import url_for
from flask import request

from models import Channel
from models import Post

app = Flask(__name__)


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
    return render_template('channels.html', channels=c_rows)


@app.route('/channel/new', methods=['GET','POST'])
def channel_new():
    c = Channel(request.form)
    c.save()
    # print('channel_new: ', c)
    return render_template('new_channel.html')


@app.route('/channel/<id>')
def channel_view(id):
    c = Channel.query.filter_by(id=id).first()
    cs = Channel.query.all()
    # print('channel view: ', c)
    plist = c.post_list()
    print('post list: ', plist)
    return render_template('channel.html', channels=cs, channel=c, posts=plist)


@app.route('/post/new', methods=['POST'])
def post_new():
    p = Post(request.form)
    p.save()
    # print('post_new: ', p)
    cid = p.channel_id
    # print('Post_new channel_id', cid)
    return redirect(url_for('channel_view', id=cid))

@app.route('/post/<id>')
def post_view(id):
    p = Post.query.filter_by(id=id).first()
    return render_template('post.html', post=p)


if __name__ == '__main__':
    host = '0.0.0.0'
    app.run(host=host, debug=True)
