from flask import Flask
from flask import render_template
from flask import redirect
from flask import url_for
from flask import request

from models import Channel

app = Flask(__name__)


@app.route('/')
def index():
    return redirect(url_for('channels'))


@app.route('/channel/list')
def channels():
    channel_list = Channel.query.all()
    return render_template('channels.html', channels=channel_list)


@app.route('/channel')
def channel_view():
    return render_template('new_channel.html')


@app.route('/channel/new', methods=['POST'])
def channel_new():
    c = Channel(request.form)
    c.save()
    return redirect(url_for('channel_view'))


if __name__ == '__main__':
    host = '0.0.0.0'
    app.run(host=host, debug=True)


