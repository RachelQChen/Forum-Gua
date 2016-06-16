from flask import Flask
from flask import render_template
from flask import redirect
from flask import url_for
from flask import request

from models import Problem

app = Flask(__name__)


@app.route('/')
def index():
    return redirect(url_for('problem'))


@app.route('/problem/list')
def problems():
    problem_list = Problem.query.all()
    return render_template('problems.html', problems=problem_list)


@app.route('/problem')
def problem():
    return render_template('new_problem.html')


@app.route('/problem/new', methods=['POST'])
def problem_new():
    p = Problem(request.form)
    p.save()
    return redirect(url_for('problem'))


if __name__ == '__main__':
    host = '0.0.0.0'
    app.run(host=host, debug=True)


