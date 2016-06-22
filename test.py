import os
from flask import Flask, request, redirect, url_for
from werkzeug import secure_filename

UPLOAD_FOLDER = '/tmp'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        print('upload request.file: ', file)
        if file and allowed_file(file.filename):
            print('filename: ', file.filename)
            filename = secure_filename(file.filename)
            print('secure_filename: ', filename)
            save = file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            print('save file: ', save)
            url = url_for('uploaded_file', filename=filename)
            print('saved url: ', url)
            return redirect(url_for('uploaded_file',
                                    filename=filename))
    return '''
    <!doctype html>
    <title>Upload new File</title>
    <h1>Upload new File</h1>
    <form action="" method=post enctype=multipart/form-data>
      <p><input type=file name=file>
         <input type=submit value=Upload>
    </form>
    '''

from flask import send_from_directory

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    file = send_from_directory(app.config['UPLOAD_FOLDER'],
                               filename)
    print('uploaded_file: ', file)

    return file


if __name__ == '__main__':
    app.run(debug=True)