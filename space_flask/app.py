from flask import Flask, render_template, render_template_string, request, session, redirect
import sqlite3
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

valid = ['SHOOT', 'EXPLODE', 'LEFT', 'RIGHT']
latest = []
bcrypt = Bcrypt()
#bcrypt.check_password_hash(hashed, not_hashed)
@app.route('/', methods=['POST', 'GET'])
def index():
    with open ('templates/index_logged_in.html') as f:
        string = f.read()
    if 'username' in session:
        if request.method == 'POST':
            command = request.form['command']
            if 'position' not in session:
                session['position'] = 'up'
            if (command == 'LEFT' and session['position'] == 'up') or (command == 'RIGHT' and session['position'] == 'down'):
                session['position'] = 'left'
            elif (command == 'LEFT' and session['position'] == 'left') or (command == 'RIGHT' and session['position'] == 'right'):
                session['position'] = 'down'
            elif (command == 'LEFT' and session['position'] == 'down') or (command == 'RIGHT' and session['position'] == 'up'):
                session['position'] = 'right'
            else:
                session['position'] = 'up'
            print(session['position'])
            latest.append(command)
            first = None
            if len(latest) > 10:
                first = latest.pop(0)
            response = render_template_string(string, latest=latest)
            if command in valid:
                return response
            if first:
                latest.insert(0, first)
            latest.pop(-1)
            return render_template('no_command.html')
        return render_template_string(string, latest=latest)
    if request.method == 'POST':
        conn = sqlite3.connect('space_flask.db')
        user_detail = request.form
        username = user_detail['username']
        password = user_detail['password']
        cur = conn.cursor()
        # cur = mysql.connection.cursor()
        result = cur.execute("SELECT password FROM users WHERE username=?", (username,)).fetchall()
        # print(cur.fetchone()[0])
        if len(result) > 0:
            hashed_password = result[0][0]
            print(hashed_password)
            conn.close()
            if bcrypt.check_password_hash(hashed_password, password):
                session['username'] = username
                return redirect ('/')
            return render_template('passwords_do_not_match.html')
        conn.close()
        return render_template('no_user.html')
    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        conn = sqlite3.connect('space_flask.db')
        user_detail = request.form
        username = user_detail['username']
        password = user_detail['password']
        repeat_password = user_detail['repeat_password']
        cur = conn.cursor()
        result = cur.execute(f"SELECT * FROM users WHERE username=?", (username,)).fetchall()
        if len(result) > 0:
            conn.close()
            return render_template('user_exists.html')
        if password != repeat_password:
            conn.close()
            return render_template('passwords_do_not_match.html')
        query = "INSERT INTO users (username, password) VALUES (?, ?)"
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        cur.execute(query, (username, hashed_password))
        conn.commit()
        conn.close()
        return redirect('/')
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        conn = sqlite3.connect('space_flask.db')
        user_detail = request.form
        username = user_detail['username']
        password = user_detail['password']
        cur = conn.cursor()
        # cur = mysql.connection.cursor()
        result = cur.execute("SELECT password FROM users WHERE username=?", (username,)).fetchall()
        # print(cur.fetchone()[0])
        if len(result) > 0:
            hashed_password = result[0][0]
            print(hashed_password)
            conn.close()
            if bcrypt.check_password_hash(hashed_password, password):
                session['username'] = username
                return redirect ('/')
            return render_template('passwords_do_not_match.html')
        conn.close()
        return render_template('no_user.html')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    latest.clear()
    return redirect('/')

@app.route('/commands')
def commands():
    explanations = ['Turn upwards and keep shooting until another command', 'Explode your spaceship (warning: everyone dies)', 'Turn your spaceship to the left', 'Turn your spaceship to the right']
    return render_template('commands.html', commands=valid, explanations=explanations)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5100)