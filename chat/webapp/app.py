# -*- coding: utf-8 -*-
# ==============================================================================
# Copyright (c) 2024 Xavier de Carné de Carnavalet
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 
# 3. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# ==============================================================================

import os
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort, flash
from flask_mysqldb import MySQL
from flask_session import Session
import yaml
import pyotp
import pyqrcode
import io
import base64
import bcrypt
from PIL import Image, ImageDraw, ImageFont
import io
import base64
import datetime

def generate_otp_key_n_qr(username):
    secretKey = pyotp.random_base32()
    uri = pyotp.totp.TOTP(secretKey).provisioning_uri(name=username, issuer_name="E2EE Chat WebApp")
    qrCodeC = pyqrcode.create(uri)
    s = io.BytesIO()
    qrCodeC.png(s,scale=6)
    toptQrCodeEncoded = base64.b64encode(s.getvalue()).decode("ascii")
    
    return secretKey, toptQrCodeEncoded

def verify_otp(secretKey, otp):
    totp = pyotp.TOTP(secretKey)

    if totp.verify(otp):
        return True
    else:
        return False

def passwordHashing(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

app = Flask(__name__)

# Configure secret key and Flask-Session
app.config['SECRET_KEY'] = 'qwer1234'
app.config['SESSION_TYPE'] = 'filesystem'  # Options: 'filesystem', 'redis', 'memcached', etc.
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True  # To sign session cookies for extra security
app.config['SESSION_FILE_DIR'] = './sessions'  # Needed if using filesystem type

# Load database configuration from db.yaml or configure directly here
db_config = yaml.load(open('db.yaml'), Loader=yaml.FullLoader)
app.config['MYSQL_HOST'] = db_config['mysql_host']
app.config['MYSQL_USER'] = db_config['mysql_user']
app.config['MYSQL_PASSWORD'] = db_config['mysql_password']
app.config['MYSQL_DB'] = db_config['mysql_db']

mysql = MySQL(app)

# Initialize the Flask-Session
Session(app)

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    sender_id = session['user_id']
    return render_template('chat.html', sender_id=sender_id)

@app.route('/users')
def users():
    if 'user_id' not in session:
        abort(403)

    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id, username FROM users")
    user_data = cur.fetchall()
    cur.close()

    filtered_users = [[user[0], user[1]] for user in user_data if user[0] != session['user_id']]
    return {'users': filtered_users}

@app.route('/fetch_messages')
def fetch_messages():
    if 'user_id' not in session:
        abort(403)

    last_message_id = request.args.get('last_message_id', 0, type=int)
    peer_id = request.args.get('peer_id', type=int)
    
    cur = mysql.connection.cursor()
    query = """SELECT message_id,sender_id,receiver_id,message_text,iv,hmac FROM messages 
               WHERE message_id > %s AND 
               ((sender_id = %s AND receiver_id = %s) OR (sender_id = %s AND receiver_id = %s))
               ORDER BY message_id ASC"""
    cur.execute(query, (last_message_id, peer_id, session['user_id'], session['user_id'], peer_id))

    # Fetch the column names
    column_names = [desc[0] for desc in cur.description]
    # Fetch all rows, and create a list of dictionaries, each representing a message
    messages = [dict(zip(column_names, row)) for row in cur.fetchall()]

    cur.close()
    return jsonify({'messages': messages})

# Generate a captcha
def generate_captcha():
    captcha_text = os.urandom(3).hex().upper()
    captcha_id = os.urandom(5).hex().upper()

    # Generate captcha
    img = Image.new('RGB', (160, 60), color='white')
    draw = ImageDraw.Draw(img)
    font = ImageFont.load_default()
    draw.text((10, 10), captcha_text, fill='black', font=font)
    
    # Save the base64 encode image database to database
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    captcha_img_data = base64.b64encode(buffer.getvalue()).decode()

    cur = mysql.connection.cursor()
    cur.execute('INSERT INTO captchas (captcha_id, captcha_text) VALUES (%s, %s)', (captcha_id, captcha_text))
    mysql.connection.commit()
    cur.close()
    
    return captcha_id, captcha_img_data
    
# Validate a captcha
def validate_captcha(captcha_id, user_input):
    cur = mysql.connection.cursor()
    cur.execute("SELECT captcha_text, created_at FROM captchas WHERE captcha_id = %s", (captcha_id,))
    captcha_record = cur.fetchone()
    cur.close()

    if captcha_record:
        captcha_text, created_at = captcha_record
        if datetime.datetime.now() - created_at > datetime.timedelta(minutes=5):
            return False
        if captcha_text == user_input:
            cur = mysql.connection.cursor()
            cur.execute("DELETE FROM captchas WHERE captcha_id = %s", (captcha_id,))
            mysql.connection.commit()
            cur.close()
            return True
    return False

def contains_sqli_attempt(input_string):
    SQLI_BLACKLIST = ["'", '"', ";", "--", "/*", "*/", "=", "%"]
    return any(char in input_string for char in SQLI_BLACKLIST)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    captcha_id, captcha_img_data = generate_captcha()
    if request.method == 'POST':
        captcha_id_form = request.form['captcha_id']
        captcha_input = request.form['captcha']
        userDetails = request.form
        username = userDetails['username']
        password = userDetails['password']
        otp = userDetails['otp']

        if any(contains_sqli_attempt(field) for field in [captcha_input, username, password, otp]):
            error = 'Invalid input detected'
            captcha_id, captcha_img_data = generate_captcha()
            return render_template('login.html', error=error, captcha_id=captcha_id, captcha_img_data=captcha_img_data)
        
        if not validate_captcha(captcha_id_form, captcha_input):
            error = 'Invalid captcha'
            captcha_id, captcha_img_data = generate_captcha()
            return render_template('login.html', error=error, captcha_id=captcha_id, captcha_img_data=captcha_img_data)

        cur = mysql.connection.cursor()
        cur.execute("SELECT user_id, password, mfa_secret FROM users WHERE username=%s AND mfa_enabled=TRUE", (username,))
        account = cur.fetchone()
        if account:
            session['username'] = username
            session['user_id'] = account[0]
            hashed = account[1]
            mfa_secret = account[2]
            if bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8')) and verify_otp(mfa_secret, otp):
                return redirect(url_for('index'))
            else:
                error = 'Invalid OTP or password'
        else:
            error = 'Invalid credentials'

    return render_template('login.html', error=error, captcha_id=captcha_id, captcha_img_data=captcha_img_data)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    captcha_id, captcha_img_data = generate_captcha()
    if request.method == 'POST':
        captcha_id_form = request.form['captcha_id']
        captcha_input = request.form['captcha']
        if not validate_captcha(captcha_id_form, captcha_input):
            error = 'Invalid captcha'
            captcha_id, captcha_img_data = generate_captcha()
            return render_template('signup.html', error=error, captcha_id=captcha_id, captcha_img_data=captcha_img_data)
        
        userDetails = request.form
        username = userDetails['username']
        password = userDetails['password']
        re_enter_password = userDetails['re-enter-password']

        if any(contains_sqli_attempt(field) for field in [captcha_input, username, password, re_enter_password]):
            error = 'Invalid input detected'
            captcha_id, captcha_img_data = generate_captcha()
            return render_template('signup.html', error=error, captcha_id=captcha_id, captcha_img_data=captcha_img_data)
        
        if password != re_enter_password:
            error = 'Passwords do not match'
            captcha_id, captcha_img_data = generate_captcha()
            return render_template('signup.html', error=error, captcha_id=captcha_id, captcha_img_data=captcha_img_data)
        
        if len(password) < 8:
            error = 'Password is less than 8 letters or digital'
            captcha_id, captcha_img_data = generate_captcha()
            return render_template('signup.html', error=error, captcha_id=captcha_id, captcha_img_data=captcha_img_data)

        cur = mysql.connection.cursor()
        hashedPassword = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        try:
            secretKey, qrCodeImg = generate_otp_key_n_qr(username)

            cur.execute("INSERT INTO users (username, password, mfa_secret) VALUES (%s, %s, %s)", (username, hashedPassword, secretKey, ))
            mysql.connection.commit()
            session['username'] = username
            session['qrCodeImg'] = qrCodeImg
            session['secretKey'] = secretKey
            return redirect(url_for('add_otp'))
        except Exception as e:
            error = str(e)
        finally:
            cur.close()

    return render_template('signup.html', error=error, captcha_id=captcha_id, captcha_img_data=captcha_img_data)


@app.route('/add_otp', methods=['GET', 'POST'])
def add_otp():
    error = None
    username = session.get('username')
    qrCodeImg = session.get('qrCodeImg')
    secretKey = session.get('secretKey')

    if request.method == 'POST':
        cur = mysql.connection.cursor()

        try:
            otp = request.form['otp']
            if verify_otp(secretKey, otp):
                cur.execute("UPDATE users SET mfa_enabled=TRUE WHERE username=%s", (username,))
                mysql.connection.commit()
                return redirect(url_for('login'))
            else:
                error = 'Invalid OTP'
        except Exception as e:
            error = 'Error adding OTP'
        finally:
            cur.close()

    return render_template('add_otp.html', username=username, qrCodeImg=qrCodeImg, secretKey=secretKey, error=error)

@app.route('/send_message', methods=['POST'])
def send_message():
    if not request.json or not 'message_text' in request.json:
        abort(400)  # Bad request if the request doesn't contain JSON or lacks 'message_text'
    if 'user_id' not in session:
        abort(403)

    # Extract data from the request
    sender_id = session['user_id']
    receiver_id = request.json['receiver_id']
    message_text = request.json['message_text']
    iv = request.json['iv']
    hmac = request.json['hmac']

    # Assuming you have a function to save messages
    save_message(sender_id, receiver_id, message_text, iv, hmac)
    
    return jsonify({'status': 'success', 'message': 'Message sent'}), 200

def save_message(sender, receiver, message, iv, hmac):
    cur = mysql.connection.cursor()

    cur.execute("""
        INSERT INTO messages (sender_id, receiver_id, message_text, iv, hmac) 
        VALUES (%s, %s, %s, %s, %s)
        """, (sender, receiver, message, iv, hmac))
    mysql.connection.commit()
    cur.close()

@app.route('/erase_chat', methods=['POST'])
def erase_chat():
    if 'user_id' not in session:
        abort(403)

    peer_id = request.json['peer_id']
    cur = mysql.connection.cursor()
    query = "DELETE FROM messages WHERE ((sender_id = %s AND receiver_id = %s) OR (sender_id = %s AND receiver_id = %s))"
    cur.execute(query, (peer_id, session['user_id'], session['user_id'], peer_id))
    mysql.connection.commit()

    # Check if the operation was successful by evaluating affected rows
    if cur.rowcount > 0:
        return jsonify({'status': 'success'}), 200
    else:
        return jsonify({'status': 'failure'}), 200

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been successfully logged out.', 'info')  # Flash a logout success message
    return redirect(url_for('index'))

@app.route('/send_public_key', methods=['POST'])
def send_public_key():
    if 'user_id' not in session:
        abort(403)

    user_id = session['user_id']
    public_key = request.json.get('public_key')
    
    if not public_key:
        return jsonify({'status': 'failure', 'message': 'No public key provided'}), 400

    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT COUNT(*) FROM public_keys_exchange WHERE user_id = %s", (user_id,))
        exists = cur.fetchone()[0] > 0

        if exists:
            cur.execute("UPDATE public_keys_exchange SET public_key = %s WHERE user_id = %s", (public_key, user_id))
        else:
            cur.execute("INSERT INTO public_keys_exchange (user_id, public_key) VALUES (%s, %s)", (user_id, public_key))
        
        mysql.connection.commit()
        return jsonify({'status': 'success', 'message': 'Public key uploaded successfully'}), 200
    except Exception as e:
        return jsonify({'status': 'failure', 'message': 'Failed to upload public key: ' + str(e)}), 500
    finally:
        cur.close()

@app.route('/receive_public_key/<int:user_id>', methods=['GET'])
def receive_public_key(user_id):
    if 'user_id' not in session:
        abort(403)

    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT public_key FROM public_keys_exchange WHERE user_id = %s", (user_id,))
        row = cur.fetchone()
        
        if row:
            return jsonify({'status': 'success', 'public_key': row[0]}), 200
        else:
            return jsonify({'status': 'failure', 'message': 'Public key not found'}), 404
    except Exception as e:
        return jsonify({'status': 'failure', 'message': 'Failed to fetch public key'}), 500
    finally:
        cur.close()

@app.route('/send_salt', methods=['POST'])
def send_salt():
    if 'user_id' not in session:
        abort(403)

    user_id = session['user_id']
    salt = request.json.get('salt')
    
    if not salt:
        return jsonify({'status': 'failure', 'message': 'No salt provided'}), 400

    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT COUNT(*) FROM salt_exchange WHERE user_id = %s", (user_id,))
        exists = cur.fetchone()[0] > 0

        if exists:
            cur.execute("UPDATE salt_exchange SET salt = %s WHERE user_id = %s", (salt, user_id))
        else:
            cur.execute("INSERT INTO salt_exchange (user_id, salt) VALUES (%s, %s)", (user_id, salt))
        
        mysql.connection.commit()
        return jsonify({'status': 'success', 'message': 'salt uploaded successfully'}), 200
    except Exception as e:
        return jsonify({'status': 'failure', 'message': 'Failed to upload salt: ' + str(e)}), 500
    finally:
        cur.close()

@app.route('/receive_salt/<int:user_id>', methods=['GET'])
def receive_salt(user_id):
    if 'user_id' not in session:
        abort(403)

    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT salt FROM salt_exchange WHERE user_id = %s", (user_id,))
        row = cur.fetchone()
        
        if row:
            return jsonify({'status': 'success', 'salt': row[0]}), 200
        else:
            return jsonify({'status': 'failure', 'message': 'salt not found'}), 404
    except Exception as e:
        return jsonify({'status': 'failure', 'message': 'Failed to fetch salt'}), 500
    finally:
        cur.close()


if __name__ == '__main__':
    app.run(debug=True)

