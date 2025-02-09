from flask import Flask, request, jsonify
from flask_cors import CORS
import pymysql
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps
import random
import smtplib
from email.mime.text import MIMEText
# import requests
import base64
import binascii




app = Flask(__name__)

# Enable CORS for specific origins
CORS(app, resources={
    r"/*": {
        "origins": [
            "http://localhost:3000",
            "http://localhost:3001",
            "https://localhost:3000",
            "https://localhost:3001",
            "https://bank-dash-gilt.vercel.app"
        ]
    }
})

# Database connection details
app.config['DB_HOST'] = 'Adeniran1234.mysql.pythonanywhere-services.com'
app.config['DB_USER'] = 'Adeniran1234'
app.config['DB_PASSWORD'] = 'BankDash**#'
app.config['DB_NAME'] = 'Adeniran1234$BankDash'


def get_db_connection():
    return pymysql.connect(
        host=app.config['DB_HOST'],
        user=app.config['DB_USER'],
        password=app.config['DB_PASSWORD'],
        database=app.config['DB_NAME'],
        cursorclass=pymysql.cursors.DictCursor
    )

# # JWT secret key
app.config['SECRET_KEY'] = 'nKZPu_k0A8Seh4sejPLCvoDZSB7gVwW9vdixckx7Skk'





def send_email(to_email, subject, body):
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    # sender_email = 'adisaayangbemi@gmail.com'
    # sender_password = 'olpz xdyo usnv mkrk'     nhta zxnx xdas bngl


    sender_email = 'ndiyoedward@gmail.com'
    sender_password = 'nhta zxnx xdas bngl'

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = to_email

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
        server.quit()
    except Exception as e:
        print(f"Failed to send email: {e}")


# # EmailJS configuration
# SERVICE_ID = 'service_bp0q1ia'
# TEMPLATE_ID = 'template_3q14v5o'
# PUBLIC_KEY = 'wuZcGoWkyG-Tg3bPz'

# def send_email(to_email, otp):
#     """
#     Sends an email using EmailJS API with the OTP.
#     """
#     url = "https://api.emailjs.com/api/v1.0/email/send"

#     payload = {
#         "service_id": SERVICE_ID,
#         "template_id": TEMPLATE_ID,
#         "user_id": PUBLIC_KEY,
#         "template_params": {
#             "to_email": to_email,
#             "otp": otp
#         }
#     }

#     headers = {"Content-Type": "application/json"}

#     try:
#         response = requests.post(url, json=payload, headers=headers)

#         print("Payload sent:", payload)  # Log payload
#         print("Response text:", response.text)  # Log API response

#         if response.status_code == 200:
#             print("Email sent successfully!")
#         else:
#             print(f"Failed to send email: {response.status_code}")
#             print(response.text)  # Log detailed error message
#     except Exception as e:
#         print(f"Error while sending email: {e}")





@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')

    connection = get_db_connection()
    with connection.cursor() as cursor:
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

    if not user:
        connection.close()
        return jsonify({'message': 'Email not found!'}), 404

    # Generate OTP
    otp = str(random.randint(100000, 999999))
    timestamp = datetime.now()

    with connection.cursor() as cursor:
        cursor.execute("""
            INSERT INTO otps (email, otp, timestamp)
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE
            otp = VALUES(otp), timestamp = VALUES(timestamp)
        """, (email, otp, timestamp))
    connection.commit()
    connection.close()

    # Send OTP to user's email
    send_email(email, "Password Reset OTP", f"Your OTP is: {otp}")
    return jsonify({'message': 'OTP sent to your email!'}), 200

#  # Send OTP to user's email
#     send_email(email, otp)
    # return jsonify({'message': 'OTP sent to your email!'}), 200

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')

    connection = get_db_connection()
    with connection.cursor() as cursor:
        cursor.execute("SELECT otp, timestamp FROM otps WHERE email = %s", (email,))
        record = cursor.fetchone()

    if not record:
        connection.close()
        return jsonify({'message': 'No OTP request found for this email!'}), 400

    otp_age = (datetime.now() - record['timestamp']).total_seconds() / 60  # Age in minutes

    if otp_age > 5:  # OTP expired
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM otps WHERE email = %s", (email,))
        connection.commit()
        connection.close()
        return jsonify({'message': 'OTP has expired!'}), 400

    if record['otp'] == otp:

        return jsonify({'message': 'OTP verified!'}), 200

    connection.close()
    return jsonify({'message': 'Invalid OTP!'}), 400

@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')
    new_password = data.get('new_password')

    connection = get_db_connection()
    with connection.cursor() as cursor:
        cursor.execute("SELECT otp FROM otps WHERE email = %s", (email,))
        record = cursor.fetchone()

    if not record or record['otp'] != otp:
        connection.close()
        return jsonify({'message': 'Invalid or expired OTP!'}), 400

    hashed_password = generate_password_hash(new_password)
    with connection.cursor() as cursor:
        cursor.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_password, email))
        cursor.execute("DELETE FROM otps WHERE email = %s", (email,))
    connection.commit()
    connection.close()

    return jsonify({'message': 'Password reset successfully!'}), 200



# @app.route('/signup', methods=['POST'])
# def signup():
#     data = request.get_json()
#     first_name = data['first_name']
#     last_name = data['last_name']
#     email = data['email']
#     house_address = data['house_address']
#     phone_number = data['phone_number']
#     username = data['username']
#     date_of_birth = data['date_of_birth']
#     present_address = data['present_address']
#     city = data['city']
#     postal_code = data['postal_code']
#     country = data['country']
#     password = generate_password_hash(data['password'])

#     connection = get_db_connection()
#     try:
#         with connection.cursor() as cursor:
#             cursor.execute("""
#                 INSERT INTO users
#                 (first_name, last_name, email, house_address, phone_number, username, date_of_birth,
#                  present_address, city, postal_code, country, password)
#                 VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
#             """, (first_name, last_name, email, house_address, phone_number, username, date_of_birth,
#                   present_address, city, postal_code, country, password))
#         connection.commit()
#     except pymysql.IntegrityError:
#         return jsonify({'message': 'Email or username already registered!'}), 400
#     finally:
#         connection.close()

#     return jsonify({'message': 'User registered successfully!'}), 201



def generate_unique_account_number(cursor):
    while True:
        account_number = str(random.randint(1000000000, 9999999999))  # Generate 10-digit number
        cursor.execute("SELECT COUNT(*) FROM users WHERE account_number = %s", (account_number,))
        if cursor.fetchone()[0] == 0:
            return account_number  # Ensure it's unique

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    first_name = data['first_name']
    last_name = data['last_name']
    email = data['email']
    house_address = data['house_address']
    phone_number = data['phone_number']
    username = data['username']
    date_of_birth = data['date_of_birth']
    present_address = data['present_address']
    city = data['city']
    postal_code = data['postal_code']
    country = data['country']
    password = generate_password_hash(data['password'])

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            # Generate unique account number
            account_number = generate_unique_account_number(cursor)
            balance = 5000  # Default balance

            cursor.execute("""
                INSERT INTO users
                (first_name, last_name, email, house_address, phone_number, username, date_of_birth,
                 present_address, city, postal_code, country, password, account_number, balance)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (first_name, last_name, email, house_address, phone_number, username, date_of_birth,
                  present_address, city, postal_code, country, password, account_number, balance))

        connection.commit()
    except pymysql.IntegrityError:
        return jsonify({'message': 'Email or username already registered!'}), 400
    finally:
        connection.close()

    return jsonify({'message': 'User registered successfully!', 'account_number': account_number}), 201






def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            # Extract token after "Bearer "
            token = token.split()[1] if ' ' in token else token
            decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])

            # Extract user ID and username
            current_user_id = decoded.get('sub')  # Keeps user ID under 'sub' for backward compatibility
            current_username = decoded.get('username')  # Adds new username field

            if not current_user_id or not current_username:
                return jsonify({'message': 'Invalid token payload!'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401

        # Pass both the current user ID and username to the decorated function
        return f(current_user_id, current_username, *args, **kwargs)
    return decorated

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required!'}), 400

    connection = get_db_connection()
    try:
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("SELECT id, username, password FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
    finally:
        connection.close()

    if user and check_password_hash(user['password'], password):
        # Generate JWT token with both ID (as 'sub') and username
        token = jwt.encode(
            {
                'sub': str(user['id']),  # Keep ID as 'sub' for existing implementations
                'username': user['username'],  # New field for username-based features
                'exp': datetime.utcnow() + timedelta(hours=24)  # Token expiration
            },
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )
        return jsonify({'message': 'Login successful!', 'token': token}), 200

    return jsonify({'message': 'Invalid credentials!'}), 401


# def token_required(f):
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         token = request.headers.get('Authorization')
#         if not token:
#             return jsonify({'message': 'Token is missing!'}), 401

#         try:
#             # Extract token after "Bearer "
#             token = token.split()[1] if ' ' in token else token
#             decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
#             current_user_id = decoded.get('sub')  # Extract user ID from 'sub'
#             if not current_user_id:
#                 return jsonify({'message': 'Invalid token payload!'}), 401
#         except jwt.ExpiredSignatureError:
#             return jsonify({'message': 'Token has expired!'}), 401
#         except jwt.InvalidTokenError:
#             return jsonify({'message': 'Invalid token!'}), 401

#         # Pass the current user ID to the decorated function
#         return f(current_user_id, *args, **kwargs)
#     return decorated


# @app.route('/login', methods=['POST'])
# def login():
#     data = request.get_json()
#     email = data.get('email')
#     password = data.get('password')

#     if not email or not password:
#         return jsonify({'message': 'Email and password are required!'}), 400

#     connection = get_db_connection()
#     try:
#         with connection.cursor() as cursor:
#             cursor.execute("SELECT id, password FROM users WHERE email = %s", (email,))
#             user = cursor.fetchone()
#     finally:
#         connection.close()

#     if user and check_password_hash(user['password'], password):
#         # Generate JWT token with user ID in 'sub'
        # token = jwt.encode(
        #     {
        #         'sub': str(user['id']),  # Store user ID as a string
        #         'exp': datetime.utcnow() + timedelta(hours=24)  # Token expiration
        #     },
#             app.config['SECRET_KEY'],
#             algorithm='HS256'
#         )
#         return jsonify({'message': 'Login successful!', 'token': token}), 200

#     return jsonify({'message': 'Invalid credentials!'}), 401

@app.route('/user', methods=['GET'])
@token_required
def get_user(current_user_id):
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT id, first_name, last_name, email, house_address, phone_number, username,
                       date_of_birth, present_address, city, postal_code, country, profile_image
                FROM users
                WHERE id = %s
            """, (current_user_id,))
            user = cursor.fetchone()

        if not user:
            return jsonify({'message': 'User not found!'}), 404

        # Prepare user data and encode profile image to base64
        user_data = {
            'id': user['id'],
            'first_name': user['first_name'],
            'last_name': user['last_name'],
            'email': user['email'],
            'house_address': user['house_address'],
            'phone_number': user['phone_number'],
            'username': user['username'],
            'date_of_birth': user['date_of_birth'],
            'present_address': user['present_address'],
            'city': user['city'],
            'postal_code': user['postal_code'],
            'country': user['country'],
            # Convert binary profile_image to base64 string for JSON response
            'profile_image': base64.b64encode(user['profile_image']).decode('utf-8') if user['profile_image'] else None
        }
        return jsonify(user_data), 200
    finally:
        connection.close()




@app.route('/user', methods=['PUT'])
@token_required
def update_user(current_user_id):
    data = request.get_json()
    connection = get_db_connection()

    # Extract data from the request
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    email = data.get('email')
    house_address = data.get('house_address')
    phone_number = data.get('phone_number')
    username = data.get('username')
    date_of_birth = data.get('date_of_birth')
    present_address = data.get('present_address')
    city = data.get('city')
    postal_code = data.get('postal_code')
    country = data.get('country')
    profile_image = data.get('profile_image')  # Expecting a base64-encoded string

    # Decode base64 profile image to binary if provided
    profile_image_binary = None
    if profile_image:
        try:
            # Normalize the base64 string (add missing padding if needed)
            profile_image = profile_image + '=' * (4 - len(profile_image) % 4)
            profile_image_binary = base64.b64decode(profile_image)
        except (binascii.Error, ValueError) as e:
            return jsonify({'message': 'Invalid base64 profile image format', 'error': str(e)}), 400

    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                UPDATE users
                SET
                    first_name = COALESCE(%s, first_name),
                    last_name = COALESCE(%s, last_name),
                    email = COALESCE(%s, email),
                    house_address = COALESCE(%s, house_address),
                    phone_number = COALESCE(%s, phone_number),
                    username = COALESCE(%s, username),
                    date_of_birth = COALESCE(%s, date_of_birth),
                    present_address = COALESCE(%s, present_address),
                    city = COALESCE(%s, city),
                    postal_code = COALESCE(%s, postal_code),
                    country = COALESCE(%s, country),
                    profile_image = COALESCE(%s, profile_image)
                WHERE id = %s
            """, (first_name, last_name, email, house_address, phone_number, username,
                  date_of_birth, present_address, city, postal_code, country,
                  profile_image_binary, current_user_id))
        connection.commit()

        return jsonify({'message': 'User details updated successfully!'}), 200
    except Exception as e:
        return jsonify({'message': f'Failed to update user details: {str(e)}'}), 400
    finally:
        connection.close()

# fetching user details in dashboard router -
@app.route('/dashboard', methods=['GET'])
@token_required
def get_account_details(current_user_id):
    connection = get_db_connection()
    try:
        with connection.cursor(dictionary=True) as cursor:
            cursor.execute("""
                SELECT account_number, balance
                FROM users
                WHERE id = %s
            """, (current_user_id,))
            user_data = cursor.fetchone()

        if not user_data:
            return jsonify({'message': 'User not found'}), 404

        return jsonify({
            'account_number': user_data['account_number'],
            'balance': float(user_data['balance'])
        }), 200
    except Exception as e:
        return jsonify({'message': f'Error fetching account details: {str(e)}'}), 500
    finally:
        connection.close()



        # transfers route -


# @app.route('/transfer', methods=['POST'])
# def transfer_money():
#     data = request.get_json()
#     sender_username = data['sender_username']
#     receiver_username = data['receiver_username']
#     amount = float(data['amount'])  # Convert to float for decimal handling
#     remark = data.get('remark', '')

#     # Ensure valid amount
#     if amount <= 0:
#         return jsonify({'message': 'Invalid amount'}), 400

#     connection = get_db_connection()
#     try:
#         with connection.cursor() as cursor:
#             # Get sender's balance
#             cursor.execute("SELECT balance FROM users WHERE username = %s", (sender_username,))
#             sender_data = cursor.fetchone()
#             if not sender_data:
#                 return jsonify({'message': 'Sender does not exist'}), 404

#             sender_balance = sender_data[0]
#             if sender_balance < amount:
#                 return jsonify({'message': 'Insufficient balance'}), 400

#             # Get recipient
#             cursor.execute("SELECT balance FROM users WHERE username = %s", (receiver_username,))
#             receiver_data = cursor.fetchone()
#             if not receiver_data:
#                 return jsonify({'message': 'Recipient does not exist'}), 404

#             # Perform transaction atomically
#             cursor.execute("UPDATE users SET balance = balance - %s WHERE username = %s", (amount, sender_username))
#             cursor.execute("UPDATE users SET balance = balance + %s WHERE username = %s", (amount, receiver_username))

#             # Insert transaction record
#             cursor.execute("""
#                 INSERT INTO transactions (sender_username, receiver_username, amount, remark)
#                 VALUES (%s, %s, %s, %s)
#             """, (sender_username, receiver_username, amount, remark))

#         connection.commit()
#     except Exception as e:
#         connection.rollback()  # Rollback in case of failure
#         return jsonify({'message': 'Transaction failed', 'error': str(e)}), 500
#     finally:
#         connection.close()

#     return jsonify({'message': 'Transfer successful!'}), 200


@app.route('/transfer', methods=['POST'])
@token_required
def transfer_money(current_user):
    data = request.get_json()
    receiver_username = data['receiver_username']
    amount = float(data['amount'])  # Convert to float for decimal handling
    remark = data.get('remark', '')

    # Ensure valid amount
    if amount <= 0:
        return jsonify({'message': 'Invalid amount'}), 400

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            # Get sender's balance
            cursor.execute("SELECT balance FROM users WHERE username = %s", (current_user,))
            sender_data = cursor.fetchone()
            if not sender_data:
                return jsonify({'message': 'Sender does not exist'}), 404

            sender_balance = sender_data[0]
            if sender_balance < amount:
                return jsonify({'message': 'Insufficient balance'}), 400

            # Get recipient
            cursor.execute("SELECT balance FROM users WHERE username = %s", (receiver_username,))
            receiver_data = cursor.fetchone()
            if not receiver_data:
                return jsonify({'message': 'Recipient does not exist'}), 404

            # Perform transaction atomically
            cursor.execute("UPDATE users SET balance = balance - %s WHERE username = %s", (amount, current_user))
            cursor.execute("UPDATE users SET balance = balance + %s WHERE username = %s", (amount, receiver_username))

            # Insert transaction record
            cursor.execute("""
                INSERT INTO transactions (sender_username, receiver_username, amount, remark)
                VALUES (%s, %s, %s, %s)
            """, (current_user, receiver_username, amount, remark))

        connection.commit()
    except Exception as e:
        connection.rollback()  # Rollback in case of failure
        return jsonify({'message': 'Transaction failed', 'error': str(e)}), 500
    finally:
        connection.close()

    return jsonify({'message': 'Transfer successful!'}), 200



# Protected route
@app.route('/protected', methods=['GET'])
@token_required
def protected(current_user_id):
    return jsonify({'message': f'Access granted! Welcome user with ID {current_user_id}.'}), 200



if __name__ == '__main__':
    app.run()
