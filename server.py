from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this to a random secret key
db = SQLAlchemy(app)

# Define the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(10), default='user')

# Create tables
with app.app_context():
    db.create_all()

@app.route('/showall', methods=['GET'])
def showall():
    # data = request.get_json()
    # return f'{request.form.to_dict()}'
    result = []
    user = User.query.all()
    # return f'{user.form.to_dict()}'

    for i in user:
        # return f'{i.username}'
        try:
            print(f'username: {i.username}, pwd: {i.password}')
            # return f'{i.password}'
            # resutl += "\n"
            result += [f"ID: {i.id}, username: {i.username}, password: {i.password}, role: {i.role}"]
        except:
            None
    # username = request.cookies.get
    return result
    user = User.query.filter_by(username="shaolun").first()
    # f'username'
    # print("abc")
    # return f'{user.password}'
    # return f'uesrname: {user.username} \n password: {user.password} \n role: {user.role}'
    # return User.query.all()


# Helper function to get the current user based on the session cookie
def get_current_user():
    username = request.cookies.get('username')
    return User.query.filter_by(username=username).first()

# API to register a new user
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    # Input validation
    if 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Username and password are required'}), 400

    # Check if the username is already taken
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username is already taken'}), 400

    # Create a new user
    new_user = User(username=data['username'], password=generate_password_hash(data['password'], method='sha256'))
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201

# API to login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    # Input validation
    if 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Username and password are required'}), 400

    # Check if the user exists
    user = User.query.filter_by(username=data['username']).first()
    if user and check_password_hash(user.password, data['password']):
        response = make_response(jsonify({'message': 'Login successful'}), 200)
        response.set_cookie('username', user.username)
        return response
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

# API to change password
@app.route('/changepw', methods=['POST'])
def changepw():
    data = request.get_json()

    # Input validation
    if 'username' not in data or 'old_password' not in data or 'new_password' not in data:
        return jsonify({'error': 'Username, old_password, and new_password are required'}), 400

    # Check if the user exists
    user = User.query.filter_by(username=data['username']).first()
    if user and check_password_hash(user.password, data['old_password']):
        user.password = generate_password_hash(data['new_password'], method='sha256')
        db.session.commit()
        return jsonify({'message': 'Password changed successfully'}), 201
    else:
        return jsonify({'error': 'Invalid credentials'}), 400

# API for admin
@app.route('/admin', methods=['GET'])
def admin():
    user = get_current_user()

    # Role-based authorization
    if user and user.role == 'admin':
        return f'Logged in as admin {user.username}'
    else:
        return jsonify({'error': 'Unauthorized failed to use /admin GET method'}), 401

# API for user
@app.route('/user', methods=['GET'])
def user():
    user = get_current_user()

    # Role-based authorization
    if user:
        return f'Logged in as user {user.username}'
    else:
        return jsonify({'error': 'Unauthorized'}), 401

if __name__ == '__main__':
    app.run(debug=True)

