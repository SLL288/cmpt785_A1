from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin, login_required, current_user
import uuid
import logging
from forms import *
from flask_wtf.csrf import generate_csrf

# Configure application
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SECURITY_PASSWORD_SALT'] = 'your_password_salt_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # timeout after 1 hour
db = SQLAlchemy(app)
logging.basicConfig(filename='app.log', level=logging.INFO) # logs

# Define models
roles_users = db.Table('roles_users',
    db.Column('user_id', db.String(36), db.ForeignKey('user.id')),
    db.Column('role_id', db.String(36), db.ForeignKey('role.id'))
)

class Role(db.Model, RoleMixin):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

class User(db.Model, UserMixin):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(255), unique=True) 
    password = db.Column(db.String(255))
    fs_uniquifier = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))

# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

# Security headers
@app.after_request
def apply_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff" # prevents MIME type sniffing
    response.headers["X-Frame-Options"] = "SAMEORIGIN" # prevents clickjacking
    response.headers["X-XSS-Protection"] = "1; mode=block" #protect against XSS attacks
    response.headers["Content-Security-Policy"] = "default-src 'self'" # restricts the sources from which content can be loaded
    return response

# csrf_token generation
@app.route('/csrf_token', methods=['GET'])
def csrf_token():
    token = generate_csrf()
    return jsonify(csrf_token=token)
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    form = RegistrationForm(data=data)
    if form.validate():
        username = form.data['username']
        password = form.data['password']
        if User.query.filter_by(username=username).first():
            logging.warning(f'Registration attempt with existing username: {username}')
            return jsonify(error='Username already exists'), 400
        user_datastore.create_user(username=username, password=password, roles=['user'])
        db.session.commit()
        logging.info(f'User registered: {username}')
        return '', 201
    return jsonify(error=form.errors), 400


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    form = LoginForm(data=data)
    if form.validate():
        username = form.data['username']
        password = form.data['password']
        user = User.query.filter_by(username=username).first()
        if user and user_datastore.verify_password(password, user.password):
            user_datastore.commit()
            logging.info(f'User logged in: {username}')
            return '', 200
        logging.warning(f'Invalid login attempt: {username}')
        return jsonify(error='Invalid credentials'), 401
    return jsonify(error=form.errors), 400


@app.route('/changepw', methods=['POST'])
@login_required
def changepw():
    data = request.get_json()
    form = ChangePasswordForm(data=data)
    if form.validate():
        old_password = form.data['old_password']
        new_password = form.data['new_password']
        if user_datastore.verify_password(old_password, current_user.password):
            current_user.password = user_datastore.hash_password(new_password)
            db.session.commit()
            logging.info(f'Password changed for user: {current_user.username}')
            return '', 201
        logging.warning(f'Incorrect password change attempt by user: {current_user.username}')
        return jsonify(error='Incorrect old password'), 400
    return jsonify(error=form.errors), 400

@app.route('/admin', methods=['GET'])
@login_required
def admin():
    if current_user.has_role('admin'):
        logging.info(f'Admin access by user: {current_user.username}')
        return f'Logged in as admin {current_user.username}'
    logging.warning(f'Unauthorized admin access attempt by user: {current_user.username}')
    return jsonify(error='Unauthorized'), 403

@app.route('/user', methods=['GET'])
@login_required
def user():
    logging.info(f'User access: {current_user.username}')
    return f'Logged in as user {current_user.username}'

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not Role.query.filter_by(name='admin').first():
            user_datastore.create_role(name='admin')
        if not Role.query.filter_by(name='user').first():
            user_datastore.create_role(name='user')
        if not User.query.filter_by(username='admin').first():
            user_datastore.create_user(username='admin', password='admin123', roles=['admin'])
            db.session.commit()
    app.run(ssl_context='adhoc')
