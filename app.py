from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin, login_required, current_user
import uuid

# Configure application
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SECURITY_PASSWORD_SALT'] = 'your_password_salt_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
db = SQLAlchemy(app)

# Define models
roles_users = db.Table('roles_users',
    db.Column('user_id', db.String(36), db.ForeignKey('user.id')),
    db.Column('role_id', db.String(36), db.ForeignKey('role.id'))
)

class Role(db.Model, RoleMixin):
    id = db.Column(db.String(36), primary_key=True, default=str(uuid.uuid4()))
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

class User(db.Model, UserMixin):
    id = db.Column(db.String(36), primary_key=True, default=str(uuid.uuid4()))
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

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if User.query.filter_by(username=username).first():
        return jsonify(error='Username already exists'), 400
    user_datastore.create_user(username=username, password=password)
    db.session.commit()
    return '', 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()
    if user and user_datastore.verify_password(password, user.password):
        user_datastore.commit()
        return '', 200
    return jsonify(error='Invalid credentials'), 401

@app.route('/changepw', methods=['POST'])
@login_required
def changepw():
    data = request.get_json()
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    if user_datastore.verify_password(old_password, current_user.password):
        current_user.password = user_datastore.hash_password(new_password)
        db.session.commit()
        return '', 201
    return jsonify(error='Incorrect old password'), 400

@app.route('/admin', methods=['GET'])
@login_required
def admin():
    if current_user.has_role('admin'):
        return f'Logged in as admin {current_user.username}'
    return jsonify(error='Unauthorized'), 403

@app.route('/user', methods=['GET'])
@login_required
def user():
    return f'Logged in as user {current_user.username}'

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not Role.query.filter_by(name='admin').first():
            user_datastore.create_role(name='admin')
        if not User.query.filter_by(username='admin').first():
            user_datastore.create_user(username='admin', password='password', roles=['admin'])
            db.session.commit()
    app.run(ssl_context='adhoc')
