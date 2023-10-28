from wtforms import Form, StringField, PasswordField, validators
import re

def validate_username(form, field):
    username_re = re.compile(r'^[\w]+$')
    if not username_re.match(field.data):
        raise validators.ValidationError('Invalid username. Usernames can only contain letters, numbers, and underscores.')

def validate_password(form, field):
    password_re = re.compile(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*#?&]{8,}$')
    if not password_re.match(field.data):
        raise validators.ValidationError('Password must be at least 8 characters, contain at least one letter, one number, and may contain special characters.')

class RegistrationForm(Form):
    username = StringField('Username', [
        validators.Length(min=4, max=25),
        validators.DataRequired(),
        validate_username
    ])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match'),
        validate_password
    ])
    confirm = PasswordField('Repeat Password')

class LoginForm(Form):
    username = StringField('Username', [
        validators.Length(min=4, max=25),
        validators.DataRequired(),
        validate_username
    ])
    password = PasswordField('Password', [validators.DataRequired()])

class ChangePasswordForm(Form):
    old_password = PasswordField('Old Password', [validators.DataRequired()])
    new_password = PasswordField('New Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match'),
        validate_password
    ])
    confirm = PasswordField('Repeat Password')