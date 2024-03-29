from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, InputRequired, EqualTo, Length, Regexp

from app.models import User


class RegisterForm(FlaskForm):
    username = StringField(
        'Username', validators=[
            DataRequired(),
            Length(min=4, max=50),
            Regexp('^[a-zA-Z0-9_]+$', message='Username can only contain letters, digits, and underscores.')
        ]
    )
    password = PasswordField(
        'Password', validators=[
            DataRequired(),
            Length(min=8, max=50),
            Regexp(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[!@#$%^&*()_+{}|:"<>?~])',
                   message='Password must include at least one lowercase letter, one uppercase letter, one digit, and one special character.')
        ]
    )
    confirm = PasswordField(
        'Repeat password',
        validators=[
            DataRequired(),
            EqualTo('password', message='Passwords must match.'),
        ],
    )

    def validate(self, extra_validators):
        initial_validation = super(RegisterForm, self).validate(extra_validators)
        if not initial_validation:
            return False
        
        user = User.query.filter_by(username=self.username.data).first()
        if user:
            # username already exists
            self.username.errors.append('Invalid username.')
            return False
        
        if self.password.data != self.confirm.data:
            self.password.errors.append('Passwords must match.')
            return False
        
        return True
    
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    totp = StringField('TOTP', validators=[InputRequired(), Length(min=6, max=6), Regexp('^\d+$', message='TOTP must contain only digits.')])