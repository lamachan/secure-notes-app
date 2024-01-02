from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, InputRequired, EqualTo, Length

from app.models import User


class RegisterForm(FlaskForm):
    username = StringField(
        'Username', validators=[DataRequired(), Length(min=4, max=50)]
    )
    password = PasswordField(
        'Password', validators=[DataRequired(), Length(min=8, max=50)]
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
            self.username.errors.append('Username is already taken.')
            return False
        if self.password.data != self.confirm.data:
            self.password.errors.append('Passwords must match.')
            return False
        return True
    
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class TwoFactorForm(FlaskForm):
    totp = StringField('Enter TOTP', validators=[InputRequired(), Length(min=6, max=6)])