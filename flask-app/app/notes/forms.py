from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, BooleanField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Optional, ValidationError, Length

class NoteForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    public = BooleanField('Public Note', default=False)
    encrypted = BooleanField('Encrypt Note', default=False)
    note_password = PasswordField('Note Password', validators=[Optional(), Length(min=8, max=50)])  # optional when the encrypted box is unchecked
    submit = SubmitField('Save Note')

    def validate(self, extra_validators):
        initial_validation = super(NoteForm, self).validate(extra_validators)
        if not initial_validation:
            return False
        
        if self.public.data and self.encrypted.data:
            self.public.errors.append('An encrypted note cannot be public.')
            return False
        
        return True
    
class NotePasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Submit')