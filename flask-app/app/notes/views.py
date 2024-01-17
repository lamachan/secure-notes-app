from flask import Blueprint, render_template, flash, redirect, url_for
from flask_login import login_required, current_user
import markdown
import bleach

from app import db
from app.models import Note
from app.notes.forms import NoteForm

notes_bp = Blueprint('notes', __name__)

HOME_URL = 'notes.home'

@notes_bp.route('/home')
@login_required
def home():
    notes = current_user.notes
    return render_template('notes/home.html', notes=notes)

@notes_bp.route('/add-note', methods=['GET', 'POST'])
@login_required
def add_note():
    form = NoteForm()

    if form.validate_on_submit():
        rendered_content = markdown.markdown(form.content.data)
        allowed_tags = ['p', 'h1', 'h2', 'h3', 'h4', 'h5', 'strong', 'em', 'a', 'img']
        cleaned_content = bleach.clean(rendered_content, tags=allowed_tags, attributes={'a': ['href', 'target'], 'img': ['src', 'alt']})

        new_note = Note(title=form.title.data, content=cleaned_content, user=current_user)
        db.session.add(new_note)
        db.session.commit()
        flash('Note added successfully!', 'success')
        return redirect(url_for(HOME_URL))

    return render_template('notes/add_note.html', form=form)