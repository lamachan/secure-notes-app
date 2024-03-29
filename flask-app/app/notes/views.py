from flask import Blueprint, render_template, flash, redirect, url_for, abort
from flask_login import login_required, current_user
import markdown
import bleach

from app.app import db
from app.models import Note
from app.notes.forms import NoteForm, NotePasswordForm
from app.notes.encrypt_module import encrypt_note, decrypt_note

notes_bp = Blueprint('notes', __name__)

HOME_URL = 'notes.home'

@notes_bp.route('/home')
@login_required
def home():
    personal_notes = Note.query.filter_by(user_id=current_user.id, encrypted=False).all()
    encrypted_notes = Note.query.filter_by(user_id=current_user.id, encrypted=True).all()
    public_notes = Note.query.filter_by(public=True, encrypted=False).all()

    return render_template('notes/home.html',
                            personal_notes=personal_notes,
                            encrypted_notes=encrypted_notes,
                            public_notes=public_notes)

@notes_bp.route('/add-note', methods=['GET', 'POST'])
@login_required
def add_note():
    form = NoteForm()

    if form.validate_on_submit():
        if form.encrypted.data and not form.note_password.data:
            flash('Please provide a password for the encrypted note.', 'danger')
            return render_template('notes/add_note.html', form=form)

        rendered_content = markdown.markdown(form.content.data)
        allowed_tags = ['p', 'h1', 'h2', 'h3', 'h4', 'h5', 'strong', 'em', 'a', 'img']
        cleaned_content = bleach.clean(rendered_content, tags=allowed_tags, attributes={'a': ['href', 'target'], 'img': ['src', 'alt']})

        encrypted_content, salt, iv = None, None, None
        if form.encrypted.data and form.note_password.data:
            salt, iv, encrypted_content = encrypt_note(cleaned_content, form.note_password.data)

        new_note = Note(
            title=form.title.data,
            content=encrypted_content if encrypted_content else cleaned_content,
            public=form.public.data,
            encrypted=form.encrypted.data,
            salt=salt,
            iv=iv,
            user=current_user
        )

        db.session.add(new_note)
        db.session.commit()

        flash('Note added successfully!', 'success')
        return redirect(url_for(HOME_URL))

    return render_template('notes/add_note.html', form=form)

@notes_bp.route('/render-note/<int:note_id>', methods=['GET','POST'])
@login_required
def render_note(note_id):
    note = Note.query.get(note_id)

    if note:
        if not note.public:
            if note.user_id == current_user.id:
                if note.encrypted:
                    # note encrypted and current_user is the owner
                    form = NotePasswordForm()

                    if form.validate_on_submit():
                        # 'POST' - password submitted
                        password = form.password.data
                        decrypted_content = decrypt_note(note.content, note.salt, note.iv, password)

                        if decrypted_content:
                            # correct note password
                            note.content = decrypted_content
                            return render_template('notes/render_note.html', note=note)
                        else:
                            # incorrect note password
                            flash('Incorrect note password.', 'danger')
                            return redirect(url_for(HOME_URL))
                    # 'GET' - password to be submitted
                    return render_template('notes/verify_note_password.html', form=form)
                # note not encrypted and current_user is the owner
                return render_template('notes/render_note.html', note=note)
            # note not public and current_user is not the owner
            abort(403)
        # note public
        return render_template('notes/render_note.html', note=note)
    # note not found
    abort(404)

@notes_bp.errorhandler(403)
def forbidden_error(error):
    return render_template('errors/403.html'), 403

@notes_bp.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404