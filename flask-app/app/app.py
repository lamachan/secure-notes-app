from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

from app.config import Config

db = SQLAlchemy()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)

    from app.models import User

    with app.app_context():
        db.create_all()

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    from app.index.views import index_bp
    from app.auth.views import auth_bp
    from app.notes.views import notes_bp

    app.register_blueprint(index_bp, url_prefix='/')
    app.register_blueprint(auth_bp, url_prefix='/')
    app.register_blueprint(notes_bp, url_prefix='/')

    return app

# if __name__ == "__main__":
#     app = create_app()
#     app.run(host="0.0.0.0", port=5000)