# from flask_sqlalchemy import SQLAlchemy
# from flask_login import UserMixin
# from datetime import datetime
# db = SQLAlchemy()

from . import db, login_manager
from flask_login import UserMixin
from datetime import datetime

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    meetings = db.relationship('Meeting', backref='user', lazy=True)

class Meeting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    participants = db.Column(db.String(500), nullable=False)
    notes = db.Column(db.Text, nullable=True)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))