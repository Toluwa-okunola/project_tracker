from flask import Blueprint, render_template, request, redirect, url_for, flash
from models import User
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required

auth_bp = Blueprint('auth', __name__)
# Routes
@auth_bp.route('/')
@login_required
def index():
    meetings = Meeting.query.filter_by(user_id=current_user.id).order_by(Meeting.date.desc()).all()
    return render_template('index.html', meetings=meetings)

@auth_bp.route('/add', methods=['POST'])
@login_required
def add_meeting():
    title = request.form['title']
    participants = request.form['participants']
    notes = request.form['notes']
    new_meeting = Meeting(title=title, participants=participants, notes=notes, user_id=current_user.id)
    db.session.add(new_meeting)
    db.session.commit()
    return redirect(url_for('index'))

@auth_bp.route('/delete/<int:id>')
@login_required
def delete_meeting(id):
    meeting = Meeting.query.get_or_404(id)
    if meeting.user_id != current_user.id:
        return "Unauthorized", 403
    db.session.delete(meeting)
    db.session.commit()
    return redirect(url_for('index'))

@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        email = request.form['email']
        password = request.form['password']
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered. Please log in.', 'warning')
            return redirect(url_for('signup'))
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(firstname=firstname,lastname=lastname,email=email, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        flash('Signup successful! Welcome.', 'success')
        return redirect(url_for('index'))
    return render_template('signup.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('No account found with that email.', 'danger')
            return redirect(url_for('login'))
        if not check_password_hash(user.password, password):
            flash('Incorrect password.', 'danger')
            return redirect(url_for('login'))
        login_user(user)
        return redirect(url_for('index'))
    return render_template('login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))
