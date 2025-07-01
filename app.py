from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_migrate import Migrate

from flask_mail import Mail, Message


from sqlalchemy import or_

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///meetings.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'yoursecretkey'  # Replace with a secure random string in production

app.config.update(
    MAIL_SERVER='smtp.gmail.com',    # Example: Gmail SMTP server
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME='acada.app1@gmail.com',  # Your email here
    MAIL_PASSWORD='1ppa.adaca',   # Your app password or real password (better: use environment vars)
    MAIL_DEFAULT_SENDER='acada.app1@gmail.com'
)

mail = Mail(app)

db = SQLAlchemy(app)

migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Association tables
# Add 'role' column to the association table
# project_users = db.Table('project_users',
#     db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
#     db.Column('project_id', db.Integer, db.ForeignKey('project.id'), primary_key=True),
#     db.Column('role', db.String(20), nullable=False, default='viewer')  # role column added
# )
#

related_projects = db.Table('related_projects',
    db.Column('project_id', db.Integer, db.ForeignKey('project.id'), primary_key=True),
    db.Column('related_id', db.Integer, db.ForeignKey('project.id'), primary_key=True)
)

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    meetings = db.relationship('Meeting', backref='user', lazy=True)
    project_associations = db.relationship('ProjectUser', back_populates='user')
    # Convenient access to projects through association (read-only)
    projects = db.relationship('Project', secondary='project_users', viewonly=True)
class ProjectUser(db.Model):
    __tablename__ = 'project_users'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), primary_key=True)
    role = db.Column(db.String(20), nullable=False, default='viewer')

    # Relationships for back-population
    user = db.relationship('User', back_populates='project_associations')
    project = db.relationship('Project', back_populates='user_associations')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text)
    start_date = db.Column(db.Date, default=datetime.utcnow)
    status = db.Column(db.String(50), default='Planning')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user_associations = db.relationship('ProjectUser', back_populates='project')
    users = db.relationship('User', secondary='project_users', viewonly=True)
    meetings = db.relationship('Meeting', backref='project', lazy=True)
    publications = db.relationship('Publication', backref='project', lazy=True)
    references = db.relationship('Reference', backref='project', lazy=True)
    related = db.relationship(
        'Project',
        secondary=related_projects,
        primaryjoin=id==related_projects.c.project_id,
        secondaryjoin=id==related_projects.c.related_id,
        backref='linked_projects'
    )

class Publication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    journal = db.Column(db.String(100))
    link = db.Column(db.String(300))
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'))

class Reference(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.Text)
    link = db.Column(db.String(300))
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'))

# Update Meeting to link to project
class Meeting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    participants = db.Column(db.String(500), nullable=False)
    notes = db.Column(db.Text, nullable=True)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=True)  # nullable=True so meetings can be general if you want

# Routes
@app.route('/')
@login_required
def index():
    meetings = Meeting.query.filter_by(user_id=current_user.id).order_by(Meeting.date.desc()).all()
    return render_template('index.html', meetings=meetings)


@app.route('/project/<int:project_id>/add_meeting', methods=['GET', 'POST'])
@login_required
def add_meeting(project_id):
    project = Project.query.get_or_404(project_id)

    # show the empty meeting form
    if request.method == 'GET':
        return render_template('add_meeting.html', project=project)

    # handle form submission (POST)
    title        = request.form['title']
    participants = request.form['participants']
    notes        = request.form.get('notes', '')

    new_meeting = Meeting(
        title        = title,
        participants = participants,
        notes        = notes,
        project_id   = project.id,
        user_id      = current_user.id
    )
    db.session.add(new_meeting)
    db.session.commit()
    flash('Meeting added successfully!', 'success')
    return redirect(url_for('project_detail', project_id=project.id))


@app.route('/delete/<int:id>')
@login_required
def delete_meeting(id):
    meeting = Meeting.query.get_or_404(id)
    if meeting.user_id != current_user.id:
        return "Unauthorized", 403
    db.session.delete(meeting)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/signup', methods=['GET', 'POST'])
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
        return redirect(url_for('dashboard'))
    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
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

        # 🔥 THIS is the key line to fix the stale project list
        db.session.refresh(user)
        print("User projects on login:", [p.title for p in user.projects])
        fresh_user = User.query.get(user.id)
        print("User projects fresh from DB:", [p.title for p in fresh_user.projects])
        return redirect(url_for('dashboard'))
    return render_template('login.html')


# @app.route('/dashboard')
# @login_required
# def dashboard():
#     projects = current_user.projects
#     return render_template('dashboard.html', projects=projects)

@app.route('/dashboard')
@login_required
def dashboard():
    owned_projects = Project.query.filter_by(user_id=current_user.id).all()
    shared_projects = Project.query.filter(
        Project.users.any(id=current_user.id),
        Project.user_id != current_user.id
    ).all()
    return render_template('dashboard.html', owned_projects=owned_projects, shared_projects=shared_projects)

# @app.route('/dashboard')
# @login_required
# def dashboard():
#     print(f"\n=== DEBUG: Dashboard for user {current_user.id} ===")
#
#     # Check all projects in database
#     all_projects = Project.query.all()
#     print(f"Total projects in DB: {len(all_projects)}")
#     for p in all_projects:
#         print(f"  Project {p.id}: '{p.title}' - Owner: {p.user_id}, Users: {[u.id for u in p.users]}")
#
#     # Check projects where user is owner
#     owned_projects = Project.query.filter(Project.user_id == current_user.id).all()
#     print(f"Projects owned by user {current_user.id}: {len(owned_projects)}")
#     for p in owned_projects:
#         print(f"  Owned: {p.title}")
#
#     # Check projects where user is collaborator
#     collab_projects = Project.query.filter(Project.users.any(id=current_user.id)).all()
#     print(f"Projects where user {current_user.id} is collaborator: {len(collab_projects)}")
#     for p in collab_projects:
#         print(f"  Collaborator: {p.title}")
#
#     # Final query (your current approach)
#     projects = Project.query.filter(
#         or_(
#             Project.user_id == current_user.id,
#             Project.users.any(id=current_user.id)
#         )
#     ).all()
#
#     print(f"Final result: {len(projects)} projects")
#     print("=== END DEBUG ===\n")
#
#     return render_template('dashboard.html', projects=projects)

from flask import request

@app.route('/project/<int:project_id>/invite', methods=['POST'])
@login_required
def invite_collaborators(project_id):
    project = Project.query.get_or_404(project_id)

    # Only owner can invite collaborators
    owner_assoc = next((assoc for assoc in project.user_associations if assoc.user_id == current_user.id and assoc.role == 'owner'), None)
    if not owner_assoc:
        flash("Only project owners can invite collaborators.", "danger")
        return redirect(url_for('dashboard'))

    email = request.form.get('email')
    user = User.query.filter_by(email=email).first()
    if not user:
        flash("No user found with that email.", "danger")
        return redirect(url_for('dashboard'))

    # Check if user already collaborator
    existing_assoc = ProjectUser.query.filter_by(user_id=user.id, project_id=project.id).first()
    if existing_assoc:
        flash(f"{user.firstname} is already a collaborator.", "info")
        return redirect(url_for('dashboard'))

    new_assoc = ProjectUser(user=user, project=project, role='viewer')  # default role
    db.session.add(new_assoc)
    db.session.commit()
    flash(f"{user.firstname} has been added as a collaborator with 'viewer' role.", "success")
    # After db.session.commit() and flash for success
    try:
        msg = Message(
            subject=f"You've been invited to collaborate on project '{project.title}'",
            recipients=[user.email],
            body=f"Hello {user.firstname},\n\n"
                 f"You have been invited to collaborate on the project '{project.title}'.\n"
                 f"Log in to your account to see the details and start collaborating!\n\n"
                 f"Best,\nAcademic Planner Team"
        )
        mail.send(msg)
    except Exception as e:
        # Log error, but don’t break the user flow
        print(f"Failed to send invite email: {e}")

    return redirect(url_for('dashboard'))

@app.route('/meetings')
@login_required
def all_meetings():
    accessible_project_ids = [
        assoc.project_id for assoc in current_user.project_associations
    ]
    meetings = Meeting.query.filter(Meeting.project_id.in_(accessible_project_ids)).order_by(Meeting.date.desc()).all()
    return render_template('all_meetings.html', meetings=meetings)

@app.route('/project/<int:project_id>')
@login_required
def project_detail(project_id):
    project = Project.query.get_or_404(project_id)
    # Check if current user is part of project
    if current_user not in project.users:
        return "Unauthorized", 403
    return render_template('project_detail.html', project=project)

@app.route('/select_project_for_meeting', methods=['GET'])
@login_required
def select_project_for_meeting():
    project_id = request.args.get('project_id')
    if not project_id:
        flash('Please select a project.', 'warning')
        return redirect(url_for('dashboard'))
    # Redirect user to the meeting creation page for that project
    return redirect(url_for('add_meeting', project_id=project_id))

@app.route('/project/create', methods=['GET', 'POST'])
@login_required
def create_project():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        status = request.form.get('status', 'Planning')

        project = Project(
            title=title,
            description=description,
            status=status,
            user_id=current_user.id  # Still track ownership at the Project level too
        )

        # Explicitly create the ProjectUser association with role='owner'
        owner_assoc = ProjectUser(user=current_user, project=project, role='owner')
        db.session.add_all([project, owner_assoc])
        db.session.commit()

        flash('Project created and you are now the owner!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('create_project.html')

@app.route('/project/<int:project_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_project(project_id):
    project = Project.query.get_or_404(project_id)

    # Only the owner can edit
    if project.user_id != current_user.id:
        flash("Only the project owner can edit this project.", "danger")
        return redirect(url_for('project_detail', project_id=project_id))

    if request.method == 'POST':
        project.title = request.form['title']
        project.description = request.form['description']
        project.status = request.form['status']
        db.session.commit()
        flash("Project updated successfully!", "success")
        return redirect(url_for('project_detail', project_id=project_id))

    return render_template('edit_project.html', project=project)
@app.route('/project/<int:project_id>/add_publication', methods=['POST'])
@login_required
def add_publication(project_id):
    project = Project.query.get_or_404(project_id)
    if current_user.id != project.user_id:
        flash("Only the project owner can add publications.", "danger")
        return redirect(url_for('project_detail', project_id=project_id))

    title = request.form['title']
    journal = request.form.get('journal', '')
    link = request.form.get('link', '')

    publication = Publication(title=title, journal=journal, link=link, project=project)
    db.session.add(publication)
    db.session.commit()
    flash("Publication added successfully!", "success")
    return redirect(url_for('project_detail', project_id=project_id))


@app.route('/project/<int:project_id>/add_reference', methods=['POST'])
@login_required
def add_reference(project_id):
    project = Project.query.get_or_404(project_id)
    if current_user.id != project.user_id:
        flash("Only the project owner can add references.", "danger")
        return redirect(url_for('project_detail', project_id=project_id))

    description = request.form['description']
    link = request.form.get('link', '')

    reference = Reference(description=description, link=link, project=project)
    db.session.add(reference)
    db.session.commit()
    flash("Reference added successfully!", "success")
    return redirect(url_for('project_detail', project_id=project_id))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
