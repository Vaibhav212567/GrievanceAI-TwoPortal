import os
from datetime import datetime
from functools import wraps
from urllib.parse import urlparse

from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-only-change-me')
database_url = os.environ.get('DATABASE_URL', 'sqlite:///grievanceai.db')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Enable secure cookies on HTTPS deployments.
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax')
if os.environ.get('RENDER'):
    app.config['SESSION_COOKIE_SECURE'] = True

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to continue.'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    grievances = db.relationship('Grievance', backref='owner', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Grievance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    title = db.Column(db.String(180), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(80), nullable=False, default='General')
    priority = db.Column(db.String(20), nullable=False, default='Medium')
    status = db.Column(db.String(30), nullable=False, default='Submitted')
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def developer_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if current_user.role != 'developer':
            abort(403)
        return view(*args, **kwargs)
    return wrapped

def classify(text):
    t = text.lower()
    if any(w in t for w in ('safety', 'danger', 'harass', 'threat', 'urgent', 'emergency')):
        priority = 'High'
    elif any(w in t for w in ('delay', 'broken', 'not working', 'payment', 'water', 'electricity')):
        priority = 'Medium'
    else:
        priority = 'Low'
    if any(w in t for w in ('wifi', 'internet', 'network', 'computer', 'software', 'website', 'technical')):
        category = 'Technical'
    elif any(w in t for w in ('water', 'electricity', 'clean', 'maintenance', 'hostel', 'building')):
        category = 'Facilities'
    elif any(w in t for w in ('fee', 'payment', 'refund', 'scholarship', 'salary')):
        category = 'Finance'
    elif any(w in t for w in ('teacher', 'class', 'exam', 'marks', 'course', 'academic')):
        category = 'Academic'
    else:
        category = 'General'
    return category, priority

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('developer_dashboard' if current_user.role == 'developer' else 'user_dashboard'))
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        if not name or not email or len(password) < 8:
            flash('Enter your name and email, and use a password with at least 8 characters.', 'error')
        elif User.query.filter_by(email=email).first():
            flash('An account with that email already exists. Please log in.', 'error')
        else:
            user = User(name=name, email=email, role='user')
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash('Your account is ready. Welcome to GrievanceAI!', 'success')
            return redirect(url_for('user_dashboard'))
    return render_template('auth.html', mode='signup')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('developer_dashboard' if user.role == 'developer' else 'user_dashboard'))
        flash('Email or password is incorrect.', 'error')
    return render_template('auth.html', mode='login')

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def user_dashboard():
    if current_user.role == 'developer':
        return redirect(url_for('developer_dashboard'))
    grievances = Grievance.query.filter_by(user_id=current_user.id).order_by(Grievance.created_at.desc()).all()
    return render_template('user_dashboard.html', grievances=grievances)

@app.route('/grievances/new', methods=['GET', 'POST'])
@login_required
def new_grievance():
    if current_user.role == 'developer':
        return redirect(url_for('developer_dashboard'))
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        if not title or not description:
            flash('Please fill in both the title and description.', 'error')
        elif len(title) > 180 or len(description) > 10000:
            flash('Title must be under 180 characters and description under 10,000.', 'error')
        else:
            category, priority = classify(title + ' ' + description)
            item = Grievance(user_id=current_user.id, title=title, description=description,
                             category=category, priority=priority)
            db.session.add(item)
            db.session.commit()
            flash(f'Grievance #{item.id} submitted. Suggested category: {category}.', 'success')
            return redirect(url_for('user_dashboard'))
    return render_template('new_grievance.html')

@app.route('/developer')
@developer_required
def developer_dashboard():
    query = Grievance.query.join(User)
    search = request.args.get('q', '').strip()
    status_filter = request.args.get('status', '').strip()
    if search:
        pattern = f'%{search}%'
        query = query.filter(db.or_(Grievance.title.ilike(pattern), Grievance.description.ilike(pattern), User.name.ilike(pattern), User.email.ilike(pattern)))
    if status_filter in ('Submitted', 'In Progress', 'Resolved', 'Rejected'):
        query = query.filter(Grievance.status == status_filter)
    grievances = query.order_by(Grievance.created_at.desc()).all()
    stats = {
        'users': User.query.filter_by(role='user').count(),
        'total': Grievance.query.count(),
        'open': Grievance.query.filter(Grievance.status.in_(['Submitted', 'In Progress'])).count(),
        'resolved': Grievance.query.filter_by(status='Resolved').count(),
    }
    users = User.query.filter_by(role='user').order_by(User.created_at.desc()).all()
    return render_template('developer_dashboard.html', grievances=grievances, users=users, stats=stats,
                           search=search, status_filter=status_filter)

@app.route('/developer/grievance/<int:grievance_id>', methods=['POST'])
@developer_required
def update_grievance(grievance_id):
    item = db.get_or_404(Grievance, grievance_id)
    status = request.form.get('status', '')
    priority = request.form.get('priority', '')
    valid_status = {'Submitted', 'In Progress', 'Resolved', 'Rejected'}
    valid_priority = {'Low', 'Medium', 'High'}
    if status in valid_status and priority in valid_priority:
        item.status = status
        item.priority = priority
        db.session.commit()
        flash(f'Grievance #{item.id} updated.', 'success')
    else:
        flash('Invalid status or priority.', 'error')
    return redirect(url_for('developer_dashboard'))

@app.errorhandler(403)
def forbidden(_error):
    return render_template('message.html', title='Access denied', message='This area is for the developer account only.'), 403

@app.errorhandler(404)
def not_found(_error):
    return render_template('message.html', title='Not found', message='The page or grievance could not be found.'), 404

with app.app_context():
    db.create_all()
    # Bootstrap a developer account from environment variables. Never expose developer signup publicly.
    dev_email = os.environ.get('DEVELOPER_EMAIL', '').strip().lower()
    dev_password = os.environ.get('DEVELOPER_PASSWORD', '')
    if dev_email and dev_password:
        dev = User.query.filter_by(email=dev_email).first()
        if dev is None:
            dev = User(name=os.environ.get('DEVELOPER_NAME', 'GrievanceAI Developer'), email=dev_email, role='developer')
            dev.set_password(dev_password)
            db.session.add(dev)
            db.session.commit()
        elif dev.role != 'developer':
            # Never silently promote an existing public account.
            app.logger.error('DEVELOPER_EMAIL matches an existing non-developer account; resolve this manually.')

if __name__ == '__main__':
    app.run(debug=True)
