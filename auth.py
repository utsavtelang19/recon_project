from functools import wraps
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify
from models import db, User
from config import PLAN_LIMITS

auth_bp = Blueprint('auth', __name__)

def get_current_user():
    user_id = session.get('user_id')
    if not user_id:
        return None
    user = db.session.get(User, user_id)
    if user:
        user.reset_quota_if_new_day()
    return user

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user:
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required. Please log in.', 'code': 'AUTH_REQUIRED'}), 401
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login', next=request.path))
        if not user.is_active:
            session.clear()
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Your account has been deactivated.', 'code': 'ACCOUNT_DISABLED'}), 403
            flash('Your account has been deactivated by the administrator.', 'danger')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user or not user.is_admin():
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Access denied: Administrator privileges required.', 'code': 'FORBIDDEN'}), 403
            flash('Access denied. Administrator privileges required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if get_current_user():
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Basic validations
        if not username or len(username) < 3:
            flash('Username must be at least 3 characters long.', 'danger')
            return render_template('register.html', username=username, email=email)
        
        if not email or '@' not in email or '.' not in email:
            flash('Please enter a valid email address.', 'danger')
            return render_template('register.html', username=username, email=email)

        if not password or len(password) < 6:
            flash('Password must be at least 6 characters long.', 'danger')
            return render_template('register.html', username=username, email=email)

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html', username=username, email=email)

        if User.query.filter_by(username=username).first():
            flash('Username is already taken. Please choose another.', 'danger')
            return render_template('register.html', username=username, email=email)

        if User.query.filter_by(email=email).first():
            flash('An account with this email already exists.', 'danger')
            return render_template('register.html', username=username, email=email)

        # Create new user (Free tier by default: 50 checks / day)
        new_user = User(
            username=username,
            email=email,
            role='free',
            plan_tier='free',
            daily_limit=PLAN_LIMITS['free'],
            checks_today=0
        )
        new_user.set_password(password)

        try:
            db.session.add(new_user)
            db.session.commit()
            session['user_id'] = new_user.id
            flash(f'Account created successfully! Welcome, {new_user.username}. You have 50 daily reconnaissance checks.', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Registration failed due to a database error: {str(e)}', 'danger')

    return render_template('register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if get_current_user():
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        login_input = request.form.get('login_input', '').strip()
        password = request.form.get('password', '')

        if not login_input or not password:
            flash('Please enter your username/email and password.', 'danger')
            return render_template('login.html', login_input=login_input)

        user = User.query.filter(
            (User.username == login_input) | (User.email == login_input.lower())
        ).first()

        if not user or not user.check_password(password):
            flash('Invalid username/email or password.', 'danger')
            return render_template('login.html', login_input=login_input)

        if not user.is_active:
            flash('This account has been deactivated. Please contact support/administrator.', 'danger')
            return render_template('login.html', login_input=login_input)

        session['user_id'] = user.id
        user.reset_quota_if_new_day()
        flash(f'Welcome back, {user.username}!', 'success')

        next_url = request.args.get('next')
        if next_url and next_url.startswith('/'):
            return redirect(next_url)
        return redirect(url_for('dashboard'))

    return render_template('login.html')

@auth_bp.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out safely.', 'info')
    return redirect(url_for('auth.login'))
