from datetime import date, datetime
from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from models import db, User, ScanLog
from auth import login_required, admin_required, get_current_user
from config import PLAN_LIMITS, PLAN_NAMES, ACTIVE_DB_TYPE

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.route('')
@admin_bp.route('/')
@login_required
@admin_required
def admin_dashboard():
    current_user = get_current_user()
    
    # Calculate statistics
    total_users = User.query.count()
    paid_users = User.query.filter(User.plan_tier.in_(['monthly', 'annual', 'lifetime'])).count()
    free_users = User.query.filter_by(plan_tier='free').count()
    admin_users = User.query.filter_by(role='admin').count()
    
    total_scans = ScanLog.query.count()
    
    # Scans performed today
    today_start = datetime.combine(date.today(), datetime.min.time())
    today_scans = ScanLog.query.filter(ScanLog.created_at >= today_start).count()
    
    # All users list
    users = User.query.order_by(User.created_at.desc()).all()
    for u in users:
        u.reset_quota_if_new_day()

    # Recent scans across all users
    recent_scans = ScanLog.query.order_by(ScanLog.created_at.desc()).limit(100).all()

    stats = {
        'total_users': total_users,
        'paid_users': paid_users,
        'free_users': free_users,
        'admin_users': admin_users,
        'total_scans': total_scans,
        'today_scans': today_scans,
        'db_type': ACTIVE_DB_TYPE
    }

    return render_template(
        'admin.html',
        current_user=current_user,
        stats=stats,
        users=users,
        recent_scans=recent_scans,
        plan_limits=PLAN_LIMITS
    )

@admin_bp.route('/api/users/<int:user_id>/update-plan', methods=['POST'])
@login_required
@admin_required
def update_user_plan(user_id):
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.json or {}
    new_tier = data.get('plan_tier', '').lower()
    
    if new_tier not in PLAN_LIMITS:
        return jsonify({'error': f'Invalid plan tier. Choose from: {list(PLAN_LIMITS.keys())}'}), 400

    user.set_plan(new_tier)
    return jsonify({
        'success': True,
        'message': f"Updated {user.username}'s plan to {PLAN_NAMES[new_tier]} ({PLAN_LIMITS[new_tier]} checks/day)",
        'user': user.to_dict()
    })

@admin_bp.route('/api/users/<int:user_id>/reset-quota', methods=['POST'])
@login_required
@admin_required
def reset_user_quota(user_id):
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    user.checks_today = 0
    user.last_reset_date = date.today()
    db.session.commit()

    return jsonify({
        'success': True,
        'message': f"Reset daily check quota for {user.username}. Remaining: {user.daily_limit}/{user.daily_limit}.",
        'user': user.to_dict()
    })

@admin_bp.route('/api/users/<int:user_id>/toggle-status', methods=['POST'])
@login_required
@admin_required
def toggle_user_status(user_id):
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    if user.id == get_current_user().id:
        return jsonify({'error': 'You cannot deactivate your own admin account.'}), 400

    user.is_active = not user.is_active
    db.session.commit()

    status_str = "activated" if user.is_active else "deactivated"
    return jsonify({
        'success': True,
        'message': f"User {user.username} has been {status_str}.",
        'is_active': user.is_active
    })

@admin_bp.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    if user.id == get_current_user().id:
        return jsonify({'error': 'You cannot delete your own admin account.'}), 400

    username = user.username
    db.session.delete(user)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': f"User {username} and associated scan logs have been deleted."
    })

@admin_bp.route('/api/reset-all-quotas', methods=['POST'])
@login_required
@admin_required
def reset_all_quotas():
    users = User.query.all()
    today = date.today()
    for u in users:
        u.checks_today = 0
        u.last_reset_date = today
    db.session.commit()
    return jsonify({'success': True, 'message': f'Reset daily checks for all {len(users)} users successfully.'})
