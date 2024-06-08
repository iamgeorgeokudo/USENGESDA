from functools import wraps

from flask import redirect, url_for, flash
from flask_login import current_user

def admin_required(fn):
    @wraps(fn)
    def check_admin(*args, **kwargs):
        if not current_user.is_anonymous and current_user.role.name == 'Administrator':
            return fn(*args, **kwargs)
        flash('You are not authorized to access this page.')
        return redirect(url_for('auth.login'))
    
    return check_admin