from flask import render_template, redirect, request, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from flask_mail import Message
from app import db, mail
from . import auth
from ..models import User, Role
from .forms import LoginForm, RegistrationForm
from itsdangerous import URLSafeTimedSerializer
from config import Config

s = URLSafeTimedSerializer(Config.SECRET_KEY)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # Check if user exists
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password (form.password.data) and user.confirmed:
            # Log user in
            login_user(user, form.remember_me.data)
            next_url = request.args.get('next')
            if next_url is None or not next_url.startswith('/'):
                if user.role.name == 'Administrator':
                    next_url = url_for('admin.dashboard')
                elif user.role.name == 'User':
                    next_url = url_for('main.index')
                else:
                    flash('Invalid user role or unconfirmed account.')
                    next_url = url_for('auth.login')
            return redirect(next_url)
        flash('Invalid username or password.')
    return render_template('auth/login.html', form=form)


@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    role = Role.query.filter_by(name='User').first()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            flash('Email already registered.', 'warning')
            return redirect(url_for('auth.login'))
        user = User(email=form.email.data,
                    username=form.username.data,
                    password=form.password.data,
                    role=role)
        db.session.add(user)
        db.session.commit()
        
        token = s.dumps(user.email, salt='email-confirm')
        confirm_url = url_for('auth.confirm_email', token=token, _external=True)
        html = render_template('auth/activate.html', confirm_url=confirm_url)

        msg = Message(subject='Welcome to Usenge Sda Church.',
                        sender=Config.MAIL_USERNAME,
                      recipients=[user.email],
                      html=html)
        msg.body = 'Please confirm your email by clicking on the link below.'
        msg.html = html
        try:
            mail.send(msg)
            flash('A confirmation email has been sent to you by email.', 'success')
        except Exception as e:
            flash('An error occurred while sending the email.', 'error')
            db.session.delete(user)
            db.session.commit()
            print(f"Error: {e}")

        return redirect(url_for('auth.post_registration'))
    return render_template('auth/register.html', form=form)

@auth.route('/post_registration')
def post_registration():
    gmail_link = "https://mail.google.com/"
    return render_template('auth/post_registration.html', gmail_link=gmail_link)


@auth.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('main.index'))
    
    user = User.query.filter_by(email=email).first_or_404()
    if user.confirmed:
        flash('Account already confirmed. Please login.', 'success')
    else:
        user.confirmed = True
        db.session.commit()
        flash('You have confirmed your account. Thanks!', 'success')
    return redirect(url_for('main.index'))

@auth.route('/protected')
@login_required
def protected():
    if not current_user.confirmed:
        flash('Please confirm your account first.', 'warning')
        return redirect(url_for('index'))
    return 'This is a protected page.'

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out. Login again.', 'success')
    return redirect(url_for('auth.login'))
