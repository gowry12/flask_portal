import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
import random

# Initialize app and configurations
app = Flask(__name__)

# Fetch configurations from environment variables
app.config.update(
    SECRET_KEY=os.getenv('SECRET_KEY','secret_key'), 
    SQLALCHEMY_DATABASE_URI=os.getenv('DATABASE_URL', 'sqlite:///users.db'),
    MAIL_SERVER=os.getenv('MAIL_SERVER', 'smtp.gmail.com'),
    MAIL_PORT=int(os.getenv('MAIL_PORT', 465)),
    MAIL_USERNAME=os.getenv('MAIL_USERNAME', 'default_email@gmail.com'),
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD', 'default_password'),
    MAIL_USE_SSL=os.getenv('MAIL_USE_SSL', 'True').lower() == 'true',
    MAIL_DEFAULT_SENDER=os.getenv('MAIL_DEFAULT_SENDER', 'default_email@gmail.com'),
)

# Extensions
db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    verified = db.Column(db.Boolean, default=False)
    verification_code = db.Column(db.String(6), nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email, password = request.form['email'], request.form['password']

        # Check if email already exists
        if User.query.filter_by(email=email).first():
            flash('Email already exists!')
        else:
            # Generate a verification code
            code = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=6))

            # Create and save the user
            user = User(email=email, password=generate_password_hash(password), verification_code=code)
            db.session.add(user)
            db.session.commit()

            # Send verification email
            mail.send(Message('Verify Your Email', recipients=[email], body=f'Your code: {code}'))

            flash('Registration successful! Check your email for verification.')
            return redirect(url_for('verify_email', user_id=user.id))

    return render_template('register.html')

@app.route('/verify_email/<int:user_id>', methods=['GET', 'POST'])
def verify_email(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST' and request.form['code'] == user.verification_code:
        user.verified = True
        user.verification_code = None
        db.session.commit()
        flash('Email verified! You can now log in.')
        return redirect(url_for('login'))
    if request.method == 'POST':
        flash('Invalid verification code.')
    return render_template('verify_email.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user and check_password_hash(user.password, request.form['password']):
            if user.verified:
                login_user(user)
                return redirect(url_for('home'))
            flash('Please verify your email.')
            return redirect(url_for('verify_email', user_id=user.id))
        flash('Invalid credentials.')
    return render_template('login.html')

@app.route('/home')
@login_required
def home():
    return render_template('home.html', email=current_user.email)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.')
    return redirect(url_for('index'))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return render_template('index.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
