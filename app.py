from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
import random
from flask_migrate import Migrate

# Initialize app and configurations
app = Flask(__name__)
app.config.update(
    SECRET_KEY='secret_key',
    SQLALCHEMY_DATABASE_URI='sqlite:///users.db',
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=465,
    MAIL_USERNAME='ngowry12@gmail.com',
    MAIL_PASSWORD='pyyc jmou ypkb iecf',  # Ensure this is the correct Gmail App Password
    MAIL_USE_SSL=True,
    MAIL_DEFAULT_SENDER='ngowry12@gmail.com',
    MAIL_DEBUG=True  # Enable Mail Debugging
)

# Extensions
db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)  # Initialize Flask-Migrate

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

# Home route
@app.route('/')
def index():
    # Redirect authenticated users to the home page
    return redirect(url_for('home')) if current_user.is_authenticated else render_template('index.html')

# Home route (after login)
@app.route('/home')
@login_required
def home():
    return render_template('home.html', email=current_user.email)

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email, password = request.form.get('email'), request.form.get('password')
        
        # Validate form data
        if not email or not password:
            flash('Email and Password are required.')
            return render_template('register.html')

        # Check if email already exists
        if User.query.filter_by(email=email).first():
            flash('Email already exists!')
        else:
            # Generate verification code
            code = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=6))
            
            # Create new user and send verification email
            user = User(email=email, password=generate_password_hash(password), verification_code=code)
            db.session.add(user)
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                flash(f'Error during registration: {e}')
                return render_template('register.html')
            
            # Send verification email
            try:
                mail.send(Message('Verify Your Email', recipients=[email], body=f'Your verification code: {code}'))
                flash('Registration successful! Check your email for verification.')
                return redirect(url_for('verify_email', user_id=user.id))
            except Exception as e:
                flash(f'Error sending verification email: {e}')
                return redirect(url_for('index'))
    
    return render_template('register.html')

# Email verification route
@app.route('/verify_email/<int:user_id>', methods=['GET', 'POST'])
def verify_email(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        code = request.form.get('code')
        if code == user.verification_code:
            user.verified, user.verification_code = True, None
            try:
                db.session.commit()
                flash('Email verified! You can now log in.')
                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()
                flash(f'Error during verification: {e}')
        else:
            flash('Invalid verification code.')
    
    return render_template('verify_email.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first()
        
        if user and check_password_hash(user.password, request.form.get('password')):
            if user.verified:
                login_user(user)
                return redirect(url_for('home'))
            flash('Please verify your email before logging in.')
            return redirect(url_for('verify_email', user_id=user.id))
        
        flash('Invalid credentials.')
    
    return render_template('login.html')

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.')
    return redirect(url_for('index'))

# Initialize the app and run
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables if they don't exist
    app.run(debug=True)
