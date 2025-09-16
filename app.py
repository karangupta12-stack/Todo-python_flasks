from flask import Flask, render_template, request, redirect, jsonify, session, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, UTC
import random
import string
import os
from itsdangerous import URLSafeTimedSerializer
from email.mime.text import MIMEText
import smtplib
from dotenv import load_dotenv  
from flask_migrate import Migrate

load_dotenv()  

app = Flask(__name__)
# --- Configuration ---
# It's crucial to use environment variables for sensitive data.
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-super-secret-key-for-dev')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI', 'postgresql://flaskuser:todo2114@localhost:5432/tododb')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


# --- Default Email Configuration (can be overridden by user settings) ---
# Used for the initial registration verification email.
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', '1', 't']
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME') # Your default sending email
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD') # Your app password
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', app.config['MAIL_USERNAME'])


db = SQLAlchemy(app)
print("ENV SQLALCHEMY_DATABASE_URI:", os.environ.get('SQLALCHEMY_DATABASE_URI'))
print("👉 Using database:", app.config["SQLALCHEMY_DATABASE_URI"])

migrate = Migrate(app, db)
mail = Mail(app)


# User Model
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    verification_token = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    
     # Email configuration fields
    smtp_server = db.Column(db.String(100), default='smtp.gmail.com')
    smtp_port = db.Column(db.Integer, default=587)
    smtp_username = db.Column(db.String(120), nullable=True)  # Email for sending
    smtp_password = db.Column(db.String(200), nullable=True)  # App password
    use_tls = db.Column(db.Boolean, default=True)
    
    
    # Relationship with todos
    todos = db.relationship('Todo', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def get_reset_token(self):
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id})

    @staticmethod
    def verify_reset_token(token, expires_sec=1800):
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token, max_age=expires_sec)
            user_id = data.get('user_id')
        except Exception:
            return None
        return User.query.get(user_id)

# Updated Todo Model with user relationship
class Todo(db.Model):
    __tablename__ = 'todos' 
    Sno = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def __repr__(self) -> str:
        return f"{self.Sno} - {self.title}"
    
# OTP Model for email verification
class OTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    otp_code = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)

# -------------------------------------------------Helper functions------------------------------------
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))


def send_otp_email(email, otp_code, user_config=None):
    """Sends an OTP email using either default or user-provided SMTP settings."""
    subject = 'Your MyTodo Verification Code'
    html_body = render_template('emails/otp_template.html', otp_code=otp_code)

    # Use user-specific configuration if provided
    if user_config:
        sender_email = user_config.get('username')
        password = user_config.get('password')
        
        if not sender_email or not password:
            return False, "User's SMTP username or password is not configured."

        # Create the email message
        msg = MIMEText(html_body, 'html')
        msg['Subject'] = subject
        msg['From'] = sender_email
        msg['To'] = email

        try:
            # Connect to the server and send the email
            server = smtplib.SMTP(user_config.get('server'), user_config.get('port'))
            if user_config.get('use_tls', True):
                server.starttls()
            server.login(sender_email, password)
            server.sendmail(sender_email, [email], msg.as_string())
            server.quit()
            print(f"Email sent successfully to {email} using user's custom SMTP.")
            return True, None
        except Exception as e:
            error_msg = str(e)
            print(f"Failed to send email with custom settings: {error_msg}")
            return False, error_msg
    else: # Use default app config
        sender = app.config.get('MAIL_DEFAULT_SENDER')

        if not sender:
            return False, "Default sender email is not configured in the app."

        msg = Message(subject=subject, recipients=[email], html=html_body, sender=sender)

        try:
            mail.send(msg)
            print(f"Email sent successfully to {email} using default app settings.")
            return True, None
        except Exception as e:
            error_msg = str(e)
            print(f"Failed to send email with default settings: {error_msg}")
            return False, error_msg


def send_password_reset_email(user):
    """Sends a password reset email."""
    token = user.get_reset_token()
    subject = 'Password Reset Request for MyTodo'
    reset_url = url_for('reset_password', token=token, _external=True)
    html_body = render_template('emails/reset_password_template.html', reset_url=reset_url)

    # Use default app config for sending reset emails
    sender = app.config['MAIL_DEFAULT_SENDER']

    if not sender:
        print("Email sending failed: MAIL_DEFAULT_SENDER is not configured.")
        return False, "Sender email not configured."

    msg = Message(subject=subject, recipients=[user.email], html=html_body, sender=sender)

    try:
        mail.send(msg)
        print(f"Password reset email sent successfully to {user.email}")
        return True, None
    except Exception as e:
        error_msg = str(e)
        print(f"Failed to send password reset email to {user.email}: {error_msg}")
        return False, error_msg


# -----------------------------------------------------------------Routes----------------------------------------------------
@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['desc']
        
        todo = Todo(title = title, description = description, user_id=session['user_id'])
        db.session.add(todo)
        db.session.commit()
    
        flash('Todo added successfully!', 'success')
    
    allTodo = Todo.query.filter_by(user_id=session['user_id']).all()
    return render_template('index.html', allTodo=allTodo)

    
@app.route('/about')
def about():
    allTodo = Todo.query.all()
    return render_template('about.html', allTodo=allTodo)


# ---------------------------------------------Authentication Routes ----------------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email'].lower().strip()
        password = request.form['password']
        # print(f"User password: {password}")
        confirm_password = request.form['confirm_password']
        
        # Validation
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long!', 'error')
            return render_template('register.html')
        
        # Check if user already exists
        if User.query.filter_by(email=email).first():
            flash('Email already registered! Please login.', 'error')
            return redirect(url_for('login'))
        
# Create new user
        user = User(email=email)
        user.set_password(password)
        # user.generate_verification_token()
        
        db.session.add(user)
        db.session.commit()
        
        # Generate and send OTP
        otp_code = generate_otp()
        # from datetime import timedelta
        otp = OTP(
            email=email,
            otp_code=otp_code,
            expires_at=datetime.now(UTC) + timedelta(minutes=10)
        )
        db.session.add(otp)
        db.session.commit()
        
        # Try to send email, but don't fail if email service isn't configured
        email_sent = send_otp_email(email, otp_code)
        if not email_sent:
            flash(f'Account created! Email service not configured. Use OTP: {otp_code}', 'info')
        else:
            flash('Account created! Please check your email for verification code.', 'success')
        
        session['temp_email'] = email
        return redirect(url_for('verify_email'))
    
    return render_template('register.html')


@app.route('/verify-email', methods=['GET', 'POST'])
def verify_email():
    if 'temp_email' not in session:
        flash('Please register first.', 'warning')
        return redirect(url_for('register'))
    
    if request.method == 'POST':
        otp_code = request.form['otp_code']
        email = session['temp_email']
        
        # Find valid OTP
        otp = OTP.query.filter_by(
            email=email, 
            otp_code=otp_code, 
            is_used=False
        ).filter(OTP.expires_at > datetime.now(UTC)).first()
        
        if otp:
            # Mark OTP as used
            otp.is_used = True
            user = User.query.filter_by(email=email).first()
            if user:
                user.is_verified = True
                db.session.commit()
                session.pop('temp_email', None)
                flash('Email verified successfully! You can now log in.', 'success')
                return redirect(url_for('login'))
            else:
                flash('User not found. Please register again.', 'danger')
                return redirect(url_for('register'))
        else:
            flash('Invalid or expired OTP code!', 'error')
    
    return render_template('verify_email.html')


# Resend OTP route
@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    if 'temp_email' not in session:
        return jsonify({'error': 'No email in session'}), 400
    
    email = session['temp_email']
    
    # Generate new OTP
    otp_code = generate_otp()
    from datetime import timedelta
    otp = OTP(
        email=email,
        otp_code=otp_code,
        expires_at=datetime.now(UTC) + timedelta(minutes=10)
    )
    db.session.add(otp)
    db.session.commit()
    
    success, error = send_otp_email(email, otp_code)
    if success:
        return jsonify({'success': True, 'message': 'A new OTP has been sent to your email.'}), 200
    else:
        # Provide OTP in response for dev fallback
        return jsonify({'success': True, 'message': f'Could not send email. New OTP: {otp_code}'}), 200
    

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].lower().strip()
        password = request.form['password']
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            if not user.is_verified:
                flash('Please verify your email first.', 'warning')
                session['temp_email'] = email
                return redirect(url_for('verify_email'))
            
            session['user_id'] = user.id
            session['user_email'] = user.email
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password!', 'error')
    
    return render_template('login.html')


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email'].lower().strip()
        user = User.query.filter_by(email=email).first()
        if user:
            success, error = send_password_reset_email(user)
            if success:
                flash('A password reset link has been sent to your email.', 'info')
            else:
                flash('Could not send the password reset email. Please try again later.', 'danger')
            return redirect(url_for('login'))
        else:
            flash('Email address not found.', 'warning')
    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.verify_reset_token(token)
    if not user:
        flash('That is an invalid or expired token.', 'warning')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return render_template('reset_password.html')
        if len(password) < 6:
            flash('Password must be at least 6 characters long!', 'danger')
            return render_template('reset_password.html')

        user.set_password(password)
        db.session.commit()
        flash('Your password has been updated! You are now able to log in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'info')
    return redirect(url_for('login'))


# --------------------------------------------ToDo Management Routes----------------------------------

@app.route('/update/<int:Sno>', methods=['GET', 'POST'])
@login_required
def update(Sno):
    todo = Todo.query.filter_by(Sno=Sno, user_id=session['user_id']).first_or_404()

    if request.method == 'POST':
        todo.title = request.form['title']
        todo.description = request.form['desc']
        db.session.commit()
        flash('Todo updated successfully!', 'success')
        return redirect(url_for('index'))

    return render_template('update.html', todo=todo)

@app.route('/delete/<int:Sno>')
@login_required
def delete(Sno):
    todo = Todo.query.filter_by(Sno=Sno, user_id=session['user_id']).first_or_404()    
    db.session.delete(todo)
    db.session.commit()
    flash('Todo deleted successfully!', 'success')
    return redirect(url_for('index'))


#  --------------------------------------------Email Configuration Routes-------------------------------------------------
@app.route('/email-setup', methods=['GET', 'POST'])
@login_required
def email_setup():
    """Allow users to configure their email settings"""
    user = User.query.get_or_404(session['user_id'])
    
    if request.method == 'POST':
        # Get form data

        smtp_username = request.form.get('smtp_username')
        smtp_password = request.form.get('smtp_password')
        use_tls = 'use_tls' in request.form
        
        if not smtp_username or not smtp_password:
            flash('SMTP username and password are required!', 'error')
            return render_template('email_setup.html', user=user)
        
        # Test email configuration
        test_config = {
            'server': request.form.get('smtp_server', 'smtp.gmail.com'),
            'port': int(request.form.get('smtp_port', 587)),
            'username': smtp_username,
            'password': smtp_password,
            'use_tls': 'use_tls' in request.form
        }
        
        # Send test email
        test_otp = generate_otp()
        success, error = send_otp_email(smtp_username, test_otp, test_config)
        

        if success:
            user.smtp_server = test_config['server']
            user.smtp_port = test_config['port']
            user.smtp_username = test_config['username']
            user.smtp_password = test_config['password'] # Note: Storing plaintext password is a security risk
            user.use_tls = test_config['use_tls']

            
            db.session.commit()
            flash('Email configuration saved and tested successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash(f'Email test failed: {error}. Please check your settings.', 'danger')
    
    return render_template('email_setup.html', user=user)


if __name__ == '__main__':
    # with app.app_context():
    #     db.create_all()
    app.run(debug=False)