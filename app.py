import os
import base64
from io import BytesIO
from flask import Flask, render_template, redirect, url_for, flash, session, \
    abort
from flask_jwt_extended import JWTManager, create_access_token, decode_token
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, \
    current_user
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import Required, Length, EqualTo
from flask_mail import Mail
import datetime
import onetimepass
import pyqrcode

# create application instance
app = Flask(__name__)
app.config.from_object('config')
mail = Mail(app)
from services.mail_service import send_email

# initialize extensions
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
lm = LoginManager(app)
jwt = JWTManager(app)


class User(UserMixin, db.Model):
    """User model."""
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), index=True)
    password_hash = db.Column(db.String(128))
    otp_secret = db.Column(db.String(16))

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.otp_secret is None:
            # generate a random secret
            self.otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_totp_uri(self):
        return 'otpauth://totp/2FA-Demo:{0}?secret={1}&issuer=2FA-Demo' \
            .format(self.email, self.otp_secret)

    def verify_totp(self, token):
        return onetimepass.valid_totp(token, self.otp_secret)


@lm.user_loader
def load_user(user_id):
    """User loader callback for Flask-Login."""
    return User.query.get(int(user_id))


class RegisterForm(FlaskForm):
    """Registration form."""
    email = StringField('Email', validators=[Required(), Length(1, 64)])
    password = PasswordField('Password', validators=[Required()])
    password_again = PasswordField('Password again',
                                   validators=[Required(), EqualTo('password')])
    submit = SubmitField('Register')

class ForgotForm(FlaskForm):
    """Registration form."""
    email = StringField('Email', validators=[Required(), Length(1, 64)])
    submit = SubmitField('Reset password')

class ResetForm(FlaskForm):
    """Registration form."""
    token = StringField('Token', validators=[Required()])
    password = PasswordField('New password', validators=[Required()])
    submit = SubmitField('Reset password')

class LoginForm(FlaskForm):
    """Login form."""
    email = StringField('Email', validators=[Required(), Length(1, 64)])
    password = PasswordField('Password', validators=[Required()])
    token = StringField('Token', validators=[Required(), Length(6, 6)])
    submit = SubmitField('Login')


@app.route('/')
def index():
    return render_template('index.html')



@app.route('/forgot', methods=['POST', 'GET'])
def forgot():
    """User registration route."""
    if current_user.is_authenticated:
        # if user is logged in we get out of here
        return redirect(url_for('index'))
    form = ForgotForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None:
            flash('Email does not exist.')
            return redirect(url_for('register'))

        expires = datetime.timedelta(minutes=30)
        reset_token = create_access_token(str(user.id), expires_delta=expires)

        send_email('[Movie-bag] Reset Your Password',
                              sender='support@movie-bag.com',
                              recipients=[user.email],
                              text_body=render_template('email/reset_password.txt',
                                                        token=reset_token),
                              html_body=render_template('email/reset_password.html',
                                                        token=reset_token))

        return redirect(url_for('reset'))
    return render_template('forgot.html', form=form)


@app.route('/reset', methods=['POST', 'GET'])
def reset():
    """User registration route."""
    if current_user.is_authenticated:
        # if user is logged in we get out of here
        return redirect(url_for('index'))
    form = ResetForm()
    if form.validate_on_submit():
        reset_token = form.token.data
        new_password = form.password.data
        if reset_token is None or new_password is None:
            flash('Email does not exist.')
            return render_template('reset.html', form=form)

        user_id = decode_token(reset_token)['identity']
        user = User.query.filter_by(id=user_id).first()
        password_hash = generate_password_hash(new_password)
        user.password_hash=password_hash
        db.session.commit()
        send_email('[Movie-bag] Password reset successful',
                              sender='support@movie-bag.com',
                              recipients=[user.email],
                              text_body='Password reset was successful',
                              html_body='<p>Password reset was successful</p>')

        return redirect(url_for('login'))
    return render_template('reset.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration route."""
    if current_user.is_authenticated:
        # if user is logged in we get out of here
        return redirect(url_for('index'))
    form = RegisterForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None:
            flash('Email already exists.')
            return redirect(url_for('register'))
        # add new user to the database
        user = User(email=form.email.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()

        # redirect to the two-factor auth page, passing email in session
        session['email'] = user.email
        return redirect(url_for('two_factor_setup'))
    return render_template('register.html', form=form)


@app.route('/twofactor')
def two_factor_setup():
    if 'email' not in session:
        return redirect(url_for('index'))
    user = User.query.filter_by(email=session['email']).first()
    if user is None:
        return redirect(url_for('index'))
    # since this page contains the sensitive qrcode, make sure the browser
    # does not cache it
    return render_template('two-factor-setup.html'), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@app.route('/qrcode')
def qrcode():
    if 'email' not in session:
        abort(404)
    user = User.query.filter_by(email=session['email']).first()
    if user is None:
        abort(404)

    # for added security, remove email from session
    del session['email']

    # render qrcode for FreeTOTP
    url = pyqrcode.create(user.get_totp_uri())
    stream = BytesIO()
    url.svg(stream, scale=3)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login route."""
    if current_user.is_authenticated:
        # if user is logged in we get out of here
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None or not user.verify_password(form.password.data) or \
                not user.verify_totp(form.token.data):
            flash('Invalid email, password or token.')
            return redirect(url_for('login'))

        # log user in
        login_user(user)
        flash('You are now logged in!')
        return redirect(url_for('index'))
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    """User logout route."""
    logout_user()
    return redirect(url_for('index'))


# create database tables if they don't exist yet
db.create_all()


#if __name__ == '__main__':
#    app.run(host='0.0.0.0', debug=True)
