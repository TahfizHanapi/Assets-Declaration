import secrets
import requests
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, abort
from werkzeug.utils import escape
import mysql.connector
from flask_wtf import FlaskForm
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_bcrypt import check_password_hash
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import PasswordField, SubmitField, StringField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo
import random
import string
from flask_mail import Mail, Message


# MySQL database configuration
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'Azib_2002',
    'database': 'assets'
}

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config[
    'SQLALCHEMY_DATABASE_URI'] = f"mysql+mysqlconnector://{db_config['user']}:{db_config['password']}@{db_config['host']}/{db_config['database']}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

users = {}

mail = Mail(app)
class PasswordResetForm(FlaskForm):
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Reset Password')
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

    # Establish the relationship with PendingAsset
    assets = db.relationship('PendingAsset', backref='user_assets', lazy=True)

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    emailadmin = db.Column(db.String(50), unique=True, nullable=False)
    passwordadmin = db.Column(db.String(255), nullable=False)

class PendingAsset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    asset_name = db.Column(db.String(100), nullable=False)
    asset_type = db.Column(db.String(50), nullable=False)
    serial_number = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    purchase_date = db.Column(db.Date, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    value = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='Pending')

    # New column to associate the asset with a user
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='user_assets', lazy=True)

app.secret_key = secrets.token_hex(16)
app.config['SECRET_KEY'] = secrets.token_hex(16)

with app.app_context():
    db.create_all()

def is_logged_in():
    return 'user_id' in session

def admin_logged_in():
    return 'admin_id' in session
@app.route('/')
def landing():
    return render_template("land.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If the user is already logged in, redirect to the main page
    if is_logged_in():
        return redirect(url_for('dashboard'))

    # If the request method is POST, get the form data and validate it
    if request.method == 'POST':
        email = escape(request.form.get('email'))
        password = escape(request.form.get('password'))

        # Validate the reCAPTCHA response
        recaptcha_response = request.form.get('g-recaptcha-response')
        if not recaptcha_response:
            return render_template('login.html', message='Please complete the reCAPTCHA.')

        # Verify the reCAPTCHA response with Google
        recaptcha_secret_key = '6Ld-imEpAAAAABc3XPYm8uxYQghQz-Sv3LwVGf9h'  # Replace with your actual secret key
        recaptcha_url = 'https://www.google.com/recaptcha/api/siteverify'
        recaptcha_data = {
            'secret': recaptcha_secret_key,
            'response': recaptcha_response,
        }
        recaptcha_verification = requests.post(recaptcha_url, data=recaptcha_data)
        recaptcha_result = recaptcha_verification.json()

        if not recaptcha_result['success']:
            return render_template('login.html', message='Failed reCAPTCHA verification.')

        # Check if the email and password are not empty
        if not email or not password:
            return render_template('login.html', message='Please fill in all the fields.')

        # Check if the email exists in the database
        user = User.query.filter_by(email=email).first()
        if not user:
            return render_template('login.html', message='Invalid email or password.')

        # Check if the password matches the hashed password in the database
        if not bcrypt.check_password_hash(user.password, password):
            return render_template('login.html', message='Invalid email or password.')

        # Store the user id in the session and redirect to the main page
        session['user_id'] = user.id
        session['name'] = user.name
        return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/adminlogin', methods=['GET', 'POST'])
def adminlogin():
    # If the admin is already logged in, redirect to the index page
    if admin_logged_in():
        return redirect(url_for('index'))

    # If the request method is POST, get the form data and validate it
    if request.method == 'POST':
        email = escape(request.form.get('emailadmin'))
        password = escape(request.form.get('passwordadmin'))

        # Check if the email and password are not empty
        if not email or not password:
            flash('Please fill in all the fields.', 'error')
            return redirect(url_for('adminlogin'))

        # Query the database to find the admin by email
        admin = Admin.query.filter_by(emailadmin=email).first()

        # Check if the admin exists and the password is correct
        if admin and check_password_hash(admin.passwordadmin, password):
            # Store the admin id in the session and redirect to the index page
            session['admin_id'] = admin.id
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password.', 'error')
            return redirect(url_for('adminlogin'))

    return render_template('login.html')



@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    user_id = session.get('user_id')
    user_name = session.get('name')

    if request.method == 'POST':
        # Existing code for handling form data
        name = escape(request.form['asset_name'])
        asset_type = escape(request.form['asset_type'])
        serial_number = escape(request.form['serial_number'])
        location = escape(request.form['location'])
        purchase_date = escape(request.form['purchase_date'])
        quantity = int(escape(request.form['quantity']))
        value = float(escape(request.form['value']))

        # Create a new pending asset application
        pending_asset = PendingAsset(
            asset_name=name,
            asset_type=asset_type,
            serial_number=serial_number,
            location=location,
            purchase_date=purchase_date,
            quantity=quantity,
            value=value,
            user_id=user_id  # Associate the asset with the current user
        )
        db.session.add(pending_asset)
        db.session.commit()
        flash('Asset registration application submitted successfully!')
        return redirect(url_for('dashboard'))

    return render_template('dashboard.html', user_name=user_name, user_id=user_id)


@app.route('/view_assets')
def view_assets():
    user_id = session.get('user_id')
    user_name = session.get('name')

    # Debugging: Print user_id
    print("User ID:", user_id)

    # Check if the user exists in the database
    user = User.query.get(user_id)
    if user:
        # Update the query to use the correct relationship and filter by status
        print("User ID:", user_id)
        user_assets = PendingAsset.query.filter_by(user_id=user_id, status='Approved').all()
        print("User Assets:", user_assets)

        return render_template('view_assets.html', approved_assets=user_assets, user_name=user_name)
    else:
        # Handle the case where the user does not exist (e.g., redirect or display an error message)
        flash('User not found.', 'error')
        return redirect(url_for('login'))

@app.route('/delete_asset', methods=['POST'])
def delete_asset():
    asset_name = request.json.get('asset_name')
    if not asset_name:
        return jsonify({'success': False, 'error': 'Asset name is missing in the request.'}), 400

    try:
        # Use SQLAlchemy to query and delete the asset
        asset = PendingAsset.query.filter_by(asset_name=asset_name).first()
        if asset:
            db.session.delete(asset)
            db.session.commit()
            return jsonify({'success': True}), 200
        else:
            return jsonify({'success': False, 'error': 'Asset not found.'}), 404
    except Exception as e:
        print("Error:", str(e))
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Remove the user_id from the session
    return redirect(url_for('login'))  # Redirect to the login page


@app.route('/newUser', methods=['GET', 'POST'])
def newUser():
    # If the request method is POST, get the form data and validate it
    if request.method == 'POST':
        name = escape(request.form.get('name'))
        email = escape(request.form.get('email'))
        password = escape(request.form.get('password'))
        confirm = escape(request.form.get('confirm'))

        # Check if the name, email, and password are not empty
        if not name or not email or not password:
            return render_template('newUser.html', message='Please fill in all the fields.')

        # Check if the password and confirm password match
        if password != confirm:
            return render_template('newUser.html', message='Passwords do not match.')

        # Check if the email already exists in the database
        user = User.query.filter_by(email=email).first()
        if user:
            return render_template('newUser.html', message='Email already registered.')

        # Create a new user object with the hashed password
        user = User(name=name, email=email, password=generate_password_hash(password))

        # Add the user to the database and commit the changes
        db.session.add(user)
        db.session.commit()

        # Store the user id in the session and redirect to the main page
        session['user_id'] = user.id
        return redirect(url_for('newUser'))

    return render_template('newUser.html')


@app.route('/index')
def index():
    return render_template('index.html')


@app.route('/user')
def user():
    return render_template('user.html')


@app.route('/register')
def register():
    return render_template('register.html')


class ApplyAssetForm(FlaskForm):
    name = StringField('Asset Name', validators=[DataRequired()])
    description = TextAreaField('Description')
    submit = SubmitField('Apply')

def update_asset_status(asset_id, new_status):
    # Your implementation to update the asset status in the database
    pass

@app.route('/assetApproval', methods=['GET', 'POST'])
def assetApproval():
    form = ApplyAssetForm()
    if form.validate_on_submit():
        # Create a new PendingAsset object based on the form data
        name = escape(form.name.data)
        # Add other attributes based on the form fields

        pending_asset = PendingAsset(
            asset_name=name,
            # Add other attributes based on the form fields
        )
        db.session.add(pending_asset)
        db.session.commit()
        flash('Asset application submitted successfully!', 'success')
        return redirect(url_for('dashboard'))

    # Fetch pending assets from the database
    pending_assets = PendingAsset.query.filter_by(status='Pending').all()

    return render_template('assetApproval.html', title='Apply Asset', form=form, pending_assets=pending_assets)


@app.route('/approve_asset', methods=['POST'])
def approve_asset():
    asset_id = escape(request.json.get('asset_id'))
    if asset_id:
        asset = PendingAsset.query.get(asset_id)
        if asset:
            asset.status = 'Approved'
            db.session.commit()  # Commit changes to the database
            return jsonify({'success': True}), 200
    return jsonify({'success': False}), 400

@app.route('/reject_asset', methods=['POST'])
def reject_asset():
    asset_id = escape(request.json.get('asset_id'))
    if asset_id:
        asset = PendingAsset.query.get(asset_id)
        if asset:
            asset.status = 'Rejected'
            db.session.commit()  # Commit changes to the database
            return jsonify({'success': True}), 200
    return jsonify({'success': False}), 400

@app.route('/reset_password/<int:user_id>', methods=['GET', 'POST'])
def reset_password(user_id):
    user = User.query.get(user_id)

    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('login'))

    form = PasswordResetForm()

    if form.validate_on_submit():
        new_password = form.new_password.data
        confirm_password = form.confirm_password.data

        if new_password == confirm_password:
            # Update the user's password in the database
            user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            db.session.commit()

            flash('Your password has been successfully reset.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Passwords do not match.', 'error')

    return render_template('reset_password.html', form=form, user=user)

if __name__ == '__main__':
    app.run(debug=True)
