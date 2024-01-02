import secrets

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import mysql.connector
from flask_wtf import FlaskForm
from mysql.connector import connect
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from werkzeug.security import generate_password_hash, check_password_hash
import os

from wtforms import SubmitField, StringField, TextAreaField
from wtforms.validators import DataRequired

# MySQL database configuration
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '1234',
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


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)


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

    # Ensure that the routes for approving and rejecting assets are defined and reachable
    print(app.url_map)

    # Double-check the JavaScript functions to ensure they correctly send requests to the server
    # and handle the responses


# Set the secret key for the application using the app.secret_key attribute
app.secret_key = secrets.token_hex(16)

# Alternatively, you can set the secret key using the app.config['SECRET_KEY'] dictionary
app.config['SECRET_KEY'] = secrets.token_hex(16)

# Set up an application context with app.app_context()
with app.app_context():
    # Create the database tables by calling the db.create_all() method
    db.create_all()


def is_logged_in():
    return 'user_id' in session

def get_current_user():
    if is_logged_in():
        return User.query.get(session['user_id'])


# Define the route for the login page
@app.route('/', methods=['GET', 'POST'])
def login():
    # If the user is already logged in, redirect to the main page
    if is_logged_in():
        return redirect(url_for('dashboard'))

    # If the request method is POST, get the form data and validate it
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Check if the email and password are not empty
        if not email or not password:
            return render_template('login.html', message='Please fill in all the fields.')

        # Check if the email exists in the database
        user = User.query.filter_by(email=email).first()
        if not user:
            return render_template('login.html', message='Invalid email or password.')

        # Check if the password matches the hashed password in the database
        if not check_password_hash(user.password, password):
            return render_template('login.html', message='Invalid email or password.')

        # Store the user id in the session and redirect to the main page
        session['user_id'] = user.id
        session['name'] = user.name
        return redirect(url_for('dashboard'))
    return render_template('login.html')


# @app.route('/register', methods=['GET', 'POST'])
# def register():
#

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if request.method == 'POST':
        # Existing code for handling form data
        name = request.form['asset_name']
        asset_type = request.form['asset_type']
        serial_number = request.form['serial_number']
        location = request.form['location']
        purchase_date = request.form['purchase_date']
        quantity = int(request.form['quantity'])
        value = float(request.form['value'])

        # Create a new pending asset application
        pending_asset = PendingAsset(
            asset_name=name,
            asset_type=asset_type,
            serial_number=serial_number,
            location=location,
            purchase_date=purchase_date,
            quantity=quantity,
            value=value
        )
        db.session.add(pending_asset)
        db.session.commit()
        flash('Asset registration application submitted successfully!')
        return redirect(url_for('dashboard'))
    return render_template('dashboard.html')


@app.route('/view_assets')
def view_assets():
    approved_assets = PendingAsset.query.filter_by(status='Approved').all()
    return render_template('view_assets.html', approved_assets=approved_assets)

@app.route('/delete_asset', methods=['POST'])
def delete_asset():
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    try:
        asset_name = request.json.get('asset_name')
        if not asset_name:
            raise ValueError("Asset name is missing in the request.")

        # Use parameterized query to avoid SQL injection
        sql = "DELETE FROM assets WHERE asset_name = %s"
        cursor.execute(sql, (asset_name,))
        connection.commit()

        return jsonify({'success': True}), 200
    except Exception as e:
        print("Error:", str(e))
        connection.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        cursor.close()
        connection.close()


@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Remove the user_id from the session
    return redirect(url_for('login'))  # Redirect to the login page


@app.route('/newUser', methods=['GET', 'POST'])
def newUser():
    # If the request method is POST, get the form data and validate it
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm = request.form.get('confirm')

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
        pending_asset = PendingAsset(
            asset_name=form.name.data,
            # Add other attributes based on the form fields
        )
        db.session.add(pending_asset)
        db.session.commit()
        flash('Asset application submitted successfully!', 'success')
        return redirect(url_for('dashboard'))

    # Fetch pending assets from the database
    pending_assets = PendingAsset.query.all()

    return render_template('assetApproval.html', title='Apply Asset', form=form, pending_assets=pending_assets)


@app.route('/approve_asset', methods=['POST'])
def approve_asset():
    asset_id = request.json.get('asset_id')
    if asset_id:
        asset = PendingAsset.query.get(asset_id)
        if asset:
            asset.status = 'Approved'
            db.session.commit()  # Commit changes to the database
            return jsonify({'success': True}), 200
    return jsonify({'success': False}), 400

@app.route('/reject_asset', methods=['POST'])
def reject_asset():
    asset_id = request.json.get('asset_id')
    if asset_id:
        asset = PendingAsset.query.get(asset_id)
        if asset:
            asset.status = 'Rejected'
            db.session.commit()  # Commit changes to the database
            return jsonify({'success': True}), 200
    return jsonify({'success': False}), 400


if __name__ == '__main__':
    app.run(debug=True)
