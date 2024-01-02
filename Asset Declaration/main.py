# app.py

from flask import Flask, render_template, request, redirect, url_for, session,flash, jsonify
import mysql.connector
from mysql.connector import connect
from flask_sqlalchemy import SQLAlchemy
import os

# MySQL database configuration
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '1234',
    'database': 'assets'
}

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

db = SQLAlchemy(app)

@app.route('/')
#@app.route('/', methods=['GET', 'POST'])
def login():
    # if request.method == 'POST':
    #     username = request.form['username']
    #     adminusername = request.form['adminusername']
    #     password = request.form['password']
    #     adminpassword = request.form['adminpassword']
    #
    #     # Implement actual authentication logic here
    #     # For simplicity, let's assume a hardcoded username and password
    #     if username == 'admin' and password == 'password':
    #         session['username'] = username
    #         return redirect(url_for('dashboard'))
    #
    #     elif:
    #         adminusername == 'adminusername' and adminpassword == 'adminpassword':
    #         session['adminusername'] = admminusername
    #         return redirect(url_for('dashboard'))
    #
    #     else:
    #         return render_template('login.html', error='Invalid username or password')

    # Handle GET request (e.g., when initially accessing the login page)
    return render_template("login.html", error=None)

# Route for registering assets
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    # if 'username' not in session:
    #     return redirect(url_for('login'))

    # Connect to the database
    connection = connect(**db_config)
    cursor = connection.cursor()

    if request.method == 'POST':
        # Existing code for handling form data
        name = request.form['asset_name']
        asset_type = request.form['asset_type']
        serial_number = request.form['serial_number']
        location = request.form['location']
        purchase_date = request.form['purchase_date']
        quantity = int(request.form['quantity'])
        value = float(request.form['value'])

        # Handle file upload
        file = request.files['file']
        if file:
            # Create the 'uploads' directory if it doesn't exist
            upload_folder = os.path.join(app.root_path, 'uploads')
            os.makedirs(upload_folder, exist_ok=True)

            # Save the file to the 'uploads' folder
            file_path = os.path.join(upload_folder, file.filename)
            file.save(file_path)

        try:
            # Existing code for inserting data into the database
            sql = "INSERT INTO assets (asset_name, asset_type, serial_number, location, purchase_date, quantity, value) VALUES (%s, %s, %s, %s, %s, %s, %s)"
            values = (name, asset_type, serial_number, location, purchase_date, quantity, value)
            cursor.execute(sql, values)
            connection.commit()
            flash('Asset registered successfully!')
        except Exception as e:
            print("Error:", str(e))
            connection.rollback()
            flash('Error registering asset.')

    try:
        # Fetch existing assets from the database
        cursor.execute("SELECT asset_name, asset_type, serial_number, location, purchase_date, quantity, value FROM assets")
        assets = cursor.fetchall()
    except Exception as e:
        print("Error:", str(e))
        return "Error fetching asset data."
    finally:
        cursor.close()
        connection.close()

    return render_template('dashboard.html', assets=assets)

@app.route('/view_assets')
def view_assets():
    # if 'username' not in session:
    #     return redirect(url_for('view_assets'))

    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    # Fetch existing assets from the database
    try:
        cursor.execute(
            "SELECT asset_name, asset_type, serial_number, location, purchase_date, quantity, value FROM assets")
        assets = cursor.fetchall()
        cursor.close()
        connection.close()
        return render_template('view_assets.html', assets=assets)

    except Exception as e:
        print("Error fetching asset data:", str(e))
        connection.close()
        return "Error fetching asset data."

    print("Fetched assets:", assets)


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
    # session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/newUser')
def newUser():
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

@app.route('/assetApproval')
def assetApproval():
    return render_template('assetApproval.html')

if __name__ == '__main__':
    app.run(debug=True)