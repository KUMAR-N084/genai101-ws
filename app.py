from flask import Flask, render_template, request, jsonify, redirect, url_for, make_response, flash, session
from flask_sqlalchemy import SQLAlchemy
import requests
from datetime import datetime, timedelta, date as dt_date
import json
import re
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from collections import Counter

app = Flask(__name__)
app.config['SECRET_KEY'] = 'YOUR_SUPER_SECRET_KEY_HERE_REPLACE_ME' # <--- IMPORTANT: REPLACE THIS WITH A STRONG, UNIQUE KEY!
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///weather_app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    default_city = db.Column(db.String(100), nullable=True)
    settings = db.Column(db.JSON, nullable=True, default=lambda: {}) # Added for user settings (e.g., notification preferences)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # Added for password reset token
    def get_reset_token(self, expires_sec=1800):
        return s.dumps({'user_id': self.id}, expires_sec=expires_sec)

    @staticmethod
    def verify_reset_token(token):
        try:
            data = s.loads(token)
        except (SignatureExpired, BadTimeSignature):
            return None
        return User.query.get(data['user_id'])


@app.route('/')
def index():
    username = None
    logged_in = False
    default_city_from_db = None
    current_theme = request.cookies.get('theme', 'light') # Get theme from cookie

    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            username = user.username
            logged_in = True
            default_city_from_db = user.default_city

    # Provide a hardcoded default city if not logged in and no user-specific default city is set
    if not logged_in or not default_city_from_db:
        default_city_for_frontend = "London" # Or any other city you prefer as a global default
    else:
        default_city_for_frontend = default_city_from_db

    return render_template('index.html',
                           username=username,
                           logged_in=logged_in,
                           defaultCityFromServer=default_city_for_frontend, # Use this variable in script.js
                           current_theme=current_theme)
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['username'] = user.username
            session['user_id'] = user.id
            flash('Logged in successfully!', 'success')

            # Set theme cookie based on user's preference or default
            response = make_response(jsonify(success=True, message='Logged in successfully!'))
            theme = user.settings.get('theme', 'light') # Get user's preferred theme
            response.set_cookie('theme', theme, max_age=60*60*24*365) # 1 year
            return response
        else:
            return jsonify(success=False, message='Invalid username or password.'), 401
    current_theme = request.cookies.get('theme', 'light') # Get theme from cookie for GET request
    return render_template('login.html', logged_in='username' in session, current_theme=current_theme)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if not username or not email or not password or not confirm_password:
            return jsonify(success=False, message='All fields are required.'), 400
        if password != confirm_password:
            return jsonify(success=False, message='Passwords do not match.'), 400
        if len(password) < 6:
            return jsonify(success=False, message='Password must be at least 6 characters.'), 400
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return jsonify(success=False, message='Invalid email format.'), 400

        if User.query.filter_by(username=username).first():
            return jsonify(success=False, message='Username already exists.'), 409
        if User.query.filter_by(email=email).first():
            return jsonify(success=False, message='Email already registered.'), 409

        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        try:
            db.session.commit()
            return jsonify(success=True, message='Registration successful! Please log in.'), 201
        except Exception as e:
            db.session.rollback()
            return jsonify(success=False, message='Registration failed due to a server error.'), 500
    current_theme = request.cookies.get('theme', 'light') # Get theme from cookie for GET request
    return render_template('register.html', logged_in='username' in session, current_theme=current_theme)

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    # Clear the theme cookie on logout to revert to default or allow browser to set
    response = make_response(redirect(url_for('login')))
    response.set_cookie('theme', '', expires=0) # Expires immediately
    flash('You have been logged out.', 'info')
    return response

@app.route('/profile')
def profile():
    if 'username' not in session:
        flash('Please log in to view your profile.', 'error')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('login'))

    current_theme = request.cookies.get('theme', 'light')
    return render_template('profile.html', logged_in=True, username=session['username'],
                           user=user, current_theme=current_theme)


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'user_id' not in session:
        flash('Please log in to view settings.', 'error')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Check if it's a JSON request for theme update
        if request.is_json:
            data = request.get_json()
            new_theme = data.get('theme')
            if new_theme in ['light', 'dark']:
                if 'settings' not in user.settings:
                    user.settings = {} # Ensure settings is a mutable dictionary
                user.settings['theme'] = new_theme
                try:
                    db.session.commit()
                    # Set the theme cookie immediately for persistence across pages
                    response = make_response(jsonify(success=True, message='Theme updated successfully!'))
                    response.set_cookie('theme', new_theme, max_age=60*60*24*365) # 1 year
                    return response
                except Exception as e:
                    db.session.rollback()
                    return jsonify(success=False, message='Failed to save theme: ' + str(e)), 500
            else:
                return jsonify(success=False, message='Invalid theme value.'), 400

        # Handle form submission for default city or other settings
        default_city = request.form.get('default_city')
        # Add other form fields here if you have them, e.g., notification settings

        user.default_city = default_city
        
        # Example for saving notification settings from a form
        rain_alert = 'rain_alert' in request.form
        user.settings['rain_alert'] = rain_alert
        # ... other notification settings

        try:
            db.session.commit()
            flash('Settings updated successfully!', 'success')
            return redirect(url_for('settings'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {e}', 'error')
            return redirect(url_for('settings'))

    current_theme = request.cookies.get('theme', 'light')
    return render_template('settings.html',
                           username=user.username,
                           user=user,
                           current_theme=current_theme,
                           logged_in=True)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.json.get('email')
        if not email:
            return jsonify(success=False, message='Email is required.'), 400

        user = User.query.filter_by(email=email).first()
        if user:
            # In a real app, you would generate a token and send a password reset email here.
            # For this example, we'll just acknowledge the request.
            # token = user.get_reset_token()
            # send_password_reset_email(user.email, token) # You'd implement this function
            return jsonify(success=True, message='If an account with that email exists, a password reset link has been sent.')
        else:
            return jsonify(success=False, message='If an account with that email exists, a password reset link has been sent.')
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    user = User.verify_reset_token(token)
    if not user:
        flash('That is an invalid or expired token.', 'error')
        return render_template('password_reset.html', token_valid=False)

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not new_password or not confirm_password:
            flash('Both new password and confirm password are required.', 'error')
            return render_template('password_reset.html', token_valid=True, token=token)

        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('password_reset.html', token_valid=True, token=token)

        if len(new_password) < 6:
            flash('New password must be at least 6 characters.', 'error')
            return render_template('password_reset.html', token_valid=True, token=token)

        user.set_password(new_password) # Hash and set the new password
        try:
            db.session.commit()
            flash('Your password has been reset successfully! Please log in with your new password.', 'success')
            return redirect(url_for('login')) # Redirect to login page
        except Exception as e:
            db.session.rollback()
            print(f"Error resetting password in DB: {e}")
            flash('Failed to reset password due to a database error. Please try again.', 'error')
            return render_template('password_reset.html', token_valid=True, token=token)

    # For GET request (displaying the reset form)
    return render_template('password_reset.html', token_valid=True, token=token)

# API endpoint to fetch weather data (client-side)
@app.route('/get_weather')
def get_weather():
    city = request.args.get('city')
    lat = request.args.get('lat')
    lon = request.args.get('lon')
    units = request.args.get('units', 'metric')
    
    # --- IMPORTANT ---
    # Replace the placeholder below with your actual OpenWeatherMap API key.
    api_key = 'c30d188bc17fc21f941f2cb60629c583' 

    if not api_key or api_key == 'YOUR_OPENWEATHERMAP_API_KEY_HERE':
        return jsonify({"error": "API key not configured. Please add your API key in app.py."}), 500

    if city:
        current_weather_url = f"http://api.openweathermap.org/data/2.5/weather?q={city}&appid={api_key}&units={units}"
        forecast_url = f"http://api.openweathermap.org/data/2.5/forecast?q={city}&appid={api_key}&units={units}"
    elif lat and lon:
        current_weather_url = f"http://api.openweathermap.org/data/2.5/weather?lat={lat}&lon={lon}&appid={api_key}&units={units}"
        forecast_url = f"http://api.openweathermap.org/data/2.5/forecast?lat={lat}&lon={lon}&appid={api_key}&units={units}"
    else:
        return jsonify({"error": "City name or coordinates are required."}), 400

    try:
        current_response = requests.get(current_weather_url)
        current_response.raise_for_status() # Raise an exception for HTTP errors
        current_data = current_response.json()

        forecast_response = requests.get(forecast_url)
        forecast_response.raise_for_status()
        forecast_data = forecast_response.json()

        return jsonify({"current": current_data, "forecast": forecast_data})
    except requests.exceptions.HTTPError as http_err:
        error_message = f"HTTP error occurred: {http_err} - {http_err.response.text}"
        print(error_message)
        # Check for 404 specifically
        if http_err.response.status_code == 404:
             return jsonify({"error": f"City not found. Please check the spelling."}), 404
        return jsonify({"error": "City not found or API error.", "details": http_err.response.text}), http_err.response.status_code
    except requests.exceptions.ConnectionError as conn_err:
        error_message = f"Connection error occurred: {conn_err}"
        print(error_message)
        return jsonify({"error": "Network connection error. Please check your internet connection."}), 503
    except Exception as err:
        error_message = f"An unexpected error occurred: {err}"
        print(error_message)
        return jsonify({"error": "An unexpected error occurred."}), 500

@app.route('/get_city_suggestions')
def get_city_suggestions():
    query = request.args.get('q', '')
    if not query:
        return jsonify([])

    api_key = 'c30d188bc17fc21f941f2cb60629c583' # Use your OpenWeatherMap API key here
    if not api_key or api_key == 'c30d188bc17fc21f941f2cb60629c583':
        return jsonify({"error": "API key not configured."}), 500

    # OpenWeatherMap's 'find' endpoint is good for city suggestions
    find_url = f"http://api.openweathermap.org/data/2.5/find?q={query}&type=like&sort=population&cnt=10&appid={api_key}"

    try:
        response = requests.get(find_url)
        response.raise_for_status()
        data = response.json()
        suggestions = []
        if data and data.get('list'):
            for city_data in data['list']:
                name = city_data.get('name')
                country = city_data.get('sys', {}).get('country')
                if name and country:
                    suggestions.append(f"{name}, {country}")
        return jsonify(suggestions)
    except requests.exceptions.RequestException as e:
        print(f"Error fetching city suggestions: {e}")
        return jsonify({"error": "Failed to fetch city suggestions."}), 500

# Run the Flask app
if __name__ == '__main__':
    # Ensure database tables are created when the app starts
    with app.app_context():
        db.create_all()
    app.run(debug=True)