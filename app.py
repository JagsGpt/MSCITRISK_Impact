# app.py
# --- DEBUG: CONFIRMING APP.PY LOAD ---
print("--- app.py LOADED: Version with 'manage_users' endpoint ---")
# --- END DEBUG ---

import os
import csv
import pandas as pd
import psycopg2
import psycopg2.extras # For DictCursor
import datetime
import re # For regular expressions to extract numbers from Risk Number

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, has_request_context

# has_request_context is important to check if we are in a request context
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# Import the license generator module
from license_generator import generate_license_hash

# --- Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_super_secret_key_here_replace_this' # Change this for production!
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 # 16 MB max upload size
app.port = 5006 # Application will run on port 5006

# Database connection configuration
DB_CONFIG = {
    'host': 'localhost',
    'database': 'ERM_DB',
    'user': 'postgres', # Default PostgreSQL user, change if yours is different
    'password': 'nist1',
    'port': '5432'
}

# Secret key for license hash generation and validation
# !!! IMPORTANT: This MUST match the key used in license_generator.py !!!
LICENSE_SECRET_KEY = "your_super_secret_license_key_replace_this_too"

# Ensure the upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# --- Flask-Login Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Redirect to login page if not authenticated

class User(UserMixin):
    def __init__(self, id, username, password_hash, role):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.role = role

    @staticmethod
    def get(user_id):
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, username, password_hash, role FROM users WHERE id = %s", (user_id,))
        user_data = cur.fetchone()
        cur.close()
        conn.close()
        if user_data:
            return User(user_data[0], user_data[1], user_data[2], user_data[3])
        return None

    @staticmethod
    def find_by_username(username):
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, username, password_hash, role FROM users WHERE username = %s", (username,))
        user_data = cur.fetchone()
        cur.close()
        conn.close()
        if user_data:
            return User(user_data[0], user_data[1], user_data[2], user_data[3])
        return None

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# --- Role-based Access Control (RBAC) Decorators ---
def role_required(roles):
    """
    Decorator to restrict access to routes based on user roles.
    `roles` can be a single role string or a list/tuple of role strings.
    """
    if not isinstance(roles, (list, tuple)):
        roles = [roles]

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('login'))
            if current_user.role not in roles:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('dashboard')) # Or any other appropriate redirect
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- Database Functions ---
def get_db_connection():
    """Establishes a connection to the PostgreSQL database."""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        return conn
    except psycopg2.Error as e:
        print(f"Database connection error: {e}")
        # Removed flash here as it's outside request context on app startup
        return None

def init_db():
    """Initializes the database tables (users and risk_items)."""
    conn = get_db_connection()
    if conn is None:
        print("Could not connect to database for initialization. Please check DB_CONFIG.")
        return

    cur = conn.cursor()
    try:
        # Create users table with new license-related columns
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(80) UNIQUE NOT NULL,
                password_hash VARCHAR(120) NOT NULL,
                role VARCHAR(20) NOT NULL DEFAULT 'VIEWER',
                expiry_date DATE,           -- New column for license expiry
                transaction_limit INTEGER   -- New column for license transaction limit
            );
        """)
        # Create risk_items table with the new column names from the image
        # Updated "Risk Discription" to "Risk Description" and added "Secondary Risk Owner"
        cur.execute("""
            CREATE TABLE IF NOT EXISTS risk_items (
                id SERIAL PRIMARY KEY,
                "Risk Number" VARCHAR(255) UNIQUE,
                "ISP Pillar" VARCHAR(255),
                "Goal" TEXT,
                "Risk Name" VARCHAR(255),
                "Due Date" DATE,
                "Status" VARCHAR(50),
                "Risk Description" TEXT,
                "Root Cause" TEXT,
                "Consequences" TEXT,
                "Risk Category (As per the approved RAT)" VARCHAR(255),
                "Impact" INTEGER,
                "Likelihood" INTEGER,
                "Inherent Exposure" INTEGER,
                "Inherent Rating" VARCHAR(50),
                "Control Effectiveness: How effective is the control in addressi" VARCHAR(50),
                "Residual Exposure (New)" VARCHAR(50),
                "Risk Owner" VARCHAR(255),
                "Secondary Risk Owner" VARCHAR(255), -- New column for secondary owner
                "Current Controls (What mechanism do we have in place to ensure the achievement of objectives?)" TEXT,
                "Type of Control (Preventative/Detective)" VARCHAR(50),
                "Control Frequency" VARCHAR(50),
                "Key Risk Indicator (KRI)" TEXT,
                "Action plan to further improve the Controls and Mitigate the Risk" TEXT,
                "Action Owner" VARCHAR(255),
                "Status Update Term1" TEXT,
                "Status Update Term2" TEXT,
                "Status Update Term3" TEXT,
                "Status Update Term4" TEXT
            );
        """)
        # New table for granular risk access
        cur.execute("""
            CREATE TABLE IF NOT EXISTS risk_access (
                id SERIAL PRIMARY KEY,
                risk_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                permission_level VARCHAR(10) NOT NULL, -- 'VIEWER' or 'EDITOR'
                UNIQUE (risk_id, user_id), -- A user can only have one explicit permission per risk
                FOREIGN KEY (risk_id) REFERENCES risk_items(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)


        # Add a default admin user if not exists
        cur.execute("SELECT id FROM users WHERE username = 'admin'")
        if cur.fetchone() is None:
            admin_password_hash = generate_password_hash('adminpass') # Default admin password
            cur.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
                ('admin', admin_password_hash, 'ADMINISTRATOR')
            )
            print("Default admin user created: username='admin', password='adminpass'")

        # Add a special 'License' user if not exists
        cur.execute("SELECT id FROM users WHERE username = 'License'")
        if cur.fetchone() is None:
            # For the 'License' user, password_hash will store the actual license hash
            # expiry_date and transaction_limit will store the license parameters
            cur.execute(
                "INSERT INTO users (username, password_hash, role, expiry_date, transaction_limit) VALUES (%s, %s, %s, %s, %s)",
                ('License', '', 'LICENSE_MANAGER', None, 0) # Initially blank license
            )
            print("Special 'License' user created.")

        conn.commit()
    except psycopg2.Error as e:
        conn.rollback()
        print(f"Database initialization error: {e}")
        # Removed flash here as it's outside request context on app startup
    finally:
        cur.close()
        conn.close()

def get_next_risk_number():
    """Fetches the highest numeric part of 'Risk Number' and returns it + 1."""
    conn = get_db_connection()
    if conn is None: return "1" # Default to 1 if no DB connection

    cur = conn.cursor()
    try:
        cur.execute('SELECT "Risk Number" FROM risk_items WHERE "Risk Number" IS NOT NULL;')
        risk_numbers = cur.fetchall()
        max_num = 0
        for rn_tuple in risk_numbers:
            rn_str = rn_tuple[0]
            # Extract all numbers from the string
            numbers = re.findall(r'\d+', rn_str)
            if numbers:
                # Take the last number found, convert to int, and compare
                try:
                    num = int(numbers[-1])
                    if num > max_num:
                        max_num = num
                except ValueError:
                    continue # Skip if conversion fails

        return str(max_num + 1)
    except Exception as e:
        print(f"Error getting next risk number: {e}")
        return "1" # Fallback to 1 on error
    finally:
        cur.close()
        conn.close()


def calculate_inherent_rating(exposure):
    """Calculates Inherent Rating based on Inherent Exposure."""
    if exposure is None:
        return None
    if 16 <= exposure <= 25:
        return "Extreme"
    elif 10 <= exposure <= 15:
        return "High"
    elif 5 <= exposure <= 9:
        return "Medium"
    elif 3 <= exposure <= 4:
        return "Low"
    elif 1 <= exposure <= 2:
        return "Housekeeping"
    else:
        return "N/A" # Or some other default for out-of-range values

def calculate_residual_exposure(inherent_rating, control_effectiveness):
    """Calculates Residual Exposure based on Inherent Rating and Control Effectiveness."""
    # Ensure inputs are strings and stripped of whitespace
    inherent_rating = str(inherent_rating).strip() if inherent_rating is not None else None
    control_effectiveness = str(control_effectiveness).strip() if control_effectiveness is not None else None

    if not inherent_rating or not control_effectiveness:
        return None

    # Define the mapping for Residual Exposure
    mapping = {
        "Housekeeping": {
            "Unsatisfactory": "Priority 3", "Weak": "Priority 3", "Satisfactory": "Priority 4",
            "Good": "Priority 5", "Very Good": "Priority 5"
        },
        "Low": {
            "Unsatisfactory": "Priority 2", "Weak": "Priority 3", "Satisfactory": "Priority 3",
            "Good": "Priority 4", "Very Good": "Priority 5"
        },
        "Medium": {
            "Unsatisfactory": "Priority 1", "Weak": "Priority 2", "Satisfactory": "Priority 3",
            "Good": "Priority 3", "Very Good": "Priority 4"
        },
        "High": {
            "Unsatisfactory": "Priority 1", "Weak": "Priority 1", "Satisfactory": "Priority 2",
            "Good": "Priority 2", "Very Good": "Priority 3"
        },
        "Extreme": {
            "Unsatisfactory": "Priority 1", "Weak": "Priority 1", "Satisfactory": "Priority 1",
            "Good": "Priority 2", "Very Good": "Priority 2"
        }
    }
    return mapping.get(inherent_rating, {}).get(control_effectiveness, None)


def clear_and_import_risks(file_path, is_initial_import=False):
    """
    Clears the risk_items table and imports data from a CSV or XLSX file.
    Assumes the file has a header row matching the table columns.
    `is_initial_import` is a flag to suppress flash messages if called during app startup.
    """
    conn = get_db_connection()
    if conn is None:
        if not is_initial_import and has_request_context():
            flash("Database connection failed for import.", 'danger')
        return False

    cur = conn.cursor()
    file_extension = None # Initialize file_extension
    try:
        # Determine file type and read accordingly
        file_extension = file_path.rsplit('.', 1)[1].lower()
        if file_path.endswith('.csv'):
            df = pd.read_csv(file_path)
        elif file_path.endswith('.xlsx'):
            df = pd.read_excel(file_path)
        else:
            if not is_initial_import and has_request_context():
                flash("Unsupported file type. Please provide a CSV or XLSX file.", 'danger')
            raise ValueError("Unsupported file type. Please provide a CSV or XLSX file.")

        # Clear existing data
        cur.execute("DELETE FROM risk_items;")
        print("Existing risk_items data cleared.")

        # Get the actual column names from the database
        cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name = 'risk_items' AND table_schema = 'public' ORDER BY ordinal_position;")
        db_column_names = [col[0] for col in cur.fetchall() if col[0].lower() != 'id'] # Exclude 'id'

        # Rename 'Risk Discription' to 'Risk Description' in DataFrame if it exists
        if 'Risk Discription' in df.columns and 'Risk Description' not in df.columns:
            df.rename(columns={'Risk Discription': 'Risk Description'}, inplace=True)

        # Filter DataFrame columns to match database columns and ensure order
        common_columns = [col for col in db_column_names if col in df.columns]
        df_filtered = df[common_columns]

        # Add "Inherent Exposure", "Inherent Rating", "Residual Exposure (New)" if not already in common_columns
        # These will be calculated during import
        if "Inherent Exposure" not in common_columns: common_columns.append("Inherent Exposure")
        if "Inherent Rating" not in common_columns: common_columns.append("Inherent Rating")
        if "Residual Exposure (New)" not in common_columns: common_columns.append("Residual Exposure (New)")
        # Ensure Secondary Risk Owner is handled during import if present in file, otherwise default to None
        if "Secondary Risk Owner" not in common_columns: common_columns.append("Secondary Risk Owner")


        placeholders = ', '.join(['%s'] * len(common_columns))
        insert_query = f"INSERT INTO risk_items ({', '.join([f'"{c}"' for c in common_columns])}) VALUES ({placeholders})"

        # Iterate over DataFrame rows and insert into DB
        for index, row in df_filtered.iterrows():
            row_data = []
            row_dict = row.to_dict() # Convert row to dict for easier access

            # Extract Impact and Likelihood, convert to int
            impact = int(row_dict.get('Impact')) if pd.notna(row_dict.get('Impact')) else None
            likelihood = int(row_dict.get('Likelihood')) if pd.notna(row_dict.get('Likelihood')) else None

            # Calculate Inherent Exposure and Rating
            inherent_exposure = (impact * likelihood) if impact is not None and likelihood is not None else None
            inherent_rating = calculate_inherent_rating(inherent_exposure)

            # Get Control Effectiveness for Residual Exposure calculation
            control_effectiveness = row_dict.get("Control Effectiveness: How effective is the control in addressi") # Updated column name
            # Strip whitespace for robust matching
            if control_effectiveness is not None:
                control_effectiveness = str(control_effectiveness).strip()

            residual_exposure = calculate_residual_exposure(inherent_rating, control_effectiveness)

            print(f"DEBUG (Import): Risk Number: {row_dict.get('Risk Number')}, Impact: {impact}, Likelihood: {likelihood}, Inherent Exposure: {inherent_exposure}, Inherent Rating: {inherent_rating}, Control Effectiveness: '{control_effectiveness}', Residual Exposure: '{residual_exposure}'")


            for col in common_columns:
                value = row_dict.get(col) # Use .get() for robustness

                if col == "Due Date" and pd.notna(value):
                    try:
                        value = pd.to_datetime(value).strftime('%Y-%m-%d')
                    except ValueError:
                        value = None
                elif col == "Impact" or col == "Likelihood":
                    value = int(value) if pd.notna(value) else None
                elif col == "Inherent Exposure":
                    value = inherent_exposure
                elif col == "Inherent Rating":
                    value = inherent_rating
                elif col == "Residual Exposure (New)":
                    value = residual_exposure
                elif pd.isna(value):
                    value = None
                row_data.append(value)

            cur.execute(insert_query, tuple(row_data))

        conn.commit()
        if not is_initial_import and has_request_context():
            flash(f"Successfully imported {len(df_filtered)} risk items from {file_extension.upper()} file!", 'success')
        print(f"Successfully imported {len(df_filtered)} risk items from {file_path}")
        return True
    except Exception as e:
        conn.rollback()
        print(f"Error importing risks: {e}")
        if not is_initial_import and has_request_context():
            display_file_ext = file_extension if file_extension is not None else 'file'
            flash(f"Error importing risks from {display_file_ext.upper()}: {e}", 'danger')
        return False
    finally:
        cur.close()
        conn.close()

def append_import_risks(file_path):
    """
    Appends data from a CSV or XLSX file to the existing risk_items table.
    Calculates derived fields.
    """
    conn = get_db_connection()
    if conn is None:
        if has_request_context():
            flash("Database connection failed for append import.", 'danger')
        return False

    cur = conn.cursor()
    file_extension = None # Initialize file_extension
    try:
        # Determine file type and read accordingly
        file_extension = file_path.rsplit('.', 1)[1].lower()
        if file_path.endswith('.csv'):
            df = pd.read_csv(file_path)
        elif file_path.endswith('.xlsx'):
            df = pd.read_excel(file_path)
        else:
            if has_request_context():
                flash("Unsupported file type. Please provide a CSV or XLSX file.", 'danger')
            raise ValueError("Unsupported file type. Please provide a CSV or XLSX file.")

        # Get the actual column names from the database
        cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name = 'risk_items' AND table_schema = 'public' ORDER BY ordinal_position;")
        db_column_names = [col[0] for col in cur.fetchall() if col[0].lower() != 'id'] # Exclude 'id'

        # Rename 'Risk Discription' to 'Risk Description' in DataFrame if it exists
        if 'Risk Discription' in df.columns and 'Risk Description' not in df.columns:
            df.rename(columns={'Risk Discription': 'Risk Description'}, inplace=True)

        # Filter DataFrame columns to match database columns and ensure order
        common_columns = [col for col in db_column_names if col in df.columns]
        df_filtered = df[common_columns]

        # Add "Inherent Exposure", "Inherent Rating", "Residual Exposure (New)" if not already in common_columns
        if "Inherent Exposure" not in common_columns: common_columns.append("Inherent Exposure")
        if "Inherent Rating" not in common_columns: common_columns.append("Inherent Rating")
        if "Residual Exposure (New)" not in common_columns: common_columns.append("Residual Exposure (New)")
        if "Secondary Risk Owner" not in common_columns: common_columns.append("Secondary Risk Owner")


        placeholders = ', '.join(['%s'] * len(common_columns))
        insert_query = f"INSERT INTO risk_items ({', '.join([f'"{c}"' for c in common_columns])}) VALUES ({placeholders})"

        inserted_count = 0
        for index, row in df_filtered.iterrows():
            row_data = []
            row_dict = row.to_dict()

            # Check if Risk Number already exists (for "append" logic)
            risk_number = row_dict.get("Risk Number")
            if risk_number:
                cur.execute('SELECT id FROM risk_items WHERE "Risk Number" = %s;', (risk_number,))
                if cur.fetchone():
                    print(f"Skipping existing Risk Number: {risk_number} during append import.")
                    continue # Skip if risk number already exists

            # Calculate derived fields
            impact = int(row_dict.get('Impact')) if pd.notna(row_dict.get('Impact')) else None
            likelihood = int(row_dict.get('Likelihood')) if pd.notna(row_dict.get('Likelihood')) else None
            inherent_exposure = (impact * likelihood) if impact is not None and likelihood is not None else None
            inherent_rating = calculate_inherent_rating(inherent_exposure)
            control_effectiveness = row_dict.get("Control Effectiveness: How effective is the control in addressi")
            if control_effectiveness is not None:
                control_effectiveness = str(control_effectiveness).strip()
            residual_exposure = calculate_residual_exposure(inherent_rating, control_effectiveness)

            for col in common_columns:
                value = row_dict.get(col)

                if col == "Due Date" and pd.notna(value):
                    try:
                        value = pd.to_datetime(value).strftime('%Y-%m-%d')
                    except ValueError:
                        value = None
                elif col == "Impact" or col == "Likelihood":
                    value = int(value) if pd.notna(value) else None
                elif col == "Inherent Exposure":
                    value = inherent_exposure
                elif col == "Inherent Rating":
                    value = inherent_rating
                elif col == "Residual Exposure (New)":
                    value = residual_exposure
                elif pd.isna(value):
                    value = None
                row_data.append(value)

            cur.execute(insert_query, tuple(row_data))
            inserted_count += 1

        conn.commit()
        if has_request_context():
            flash(f"Successfully appended {inserted_count} new risk items from {file_extension.upper()} file!", 'success')
        print(f"Successfully appended {inserted_count} new risk items from {file_path}")
        return True
    except Exception as e:
        conn.rollback()
        print(f"Error appending risks: {e}")
        if has_request_context():
            display_file_ext = file_extension if file_extension is not None else 'file'
            flash(f"Error appending risks from {display_file_ext.upper()}: {e}", 'danger')
        return False
    finally:
        cur.close()
        conn.close()


# --- License Validation Function ---
def validate_license():
    """
    Validates the application license based on the 'License' user's data.
    Checks expiry date and hash integrity.
    """
    conn = get_db_connection()
    if conn is None:
        print("License validation: DB connection failed.")
        return False # Cannot validate without DB

    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        cur.execute("SELECT password_hash, expiry_date, transaction_limit FROM users WHERE username = 'License';")
        license_data = cur.fetchone()

        if not license_data:
            print("License validation: 'License' user not found.")
            return False # License user not configured

        stored_hash = license_data['password_hash']
        expiry_date = license_data['expiry_date']
        transaction_limit = license_data['transaction_limit']

        if not stored_hash or not expiry_date or transaction_limit is None:
            print("License validation: Incomplete license data.")
            return False # License data incomplete

        # Check expiry date
        if expiry_date < datetime.date.today():
            print(f"License validation: Expired on {expiry_date}.")
            return False # License expired

        # Check transaction limit (assuming 0 means unlimited, or a specific minimum)
        # For simplicity, we'll assume a positive limit means valid, if you need to track usage,
        # you'd decrement this and check against 0.
        if transaction_limit <= 0:
            print("License validation: Transaction limit is zero or negative.")
            return False # Invalid transaction limit (or effectively no license)

        # Generate expected hash using the same logic as license_generator.py
        expected_hash = generate_license_hash(expiry_date.strftime('%Y-%m-%d'), transaction_limit, LICENSE_SECRET_KEY)

        if stored_hash != expected_hash:
            print("License validation: Hash mismatch.")
            return False # Hash mismatch

        print("License validation: License is valid.")
        return True # License is valid

    except Exception as e:
        print(f"License validation error: {e}")
        return False
    finally:
        cur.close()
        conn.close()


# --- CRUD Database Functions ---

def get_risk_by_id(risk_id):
    """
    Fetches a single risk by its ID, returning as a dictionary.
    Includes authorization check for non-ADMINISTRATOR roles.
    """
    conn = get_db_connection()
    if conn is None: return None
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor) # Use DictCursor to get dicts
    try:
        cur.execute('SELECT ri.*, ra.permission_level FROM risk_items ri LEFT JOIN risk_access ra ON ri.id = ra.risk_id AND ra.user_id = %s WHERE ri.id = %s', (current_user.id, risk_id))
        risk_data = cur.fetchone()

        if risk_data:
            risk_dict = dict(risk_data)
            for key, value in risk_dict.items():
                if isinstance(value, (datetime.date, datetime.datetime, pd.Timestamp)) and pd.notna(value):
                    risk_dict[key] = value.strftime('%Y-%m-%d')

            # Determine effective permission level for the current user on this specific risk
            effective_permission = None
            if current_user.role == 'ADMINISTRATOR':
                effective_permission = 'EDITOR' # Admins always have full control
            elif current_user.username == risk_dict.get('Risk Owner') or \
                 current_user.username == risk_dict.get('Secondary Risk Owner'):
                effective_permission = 'EDITOR' # Owners always have full control

            # Check explicit access from risk_access table
            explicit_permission = risk_dict.get('permission_level') # This comes from the LEFT JOIN
            if explicit_permission:
                if explicit_permission == 'EDITOR':
                    effective_permission = 'EDITOR'
                elif explicit_permission == 'VIEWER' and effective_permission != 'EDITOR':
                    # Only set to VIEWER if not already EDITOR (from role or ownership)
                    effective_permission = 'VIEWER'
            
            # If no explicit or ownership-based permission, default to VIEWER if user's role is VIEWER
            if not effective_permission and current_user.role == 'VIEWER':
                effective_permission = 'VIEWER'


            # Now, check if the current user has *any* effective permission to view this risk
            if effective_permission:
                # For editing/deleting, check if effective_permission is 'EDITOR'
                # For viewing, any effective_permission is enough
                risk_dict['can_edit_delete'] = (effective_permission == 'EDITOR')
                return risk_dict
            else:
                # Not authorized to view this specific risk at all
                if has_request_context():
                    flash("You are not authorized to view or edit this risk.", 'danger')
                return None
        return None # Risk not found
    except Exception as e:
        print(f"Error fetching risk by ID: {e}")
        return None
    finally:
        cur.close()
        conn.close()

def add_risk(data):
    """Inserts a new risk into the risk_items table."""
    conn = get_db_connection()
    if conn is None: return False
    cur = conn.cursor()
    try:
        # Validate Impact and Likelihood
        try:
            impact = int(data.get('Impact')) if data.get('Impact') else None
            likelihood = int(data.get('Likelihood')) if data.get('Likelihood') else None
            if impact is not None and not (1 <= impact <= 5):
                raise ValueError("Impact must be between 1 and 5.")
            if likelihood is not None and not (1 <= likelihood <= 5):
                raise ValueError("Likelihood must be between 1 and 5.")
        except (ValueError, TypeError) as e:
            if has_request_context():
                flash(f"Invalid Impact or Likelihood value: {e}", 'danger')
            return False

        # Calculate Inherent Exposure and Rating
        inherent_exposure = (impact * likelihood) if impact is not None and likelihood is not None else None
        inherent_rating = calculate_inherent_rating(inherent_exposure)

        # Get Control Effectiveness for Residual Exposure calculation
        control_effectiveness = data.get("Control Effectiveness: How effective is the control in addressi") # Updated column name
        # Strip whitespace for robust matching
        if control_effectiveness is not None:
            control_effectiveness = str(control_effectiveness).strip()

        residual_exposure = calculate_residual_exposure(inherent_rating, control_effectiveness)

        print(f"DEBUG (Add): Impact: {impact}, Likelihood: {likelihood}, Inherent Exposure: {inherent_exposure}, Inherent Rating: {inherent_rating}, Control Effectiveness: '{control_effectiveness}', Residual Exposure: '{residual_exposure}'")


        # Prepare data for insertion, including calculated fields
        insert_data = {}
        for col in data.keys():
            if col.lower() != 'id':
                insert_data[col] = data[col]

        # Explicitly set calculated fields in insert_data
        insert_data["Impact"] = impact
        insert_data["Likelihood"] = likelihood
        insert_data["Inherent Exposure"] = inherent_exposure
        insert_data["Inherent Rating"] = inherent_rating
        insert_data["Residual Exposure (New)"] = residual_exposure
        # Ensure Secondary Risk Owner is included
        insert_data["Secondary Risk Owner"] = data.get("Secondary Risk Owner")


        # Get the actual column names from the database to ensure correct order and inclusion
        cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name = 'risk_items' AND table_schema = 'public' ORDER BY ordinal_position;")
        db_column_names = [col[0] for col in cur.fetchall() if col[0].lower() != 'id']

        columns_to_insert = []
        values_to_insert = []
        for col_name in db_column_names:
            columns_to_insert.append(f'"{col_name}"')
            val_to_process = insert_data.get(col_name) # Use .get() to handle missing keys gracefully

            if col_name == "Due Date":
                if pd.notna(val_to_process):
                    try:
                        values_to_insert.append(pd.to_datetime(val_to_process).strftime('%Y-%m-%d'))
                    except ValueError:
                        values_to_insert.append(None)
                elif col_name == "Impact" or col_name == "Likelihood":
                    values_to_insert.append(int(val_to_process) if pd.notna(val_to_process) else None)
                elif col_name == "Inherent Exposure":
                    values_to_insert.append(inherent_exposure)
                elif col_name == "Inherent Rating":
                    values_to_insert.append(inherent_rating)
                elif col_name == "Residual Exposure (New)":
                    values_to_insert.append(residual_exposure)
                elif pd.isna(val_to_process):
                    values_to_insert.append(None)
                else:
                    values_to_insert.append(val_to_process)


        insert_query = f"INSERT INTO risk_items ({', '.join(columns_to_insert)}) VALUES ({', '.join(['%s'] * len(values_to_insert))})"
        cur.execute(insert_query, tuple(values_to_insert))
        conn.commit()
        if has_request_context():
            flash('Risk added successfully!', 'success')
        return True
    except Exception as e:
        conn.rollback()
        print(f"Error adding risk: {e}")
        if has_request_context():
            flash(f"Error adding risk: {e}", 'danger')
        return False
    finally:
        cur.close()
        conn.close()

def update_risk(data):
    """Updates an existing risk in the risk_items table."""
    conn = get_db_connection()
    if conn is None: return False
    cur = conn.cursor()
    try:
        # Before updating, perform authorization check
        # Note: get_risk_by_id will flash a message if unauthorized
        existing_risk = get_risk_by_id(data['id'])
        if not existing_risk or not existing_risk.get('can_edit_delete'): # Check explicit edit permission
            flash("You are not authorized to edit this risk.", 'danger')
            return False # Not authorized or risk not found

        # Validate Impact and Likelihood
        try:
            impact = int(data.get('Impact')) if data.get('Impact') else None
            likelihood = int(data.get('Likelihood')) if data.get('Likelihood') else None
            if impact is not None and not (1 <= impact <= 5):
                raise ValueError("Impact must be between 1 and 5.")
            if likelihood is not None and not (1 <= likelihood <= 5):
                raise ValueError("Likelihood must be between 1 and 5.")
        except (ValueError, TypeError) as e:
            if has_request_context():
                flash(f"Invalid Impact or Likelihood value: {e}", 'danger')
            return False

        # Calculate Inherent Exposure and Rating
        inherent_exposure = (impact * likelihood) if impact is not None and likelihood is not None else None
        inherent_rating = calculate_inherent_rating(inherent_exposure)

        # Get Control Effectiveness for Residual Exposure calculation
        control_effectiveness = data.get("Control Effectiveness: How effective is the control in addressi") # Updated column name
        # Strip whitespace for robust matching
        if control_effectiveness is not None:
            control_effectiveness = str(control_effectiveness).strip()

        residual_exposure = calculate_residual_exposure(inherent_rating, control_effectiveness)

        print(f"DEBUG (Update): Impact: {impact}, Likelihood: {likelihood}, Inherent Exposure: {inherent_exposure}, Inherent Rating: {inherent_rating}, Control Effectiveness: '{control_effectiveness}', Residual Exposure: '{residual_exposure}'")


        # Prepare data for update, including calculated fields
        update_data = {}
        for col in data.keys():
            if col.lower() != 'id':
                update_data[col] = data[col]

        # Explicitly set calculated fields in update_data
        update_data["Impact"] = impact
        update_data["Likelihood"] = likelihood
        update_data["Inherent Exposure"] = inherent_exposure
        update_data["Inherent Rating"] = inherent_rating
        update_data["Residual Exposure (New)"] = residual_exposure
        # Ensure Secondary Risk Owner is included
        update_data["Secondary Risk Owner"] = data.get("Secondary Risk Owner")


        set_clauses = []
        values = []

        # Get all actual column names from the database to ensure we update all relevant fields
        cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name = 'risk_items' AND table_schema = 'public' ORDER BY ordinal_position;")
        all_db_columns = [col[0] for col in cur.fetchall() if col[0].lower() != 'id']

        for col_name in all_db_columns:
            # Only include columns in the SET clause if they are present in update_data
            # This ensures that fields not submitted by the form (e.g., empty textareas)
            # are explicitly set to NULL if their value is empty or None.
            # If a field is not in update_data at all (e.g., if it's a calculated field
            # that wasn't in the original `data` dict from `request.form` but is now
            # explicitly added to `update_data`), it will be included.
            if col_name in update_data: # Only process if the column is in the update_data (from form or calculated)
                set_clauses.append(f'"{col_name}" = %s')
                val_to_process = update_data[col_name]

                if col_name == "Due Date":
                    if pd.notna(val_to_process):
                        try:
                            values.append(pd.to_datetime(val_to_process).strftime('%Y-%m-%d'))
                        except ValueError:
                            values.append(None)
                    else:
                        values.append(None)
                elif col_name in ["Impact", "Likelihood"]:
                    values.append(int(val_to_process) if pd.notna(val_to_process) else None)
                elif pd.isna(val_to_process): # Handle pandas NaT/NaN for general fields
                    values.append(None)
                else:
                    values.append(val_to_process)
            # If a DB column is not in update_data (e.g., if it was not part of the form submission
            # and is not a calculated field), it will be implicitly left unchanged by not including it in the SET clause.


        values.append(data['id']) # Add risk_id for WHERE clause
        update_query = f"UPDATE risk_items SET {', '.join(set_clauses)} WHERE id = %s"
        cur.execute(update_query, tuple(values))
        conn.commit()
        if has_request_context():
            flash('Risk updated successfully!', 'success')
        return True
    except Exception as e:
        conn.rollback()
        print(f"Error updating risk: {e}")
        if has_request_context():
            flash(f"Error updating risk: {e}", 'danger')
        return False
    finally:
        cur.close()
        conn.close()

def delete_risk(risk_id):
    """Deletes a risk from the risk_items table."""
    conn = get_db_connection()
    if conn is None: return False
    cur = conn.cursor()
    try:
        # Fetch risk to check authorization before deleting
        risk_to_delete = get_risk_by_id(risk_id) # This call now includes auth check
        if not risk_to_delete or not risk_to_delete.get('can_edit_delete'): # Check explicit delete permission
            flash("You are not authorized to delete this risk.", 'danger')
            return False

        cur.execute('DELETE FROM risk_items WHERE id = %s;', (risk_id,))
        conn.commit()
        if has_request_context():
            flash('Risk deleted successfully!', 'success')
        return True
    except Exception as e:
        conn.rollback()
        print(f"Error deleting risk: {e}")
        if has_request_context():
            flash(f"Error deleting risk: {e}", 'danger')
        return False
    finally:
        cur.close()
        conn.close()

# --- API Endpoints for Unique Column Values ---
@app.route('/api/unique_values/<column_name>')
@login_required
def get_unique_column_values(column_name):
    conn = get_db_connection()
    if conn is None:
        return jsonify({'error': 'Database connection failed'}), 500
    cur = conn.cursor()
    try:
        # Sanitize column_name to prevent SQL injection (though Flask's routing helps)
        # Ensure the column name is valid and quoted for PostgreSQL
        valid_columns = [
            "ISP Pillar", "Goal", "Risk Category (As per the approved RAT)",
            "Control Effectiveness: How effective is the control in addressi", # Updated column name
            "Type of Control (Preventative/Detective)", "Control Frequency",
            "Action Owner", "Status" # Risk Owner and Secondary Risk Owner are handled separately
        ]
        if column_name not in valid_columns:
            return jsonify({'error': 'Invalid column name'}), 400

        query = f'SELECT DISTINCT "{column_name}" FROM risk_items WHERE "{column_name}" IS NOT NULL ORDER BY "{column_name}";'
        cur.execute(query)
        values = [row[0] for row in cur.fetchall()]
        return jsonify(values)
    except Exception as e:
        print(f"Error fetching unique values for {column_name}: {e}")
        return jsonify({'error': f'Error fetching unique values: {e}'}), 500
    finally:
        cur.close()
        conn.close()

# --- API Endpoints for Chart Data ---
@app.route('/api/chart_data/inherent_residual')
@login_required
def get_inherent_residual_chart_data():
    conn = get_db_connection()
    if conn is None:
        return jsonify({'error': 'Database connection failed'}), 500
    cur = conn.cursor()
    try:
        # Query to get counts for each combination of Inherent Rating and Residual Exposure
        cur.execute("""
            SELECT
                "Inherent Rating",
                "Residual Exposure (New)",
                COUNT(*) as count
            FROM risk_items
            WHERE "Inherent Rating" IS NOT NULL AND "Residual Exposure (New)" IS NOT NULL
            GROUP BY "Inherent Rating", "Residual Exposure (New)"
            ORDER BY "Inherent Rating", "Residual Exposure (New)";
        """)
        data = cur.fetchall()
        # Convert to list of dictionaries for JSON
        chart_data = []
        for row in data:
            chart_data.append({
                "inherent_rating": row[0],
                "residual_exposure": row[1],
                "count": row[2]
            })
        return jsonify(chart_data)
    except Exception as e:
        print(f"Error fetching inherent/residual chart data: {e}")
        return jsonify({'error': f'Error fetching chart data: {e}'}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/api/chart_data/due_date_status')
@login_required
def get_due_date_status_chart_data():
    conn = get_db_connection()
    if conn is None:
        return jsonify({'error': 'Database connection failed'}), 500
    cur = conn.cursor()
    try:
        # Fetch all relevant data to calculate status in Python (more flexible)
        cur.execute('SELECT "Due Date" FROM risk_items WHERE "Due Date" IS NOT NULL;')
        due_dates = cur.fetchall()

        on_target_count = 0
        behind_schedule_count = 0
        current_date = datetime.date.today()

        for date_tuple in due_dates:
            due_date = date_tuple[0]
            if isinstance(due_date, datetime.datetime):
                due_date = due_date.date() # Convert datetime to date for comparison

            if due_date < current_date:
                behind_schedule_count += 1
            else:
                on_target_count += 1

        chart_data = [
            {"status": "Behind Schedule", "count": behind_schedule_count, "color": "red"},
            {"status": "On Target", "count": on_target_count, "color": "green"}
        ]
        return jsonify(chart_data)
    except Exception as e:
        print(f"Error fetching due date status chart data: {e}")
        return jsonify({'error': f'Error fetching chart data: {e}'}), 500
    finally:
        cur.close()
        conn.close()


# --- Routes ---

@app.route('/')
@login_required
def index():
    """Redirects to the dashboard if logged in."""
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.find_by_username(username)

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html', title='Login')

@app.route('/logout')
@login_required
def logout():
    """Handles user logout."""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Displays the main dashboard."""
    # Determine if the license is valid to pass to the template for display purposes
    is_licensed = validate_license()
    license_message = ""
    if not is_licensed:
        license_message = "Your license is invalid or expired. Only 5 risk items will be displayed."

    # Pass current_user.username and current_user.role to the template for JS access control
    return render_template('dashboard.html', title='Risk Dashboard', current_user=current_user,
                           is_licensed=is_licensed, license_message=license_message,
                           current_user_username=current_user.username,
                           current_user_role=current_user.role)

@app.route('/admin')
@login_required
@role_required('ADMINISTRATOR')
def admin_panel():
    """Displays the administrator panel."""
    # Fetch current license status and details for display
    conn = get_db_connection()
    license_status_msg = "License Not Configured"
    license_expiry_date = ""
    license_transaction_limit = ""
    # The stored hash itself is not displayed for security reasons, only its validity.

    if conn:
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        try:
            cur.execute("SELECT password_hash, expiry_date, transaction_limit FROM users WHERE username = 'License';")
            license_data = cur.fetchone()

            if license_data:
                stored_hash = license_data['password_hash']
                expiry_date = license_data['expiry_date']
                transaction_limit = license_data['transaction_limit']

                if not stored_hash or not expiry_date or transaction_limit is None:
                    license_status_msg = "License Incomplete"
                elif expiry_date < datetime.date.today():
                    license_status_msg = f"License Expired on {expiry_date.strftime('%Y-%m-%d')}"
                else:
                    # Attempt to validate to confirm hash
                    if validate_license(): # This call checks the hash internally
                        license_status_msg = f"License Active until {expiry_date.strftime('%Y-%m-%d')}"
                    else:
                        license_status_msg = "License Invalid (Hash Mismatch)"

                if expiry_date:
                    license_expiry_date = expiry_date.strftime('%Y-%m-%d')
                if transaction_limit is not None:
                    license_transaction_limit = str(transaction_limit)

            else:
                license_status_msg = "License User Not Found"
        except Exception as e:
            print(f"Error fetching license details for admin panel: {e}")
            license_status_msg = f"Error: {e}"
        finally:
            cur.close()
            conn.close()

    return render_template('admin.html', title='Admin Panel', current_user=current_user,
                           license_status=license_status_msg,
                           license_expiry_date=license_expiry_date,
                           license_transaction_limit=license_transaction_limit)

@app.route('/admin/set_license', methods=['POST'])
@login_required
@role_required('ADMINISTRATOR')
def set_license():
    """
    Handles setting or updating the application license.
    Validates the provided license_key against the provided expiry_date and transaction_limit.
    """
    expiry_date_str = request.form.get('expiry_date')
    transaction_limit_str = request.form.get('transaction_limit')
    provided_license_key = request.form.get('license_key') # New: Get the hash from the form

    if not expiry_date_str or not transaction_limit_str or not provided_license_key:
        flash("Expiry date, transaction limit, and license key are all required.", 'danger')
        return redirect(url_for('admin_panel'))

    try:
        expiry_date = datetime.datetime.strptime(expiry_date_str, '%Y-%m-%d').date()
        transaction_limit = int(transaction_limit_str)
        if transaction_limit < 0:
            raise ValueError("Transaction limit cannot be negative.")
    except (ValueError, TypeError) as e:
        flash(f"Invalid input for license: {e}", 'danger')
        return redirect(url_for('admin_panel'))

    # Generate the expected hash based on the provided date and limit
    expected_hash = generate_license_hash(expiry_date_str, transaction_limit, LICENSE_SECRET_KEY)

    # Compare the provided license key with the expected hash
    if provided_license_key != expected_hash:
        flash("Invalid License Key: The provided key does not match the expiry date and transaction limit.", 'danger')
        return redirect(url_for('admin_panel'))

    conn = get_db_connection()
    if conn is None:
        flash("Database connection failed for license update.", 'danger')
        return redirect(url_for('admin_panel'))
    cur = conn.cursor()
    try:
        # If we reach here, the provided_license_key is valid for the given date and limit
        cur.execute(
            "UPDATE users SET password_hash = %s, expiry_date = %s, transaction_limit = %s WHERE username = 'License';",
            (provided_license_key, expiry_date, transaction_limit) # Store the provided_license_key
        )
        conn.commit()
        flash("License updated successfully!", 'success')
    except Exception as e:
        conn.rollback()
        print(f"Error updating license: {e}")
        flash(f"Error updating license: {e}", 'danger')
    finally:
        cur.close()
        conn.close()
    return redirect(url_for('admin_panel'))


@app.route('/api/upload_risks', methods=['POST'])
@login_required
@role_required('ADMINISTRATOR')
def upload_risks():
    """API endpoint to clear and upload new risk data."""
    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(request.url)

    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(request.url)

    # Allowed extensions for import
    allowed_extensions = {'csv', 'xlsx'}
    file_extension = file.filename.rsplit('.', 1)[1].lower() # Define file_extension here

    if file and file_extension in allowed_extensions:
        filename = f'uploaded_risks.{file_extension}' # Standardize filename with correct extension
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Call clear_and_import_risks without suppressing flash messages (as it's in a request context)
        if clear_and_import_risks(filepath, is_initial_import=False):
            flash(f'Risk data successfully cleared and imported from {file_extension.upper()} file!', 'success')
            return redirect(url_for('admin_panel'))
        else:
            # clear_and_import_risks now handles its own flash message on failure
            return redirect(request.url)
    else:
        flash('Invalid file type. Please upload a CSV or XLSX file.', 'danger')
        return redirect(request.url)

@app.route('/api/append_risks', methods=['POST'])
@login_required
@role_required('ADMINISTRATOR')
def append_risks_route():
    """API endpoint to append new risk data to existing."""
    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(request.url)

    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(request.url)

    allowed_extensions = {'csv', 'xlsx'}
    file_extension = file.filename.rsplit('.', 1)[1].lower() # Define file_extension here

    if file and file_extension in allowed_extensions:
        filename = f'appended_risks.{file_extension}'
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        if append_import_risks(filepath):
            flash(f'Risk data successfully appended from {file_extension.upper()} file!', 'success')
            return redirect(url_for('admin_panel'))
        else:
            # append_import_risks now handles its own flash message on failure
            return redirect(request.url)
    else:
        flash('Invalid file type. Please upload a CSV or XLSX file.', 'danger')
        return redirect(request.url)


@app.route('/api/risks/bulk_update_owner', methods=['POST'])
@login_required
@role_required(['ADMINISTRATOR', 'EDITOR']) # Only admin/editor can bulk update
def api_bulk_update_risk_owner():
    """API endpoint to bulk update the Risk Owner for selected risks."""
    risk_ids = request.json.get('risk_ids')
    new_owner = request.json.get('new_owner')
    update_type = request.json.get('update_type', 'primary') # 'primary' or 'secondary'

    if not risk_ids or not new_owner:
        return jsonify({'success': False, 'message': 'Missing risk IDs or new owner.'}), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({'success': False, 'message': 'Database connection failed.'}), 500
    cur = conn.cursor()
    try:
        updated_count = 0
        for risk_id in risk_ids:
            # Fetch the risk to perform authorization check
            # Note: get_risk_by_id checks current_user's ownership/admin status
            risk_to_update = get_risk_by_id(risk_id)
            if not risk_to_update or not risk_to_update.get('can_edit_delete'): # Ensure user has edit permission
                # Skip if not authorized or risk not found (message already flashed by get_risk_by_id)
                print(f"Skipping risk {risk_id}: Not authorized or not found for bulk update.")
                continue

            if update_type == 'primary':
                cur.execute(
                    'UPDATE risk_items SET "Risk Owner" = %s WHERE id = %s;',
                    (new_owner, risk_id)
                )
            elif update_type == 'secondary':
                cur.execute(
                    'UPDATE risk_items SET "Secondary Risk Owner" = %s WHERE id = %s;',
                    (new_owner, risk_id)
                )
            else:
                return jsonify({'success': False, 'message': 'Invalid update type.'}), 400

            if cur.rowcount > 0:
                updated_count += 1
        conn.commit()
        return jsonify({'success': True, 'message': f'Successfully updated {updated_count} risks.'})
    except Exception as e:
        conn.rollback()
        print(f"Error bulk updating risks: {e}")
        return jsonify({'success': False, 'message': f'Error bulk updating risks: {e}'}), 500
    finally:
        cur.close()
        conn.close()


@app.route('/api/risk_owners')
@login_required
def get_risk_owners():
    """
    API endpoint to get unique risk owners from the risk_items table.
    Combines primary and secondary owners for the dashboard main dropdown.
    """
    conn = get_db_connection()
    if conn is None:
        return jsonify({'error': 'Database connection failed'}), 500
    cur = conn.cursor()
    try:
        # Fetch unique primary risk owners from risk_items
        cur.execute('SELECT DISTINCT "Risk Owner" FROM risk_items WHERE "Risk Owner" IS NOT NULL;')
        primary_owners = [row[0] for row in cur.fetchall()]

        # Fetch unique secondary risk owners from risk_items
        cur.execute('SELECT DISTINCT "Secondary Risk Owner" FROM risk_items WHERE "Secondary Risk Owner" IS NOT NULL;')
        secondary_owners = [row[0] for row in cur.fetchall()]

        # Combine and get unique list, then sort
        all_owners = sorted(list(set(primary_owners + secondary_owners)))
        return jsonify(all_owners)
    except Exception as e:
        print(f"Error fetching risk owners for dashboard dropdown: {e}")
        return jsonify({'error': f'Error fetching risk owners: {e}'}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/api/primary_risk_owners')
@login_required
def get_primary_risk_owners():
    """API endpoint to get unique primary risk owners from the risk_items table."""
    conn = get_db_connection()
    if conn is None:
        return jsonify({'error': 'Database connection failed'}), 500
    cur = conn.cursor()
    try:
        cur.execute('SELECT DISTINCT "Risk Owner" FROM risk_items WHERE "Risk Owner" IS NOT NULL ORDER BY "Risk Owner";')
        owners = [row[0] for row in cur.fetchall()]
        return jsonify(owners)
    except Exception as e:
        print(f"Error fetching primary risk owners: {e}")
        return jsonify({'error': f'Error fetching primary risk owners: {e}'}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/api/secondary_risk_owners')
@login_required
def get_secondary_risk_owners():
    """API endpoint to get unique secondary risk owners from the risk_items table."""
    conn = get_db_connection()
    if conn is None:
        return jsonify({'error': 'Database connection failed'}), 500
    cur = conn.cursor()
    try:
        cur.execute('SELECT DISTINCT "Secondary Risk Owner" FROM risk_items WHERE "Secondary Risk Owner" IS NOT NULL ORDER BY "Secondary Risk Owner";')
        owners = [row[0] for row in cur.fetchall()]
        return jsonify(owners)
    except Exception as e:
        print(f"Error fetching secondary risk owners: {e}")
        return jsonify({'error': f'Error fetching secondary risk owners: {e}'}), 500
    finally:
        cur.close()
        conn.close()


@app.route('/api/all_risks_for_dashboard')
@login_required
def get_all_risks_for_dashboard():
    """
    API endpoint to get all risk items for the dashboard,
    filtered by primary and/or secondary owner, and applying license limit.
    """
    conn = get_db_connection()
    if conn is None:
        return jsonify({'error': 'Database connection failed'}), 500
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        is_licensed = validate_license()
        limit_clause = "LIMIT 5" if not is_licensed else "" # Apply limit if license is not valid

        primary_owner_filter = request.args.get('primary_owner')
        secondary_owner_filter = request.args.get('secondary_owner')

        where_clauses = []
        query_params = []

        # Base authorization filter for non-admins
        if current_user.role != 'ADMINISTRATOR':
            # User must be either primary or secondary owner OR have explicit access
            where_clauses.append('("Risk Owner" = %s OR "Secondary Risk Owner" = %s OR id IN (SELECT risk_id FROM risk_access WHERE user_id = %s))')
            query_params.extend([current_user.username, current_user.username, current_user.id])
        
        # Add primary owner filter if specified and not 'all_risks'
        if primary_owner_filter and primary_owner_filter != 'all_risks':
            where_clauses.append('"Risk Owner" = %s')
            query_params.append(primary_owner_filter)
        
        # Add secondary owner filter if specified and not 'all_risks'
        if secondary_owner_filter and secondary_owner_filter != 'all_risks':
            where_clauses.append('"Secondary Risk Owner" = %s')
            query_params.append(secondary_owner_filter)

        # Construct the full WHERE clause
        full_where_clause = ""
        if where_clauses:
            full_where_clause = " WHERE " + " AND ".join(where_clauses)
        
        # Construct the final query
        query = f'SELECT * FROM risk_items {full_where_clause} {limit_clause};'
        
        cur.execute(query, tuple(query_params))
        
        risks_data = cur.fetchall()

        risks = []
        for row in risks_data:
            risk_dict = dict(row)
            for key, value in risk_dict.items():
                if isinstance(value, (datetime.date, datetime.datetime, pd.Timestamp)) and pd.notna(value):
                    risk_dict[key] = value.strftime('%Y-%m-%d')
            risks.append(risk_dict)

        return jsonify(risks)
    except Exception as e:
        print(f"Error fetching all risks for dashboard: {e}")
        return jsonify({'error': f'Error fetching all risks for dashboard: {e}'}), 500
    finally:
        cur.close()
        conn.close()


@app.route('/api/all_risks')
@login_required
def get_all_risks():
    """
    API endpoint to get all risk items (primarily for column names).
    This endpoint is NOT limited by license, as it's used to determine table structure.
    """
    conn = get_db_connection()
    if conn is None:
        return jsonify({'error': 'Database connection failed'}), 500
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor) # Use DictCursor
    try:
        # Fetch only one row to get column names reliably
        cur.execute('SELECT * FROM risk_items LIMIT 1;')
        sample_risk = cur.fetchone()

        if sample_risk:
            # Convert DictRow to a regular dictionary
            risk_dict = dict(sample_risk)
            # Return a list containing this single dictionary
            return jsonify([risk_dict])
        else:
            # If table is empty, return an an empty list or a placeholder with expected columns
            # To get column names even if table is empty, we can query information_schema
            cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name = 'risk_items' AND table_schema = 'public' ORDER BY ordinal_position;")
            column_names = [col[0] for col in cur.fetchall()]
            # Create a dummy dictionary with None values for all columns
            empty_risk_dict = {col: None for col in column_names}
            return jsonify([empty_risk_dict]) # Return a structure with column names

    except Exception as e:
        print(f"Error fetching all risks (for columns): {e}")
        return jsonify({'error': f'Error fetching all risks (for columns): {e}'}), 500
    finally:
        cur.close()
        conn.close()

# --- CRUD Routes ---

@app.route('/risk/add', methods=['GET', 'POST'])
@login_required
@role_required(['ADMINISTRATOR', 'EDITOR'])
def add_risk_route():
    """Handles adding a new risk."""
    if request.method == 'POST':
        risk_data = {key: request.form[key] for key in request.form.keys()}
        if add_risk(risk_data):
            # Flash message handled inside add_risk now
            return redirect(url_for('dashboard'))
        else:
            # If add_risk fails, the flash message is already set by add_risk
            # Re-render the form with the data that was submitted and dropdowns
            dropdown_data = fetch_all_dropdown_data()
            # Fetch all usernames for Risk Owner and Secondary Risk Owner dropdowns
            risk_owners_list = get_all_active_usernames() # This fetches from users table for form
            return render_template('risk_form.html', title='Add New Risk', risk=risk_data, current_user=current_user, form_action=url_for('add_risk_route'), dropdown_data=dropdown_data, risk_owners_list=risk_owners_list)
    else:
        # Get all column names to populate empty form for new risk
        conn = get_db_connection()
        if conn is None:
            if has_request_context():
                flash('Database connection error.', 'danger')
            return redirect(url_for('dashboard'))
        cur = conn.cursor()
        try:
            cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name = 'risk_items' AND table_schema = 'public' ORDER BY ordinal_position;")
            column_names = [col[0] for col in cur.fetchall() if col[0].lower() != 'id']
            empty_risk = {col: '' for col in column_names} # Create an empty dict for the form
        except Exception as e:
            print(f"Error fetching column names for add form: {e}")
            if has_request_context():
                flash('Error preparing add risk form.', 'danger')
            empty_risk = {}
        finally:
            cur.close()
            conn.close()

        # Get the next available risk number
        next_risk_num = get_next_risk_number()
        empty_risk["Risk Number"] = next_risk_num

        # Fetch unique values for dropdowns
        dropdown_data = fetch_all_dropdown_data()
        # Fetch all usernames for Risk Owner and Secondary Risk Owner dropdowns
        risk_owners_list = get_all_active_usernames() # This fetches from users table for form
        return render_template('risk_form.html', title='Add New Risk', risk=empty_risk, current_user=current_user, form_action=url_for('add_risk_route'), dropdown_data=dropdown_data, risk_owners_list=risk_owners_list)

@app.route('/risk/edit/<int:risk_id>', methods=['GET', 'POST'])
@login_required
@role_required(['ADMINISTRATOR', 'EDITOR', 'VIEWER']) # VIEWER can access if they are owner
def edit_risk_route(risk_id):
    """Handles editing an existing risk."""
    risk = get_risk_by_id(risk_id) # This function now handles authorization
    if not risk:
        # get_risk_by_id will have flashed a message if unauthorized
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # Re-check authorization for POST request as well
        # This prevents a user from getting the form, then someone else changing owner, then they submit
        if current_user.role != 'ADMINISTRATOR':
            original_risk = get_risk_by_id(risk_id) # Fetch original to check ownership
            if not original_risk or not original_risk.get('can_edit_delete'): # Check effective permission
                flash("You are not authorized to edit this risk.", 'danger')
                return redirect(url_for('dashboard'))

        risk_data = {key: request.form[key] for key in request.form.keys()}
        # Pass risk_id to update_risk
        risk_data['id'] = risk_id
        if update_risk(risk_data):
            # Flash message handled inside update_risk now
            return redirect(url_for('dashboard'))
        else:
            # If update_risk fails, the flash message is already set by update_risk
            # Re-render form with current data and errors and dropdowns
            dropdown_data = fetch_all_dropdown_data()
            # Fetch all usernames for Risk Owner and Secondary Risk Owner dropdowns
            risk_owners_list = get_all_active_usernames() # This fetches from users table for form
            return render_template('risk_form.html', title='Edit Risk', risk=risk_data, current_user=current_user, form_action=url_for('edit_risk_route', risk_id=risk_id), dropdown_data=dropdown_data, risk_owners_list=risk_owners_list)
    else:
        # Fetch unique values for dropdowns
        dropdown_data = fetch_all_dropdown_data()
        # Fetch all usernames for Risk Owner and Secondary Risk Owner dropdowns
        risk_owners_list = get_all_active_usernames() # This fetches from users table for form
        # Also fetch explicit access users for the form
        explicit_access_users = get_risk_explicit_access(risk_id)

        return render_template('risk_form.html', title='Edit Risk', risk=risk, current_user=current_user, form_action=url_for('edit_risk_route', risk_id=risk_id), dropdown_data=dropdown_data, risk_owners_list=risk_owners_list, explicit_access_users=explicit_access_users)

@app.route('/risk/delete/<int:risk_id>', methods=['POST'])
@login_required
@role_required(['ADMINISTRATOR', 'EDITOR', 'VIEWER']) # VIEWER can access if they are owner
def delete_risk_route(risk_id):
    """Handles deleting a risk."""
    # Authorization check is now handled within delete_risk function itself via get_risk_by_id
    if delete_risk(risk_id):
        pass # Flash message handled inside delete_risk now
    else:
        pass # Flash message handled inside delete_risk now
    return redirect(url_for('dashboard'))

def fetch_all_dropdown_data():
    """Helper function to fetch all unique values for dropdowns."""
    dropdown_data = {}
    dropdown_columns = [
        "ISP Pillar", "Goal", "Risk Category (As per the approved RAT)",
        "Control Effectiveness: How effective is the control in addressi", # Updated column name
        "Type of Control (Preventative/Detective)", "Control Frequency",
        "Action Owner", "Status" # Risk Owner and Secondary Risk Owner are handled separately
    ]
    for col in dropdown_columns:
        # Call get_unique_column_values directly, which handles its own DB connection
        # and returns a Flask Response object. We need to extract the JSON data.
        response = get_unique_column_values(col)
        if response.status_code == 200:
            dropdown_data[col] = response.json
        else:
            dropdown_data[col] = [] # Fallback to empty list on error
    return dropdown_data

def get_all_active_usernames():
    """Fetches all usernames from the 'users' table (excluding 'License') for use in dropdowns."""
    conn = get_db_connection()
    if conn is None: return []
    cur = conn.cursor()
    try:
        cur.execute("SELECT username FROM users WHERE username != 'License' ORDER BY username;")
        usernames = [row[0] for row in cur.fetchall()]
        return usernames
    except Exception as e:
        print(f"Error fetching all active usernames: {e}")
        return []
    finally:
        cur.close()
        conn.close()

# --- Risk Access Management Functions (New) ---
def get_risk_explicit_access(risk_id):
    """Fetches users with explicit access to a specific risk."""
    conn = get_db_connection()
    if conn is None: return []
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        cur.execute("""
            SELECT u.id as user_id, u.username, ra.permission_level
            FROM risk_access ra
            JOIN users u ON ra.user_id = u.id
            WHERE ra.risk_id = %s ORDER BY u.username;
        """, (risk_id,))
        access_users = [dict(row) for row in cur.fetchall()]
        return access_users
    except Exception as e:
        print(f"Error fetching explicit access for risk {risk_id}: {e}")
        return []
    finally:
        cur.close()
        conn.close()

def add_explicit_risk_access(risk_id, username, permission_level):
    """Adds explicit access for a user to a risk."""
    conn = get_db_connection()
    if conn is None: return False
    cur = conn.cursor()
    try:
        cur.execute("SELECT id FROM users WHERE username = %s;", (username,))
        user_data = cur.fetchone()
        if not user_data:
            if has_request_context():
                flash(f"User '{username}' not found.", 'danger')
            return False
        user_id = user_data[0]

        # Prevent adding access for 'admin' or 'License' (they have implicit access/special role)
        if username == 'admin' or username == 'License':
            if has_request_context():
                flash(f"Cannot explicitly assign access to system user '{username}'.", 'danger')
            return False

        cur.execute("""
            INSERT INTO risk_access (risk_id, user_id, permission_level)
            VALUES (%s, %s, %s)
            ON CONFLICT (risk_id, user_id) DO UPDATE SET permission_level = EXCLUDED.permission_level;
        """, (risk_id, user_id, permission_level))
        conn.commit()
        if has_request_context():
            flash(f"Access for '{username}' ({permission_level}) added/updated successfully for this risk.", 'success')
        return True
    except Exception as e:
        conn.rollback()
        print(f"Error adding explicit access for risk {risk_id}, user {username}: {e}")
        if has_request_context():
            flash(f"Error adding explicit access: {e}", 'danger')
        return False
    finally:
        cur.close()
        conn.close()

def remove_explicit_risk_access(risk_id, user_id):
    """Removes explicit access for a user from a risk."""
    conn = get_db_connection()
    if conn is None: return False
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM risk_access WHERE risk_id = %s AND user_id = %s;", (risk_id, user_id))
        conn.commit()
        if has_request_context():
            flash("Explicit access removed successfully.", 'success')
        return True
    except Exception as e:
        conn.rollback()
        print(f"Error removing explicit access for risk {risk_id}, user {user_id}: {e}")
        if has_request_context():
            flash(f"Error removing explicit access: {e}", 'danger')
        return False
    finally:
        cur.close()
        conn.close()


# --- User Management Functions (Existing from previous turn) ---
def get_all_users_from_db():
    """Fetches all users from the database."""
    conn = get_db_connection()
    if conn is None: return []
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        cur.execute("SELECT id, username, role FROM users ORDER BY username;")
        users = [dict(row) for row in cur.fetchall()]
        return users
    except Exception as e:
        print(f"Error fetching all users: {e}")
        return []
    finally:
        cur.close()
        conn.close()

def get_user_details_from_db(user_id):
    """Fetches a single user's details by ID."""
    conn = get_db_connection()
    if conn is None: return None
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        cur.execute("SELECT id, username, role FROM users WHERE id = %s;", (user_id,))
        user = cur.fetchone()
        return dict(user) if user else None
    except Exception as e:
        print(f"Error fetching user details: {e}")
        return None
    finally:
        cur.close()
        conn.close()

def create_user_in_db(username, password, role):
    """Creates a new user in the database."""
    conn = get_db_connection()
    if conn is None: return False
    cur = conn.cursor()
    try:
        # Check if username already exists
        cur.execute("SELECT id FROM users WHERE username = %s;", (username,))
        if cur.fetchone():
            if has_request_context():
                flash(f"Username '{username}' already exists.", 'danger')
            return False

        password_hash = generate_password_hash(password)
        cur.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s);",
            (username, password_hash, role)
        )
        conn.commit()
        if has_request_context():
            flash(f"User '{username}' created successfully!", 'success')
        return True
    except Exception as e:
        conn.rollback()
        print(f"Error creating user: {e}")
        if has_request_context():
            flash(f"Error creating user: {e}", 'danger')
        return False
    finally:
        cur.close()
        conn.close()

def update_user_in_db(user_id, username, new_password, new_role):
    """Updates an existing user in the database."""
    conn = get_db_connection()
    if conn is None: return False
    cur = conn.cursor()
    try:
        # Prevent changing username or role of 'admin' or 'License' user via this function
        cur.execute("SELECT username FROM users WHERE id = %s;", (user_id,))
        current_user_data = cur.fetchone()
        if current_user_data and (current_user_data[0] == 'admin' or current_user_data[0] == 'License'):
            if has_request_context():
                flash(f"Cannot modify system user '{current_user_data[0]}' via user management. Use License Management section for 'License'.", 'danger')
            return False

        # Check if new username already exists for another user
        cur.execute("SELECT id FROM users WHERE username = %s AND id != %s;", (username, user_id))
        if cur.fetchone():
            if has_request_context():
                flash(f"Username '{username}' already exists for another user.", 'danger')
            return False

        if new_password:
            password_hash = generate_password_hash(new_password)
            cur.execute(
                "UPDATE users SET username = %s, password_hash = %s, role = %s WHERE id = %s;",
                (username, password_hash, new_role, user_id)
            )
        else:
            cur.execute(
                "UPDATE users SET username = %s, role = %s WHERE id = %s;",
                (username, new_role, user_id)
            )
        conn.commit()
        if has_request_context():
            flash(f"User '{username}' updated successfully!", 'success')
        return True
    except Exception as e:
        conn.rollback()
        print(f"Error updating user: {e}")
        if has_request_context():
            flash(f"Error updating user: {e}", 'danger')
        return False
    finally:
        cur.close()
        conn.close()

def delete_user_from_db(user_id):
    """Deletes a user from the database."""
    conn = get_db_connection()
    if conn is None: return False
    cur = conn.cursor()
    try:
        # Prevent deleting 'admin' or 'License' user
        cur.execute("SELECT username FROM users WHERE id = %s;", (user_id,))
        user_to_delete = cur.fetchone()
        if user_to_delete and (user_to_delete[0] == 'admin' or user_to_delete[0] == 'License'):
            if has_request_context():
                flash(f"Cannot delete system user '{user_to_delete[0]}'.", 'danger')
            return False

        cur.execute("DELETE FROM users WHERE id = %s;", (user_id,))
        conn.commit()
        if has_request_context():
            flash("User deleted successfully!", 'success')
        return True
    except Exception as e:
        conn.rollback()
        print(f"Error deleting user: {e}")
        if has_request_context():
            flash(f"Error deleting user: {e}", 'danger')
        return False
    finally:
        cur.close()
        conn.close()


# --- User Management Routes (New) ---
# Renamed from user_management to manage_users to avoid potential conflicts
@app.route('/admin/users')
@login_required
@role_required('ADMINISTRATOR')
def manage_users(): # Renamed function
    """Displays the user management panel."""
    print("DEBUG: Accessing manage_users route.") # Debug print
    return render_template('admin_users.html', title='User Management', current_user=current_user, roles=['ADMINISTRATOR', 'EDITOR', 'VIEWER', 'LICENSE_MANAGER'])

@app.route('/api/users')
@login_required
@role_required('ADMINISTRATOR')
def api_get_users():
    """API endpoint to get all users."""
    users = get_all_users_from_db()
    return jsonify(users)

@app.route('/api/users/<int:user_id>')
@login_required
@role_required('ADMINISTRATOR')
def api_get_user(user_id):
    """API endpoint to get a single user's details."""
    user = get_user_details_from_db(user_id)
    if user:
        return jsonify(user)
    return jsonify({'error': 'User not found'}), 404

@app.route('/admin/users/add', methods=['POST'])
@login_required
@role_required('ADMINISTRATOR')
def add_user_route():
    """Handles adding a new user."""
    username = request.form['username']
    password = request.form['password']
    role = request.form['role']

    if not username or not password or not role:
        flash("Username, password, and role are required.", 'danger')
        return redirect(url_for('manage_users')) # Redirect to new endpoint name

    if create_user_in_db(username, password, role):
        pass # Flash message handled in function
    return redirect(url_for('manage_users')) # Redirect to new endpoint name

@app.route('/api/users/<int:user_id>', methods=['POST']) # Changed to POST for consistency with other updates
@login_required
@role_required('ADMINISTRATOR')
def api_edit_user(user_id): # New API endpoint for editing via fetch
    """API endpoint to edit a user."""
    username = request.json.get('username')
    new_password = request.json.get('password')
    role = request.json.get('role')

    if not username or not role:
        return jsonify({'success': False, 'message': "Username and role are required."}), 400

    if update_user_in_db(user_id, username, new_password, role):
        return jsonify({'success': True, 'message': f"User '{username}' updated successfully!"})
    else:
        # Error message is flashed by update_user_in_db
        return jsonify({'success': False, 'message': "Failed to update user. Check server logs."}), 500


@app.route('/admin/users/edit/<int:user_id>', methods=['POST']) # Keep this route for direct form submission fallback
@login_required
@role_required('ADMINISTRATOR')
def edit_user_route(): # Removed user_id from args as it's in URL
    """Handles editing an existing user (form submission fallback)."""
    # This route is less preferred now that frontend uses fetch for userForm submission
    # but kept as a fallback if JS fails or for direct POSTs.
    user_id = request.form.get('user_id') # Get from hidden input
    if not user_id:
        flash("User ID is missing for edit.", 'danger')
        return redirect(url_for('manage_users'))

    username = request.form['username']
    new_password = request.form.get('password') # Optional, only if changing
    role = request.form['role']

    if not username or not role:
        flash("Username and role are required.", 'danger')
        return redirect(url_for('manage_users'))

    if update_user_in_db(user_id, username, new_password, role):
        pass # Flash message handled in function
    return redirect(url_for('manage_users')) # Redirect to new endpoint name


@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@role_required('ADMINISTRATOR')
def delete_user_route(user_id):
    """Handles deleting a user."""
    if delete_user_from_db(user_id):
        pass # Flash message handled in function
    return redirect(url_for('manage_users')) # Redirect to new endpoint name


# --- API Endpoints for Risk Access Management (New) ---
@app.route('/api/risk/<int:risk_id>/access')
@login_required
def api_get_risk_access(risk_id):
    """API endpoint to get users with explicit access to a specific risk."""
    # Only admins can view this list
    if current_user.role != 'ADMINISTRATOR':
        return jsonify({'error': 'Unauthorized'}), 403
    
    access_users = get_risk_explicit_access(risk_id)
    return jsonify(access_users)

@app.route('/api/risk/<int:risk_id>/access/add', methods=['POST'])
@login_required
@role_required('ADMINISTRATOR') # Only admins can manage explicit access
def api_add_risk_access(risk_id):
    """API endpoint to add explicit access for a user to a risk."""
    username = request.json.get('username')
    permission_level = request.json.get('permission_level')

    if not username or not permission_level:
        return jsonify({'success': False, 'message': 'Missing username or permission level.'}), 400
    
    # Ensure permission level is valid
    if permission_level not in ['VIEWER', 'EDITOR']:
        return jsonify({'success': False, 'message': 'Invalid permission level.'}), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({'success': False, 'message': 'Database connection failed.'}), 500
    
    cur = conn.cursor()
    try:
        cur.execute("SELECT id FROM users WHERE username = %s;", (username,))
        user_data = cur.fetchone()
        if not user_data:
            return jsonify({'success': False, 'message': f"User '{username}' not found."}), 404
        user_id = user_data[0]

        # Prevent adding access for 'admin' or 'License' (they have implicit access/special role)
        if username == 'admin' or username == 'License':
            return jsonify({'success': False, 'message': f"Cannot explicitly assign access to system user '{username}'."}), 400

        cur.execute("""
            INSERT INTO risk_access (risk_id, user_id, permission_level)
            VALUES (%s, %s, %s)
            ON CONFLICT (risk_id, user_id) DO UPDATE SET permission_level = EXCLUDED.permission_level;
        """, (risk_id, user_id, permission_level))
        conn.commit()
        return jsonify({'success': True, 'message': f"Access for '{username}' ({permission_level}) added/updated successfully."})
    except Exception as e:
        conn.rollback()
        print(f"Error adding explicit access: {e}")
        return jsonify({'success': False, 'message': f"Error adding explicit access: {e}"}), 500
    finally:
        cur.close()
        conn.close()


@app.route('/api/risk/<int:risk_id>/access/remove', methods=['POST'])
@login_required
@role_required('ADMINISTRATOR') # Only admins can manage explicit access
def api_remove_risk_access(risk_id):
    """API endpoint to remove explicit access for a user from a risk."""
    user_id = request.json.get('user_id')

    if not user_id:
        return jsonify({'success': False, 'message': 'Missing user ID.'}), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({'success': False, 'message': 'Database connection failed.'}), 500
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM risk_access WHERE risk_id = %s AND user_id = %s;", (risk_id, user_id))
        conn.commit()
        if cur.rowcount > 0:
            return jsonify({'success': True, 'message': 'Explicit access removed successfully.'})
        else:
            return jsonify({'success': False, 'message': 'Explicit access not found for this user and risk.'}), 404
    except Exception as e:
        conn.rollback()
        print(f"Error removing explicit access: {e}")
        return jsonify({'success': False, 'message': f"Error removing explicit access: {e}"}), 500
    finally:
        cur.close()
        conn.close()


# --- Main ---
if __name__ == '__main__':
    # Initialize database tables on application start
    with app.app_context(): # This context is crucial for Flask extensions like Flask-Login to work during startup
        init_db()

        # Initial import of the provided CSV if the table is empty
        conn = get_db_connection()
        if conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM risk_items;")
            count = cur.fetchone()[0]
            cur.close()
            conn.close()

            if count == 0:
                print("Risk items table is empty. Attempting initial import from 'Risk.xlsx - ict services operational.csv'...")
                # IMPORTANT: If your initial file is now an XLSX, update this path accordingly.
                # Example: initial_file_path = os.path.join(os.getcwd(), 'Risk.xlsx')
                initial_file_path = os.path.join(os.getcwd(), 'Risk.xlsx - ict services operational.csv')
                if os.path.exists(initial_file_path):
                    # Pass is_initial_import=True to suppress flash messages
                    if clear_and_import_risks(initial_file_path, is_initial_import=True):
                        print("Initial import successful!")
                    else:
                        print("Initial import failed. Please check the file and database connection.")
                else:
                    print(f"File not found at {initial_file_path}. Please ensure it's in the same directory as app.py.")
            else:
                print(f"Risk items table already contains {count} records. Skipping initial import.")


    app.run(debug=True, host='0.0.0.0', port=app.port)
