from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
from flask_migrate import Migrate
from werkzeug.utils import secure_filename
import pandas as pd
from msal import ConfidentialClientApplication
from flask_session import Session
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')

# Get DATABASE_URL from Fly.io environment
database_url = os.getenv('DATABASE_URL')
if database_url:
    # Replace postgres:// with postgresql:// for SQLAlchemy
    database_url = database_url.replace("postgres://", "postgresql://", 1)
    print(f"Database URL configured: {database_url[:15]}...")  # Log partial URL for debugging
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_pre_ping': True,
        'pool_size': 5,
        'pool_timeout': 30,
        'pool_recycle': 1800,
    }
else:
    print("WARNING: No DATABASE_URL found, using SQLite")
    database_url = 'sqlite:///users.db'
    # SQLite-specific configuration without pooling options
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_pre_ping': True,
    }

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    auth_method = db.Column(db.String(20), default='local')  # 'local' or 'microsoft'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='sha256')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Policy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reference_number = db.Column(db.String(20), nullable=True)
    name = db.Column(db.String(100), nullable=False)
    version = db.Column(db.String(20), nullable=False)
    date = db.Column(db.Date, nullable=False)
    url = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class PolicyAssignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    policy_id = db.Column(db.Integer, db.ForeignKey('policy.id'), nullable=False)
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)
    acknowledged_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), default='pending')  # pending, acknowledged

    user = db.relationship('User', backref='policy_assignments')
    policy = db.relationship('Policy', backref='assignments')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create tables and admin user only if they don't exist
with app.app_context():
    # Let migrations handle table creation instead
    # db.create_all()  # Comment out or remove this line
    
    # Check if admin user exists
    admin = User.query.filter_by(username="scott.suine@osmodal.com").first()
    if not admin:
        # Create admin user
        admin = User(
            username="scott.suine@osmodal.com",
            first_name="Scott",
            last_name="Suine",
            is_admin=True
        )
        admin.set_password("jack8765")
        db.session.add(admin)
        db.session.commit()

    # Remove or comment out the test policy creation code
    # test_policy1 = Policy(...)
    # ...

@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_policies'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_policies'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully.')
            
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('user_policies'))
        
        flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    active_tab = request.args.get('active_tab', 'users-section')
    users = User.query.all()
    policies = Policy.query.order_by(Policy.date.desc()).all()
    
    # Get admin's own policy assignments
    admin_assignments = PolicyAssignment.query.filter_by(user_id=current_user.id).all()
    
    # Group assignments by user
    assignments_by_user = {}
    all_assignments = PolicyAssignment.query.join(User).join(Policy).order_by(PolicyAssignment.assigned_at.desc()).all()
    
    for assignment in all_assignments:
        if assignment.user not in assignments_by_user:
            assignments_by_user[assignment.user] = []
        assignments_by_user[assignment.user].append(assignment)
    
    return render_template('admin/dashboard.html', 
                         users=users, 
                         policies=policies, 
                         assignments_by_user=assignments_by_user,
                         admin_assignments=admin_assignments,
                         active_tab=active_tab)

@app.route('/admin/users/add', methods=['POST'])
@login_required
def add_user():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    username = request.form.get('username')
    password = request.form.get('password')
    first_name = request.form.get('first_name')
    last_name = request.form.get('last_name')
    is_admin = request.form.get('is_admin') == 'on'
    
    if User.query.filter_by(username=username).first():
        flash('Username already exists')
        return redirect(url_for('admin_dashboard'))
    
    if not all([username, password, first_name, last_name]):
        flash('All fields are required')
        return redirect(url_for('admin_dashboard'))
    
    user = User(
        username=username,
        first_name=first_name,
        last_name=last_name,
        is_admin=is_admin
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    
    flash('User added successfully')
    current_tab = request.form.get('current_tab', 'users-section')
    return redirect(url_for('admin_dashboard', active_tab=current_tab))

@app.route('/policies')
@login_required
def user_policies():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    assignments = PolicyAssignment.query.filter_by(user_id=current_user.id).all()
    return render_template('user/policies.html', assignments=assignments)

@app.route('/admin/users/edit/<int:user_id>', methods=['POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        return redirect(url_for('user_policies'))
    
    user = User.query.get_or_404(user_id)
    
    user.username = request.form.get('username')
    user.first_name = request.form.get('first_name')
    user.last_name = request.form.get('last_name')
    user.is_admin = request.form.get('is_admin') == 'on'
    
    if request.form.get('password'):
        user.set_password(request.form.get('password'))
    
    try:
        db.session.commit()
        flash('User updated successfully')
    except Exception as e:
        db.session.rollback()
        flash('Error updating user')
        print(f"Error updating user: {e}")
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return redirect(url_for('user_policies'))
    
    user = User.query.get_or_404(user_id)
    
    # Prevent deleting self
    if user.id == current_user.id:
        flash('You cannot delete your own account')
        return redirect(url_for('admin_dashboard'))
    
    try:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting user')
        print(f"Error deleting user: {e}")
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/policies/add', methods=['POST'])
@login_required
def add_policy():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    try:
        policy = Policy(
            reference_number=request.form.get('reference_number'),
            name=request.form.get('name'),
            version=request.form.get('version'),
            date=datetime.strptime(request.form.get('date'), '%Y-%m-%d'),
            url=request.form.get('url')
        )
        db.session.add(policy)
        db.session.commit()
        flash('Policy added successfully')
    except Exception as e:
        db.session.rollback()
        flash('Error adding policy')
        print(f"Error adding policy: {e}")
    
    current_tab = request.form.get('current_tab', 'policies-section')
    return redirect(url_for('admin_dashboard', active_tab=current_tab))

@app.route('/admin/policies/edit/<int:policy_id>', methods=['POST'])
@login_required
def edit_policy(policy_id):
    if not current_user.is_admin:
        return redirect(url_for('user_policies'))
    
    policy = Policy.query.get_or_404(policy_id)
    
    try:
        policy.reference_number = request.form.get('reference_number')
        policy.name = request.form.get('name')
        policy.version = request.form.get('version')
        policy.date = datetime.strptime(request.form.get('date'), '%Y-%m-%d')
        policy.url = request.form.get('url')
        
        db.session.commit()
        flash('Policy updated successfully')
    except Exception as e:
        db.session.rollback()
        flash('Error updating policy')
        print(f"Error updating policy: {e}")
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/policies/delete/<int:policy_id>', methods=['POST'])
@login_required
def delete_policy(policy_id):
    if not current_user.is_admin:
        return redirect(url_for('user_policies'))
    
    policy = Policy.query.get_or_404(policy_id)
    
    try:
        # First delete all assignments
        PolicyAssignment.query.filter_by(policy_id=policy_id).delete()
        # Then delete the policy
        db.session.delete(policy)
        db.session.commit()
        flash('Policy deleted successfully')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting policy: ' + str(e))
        print(f"Error deleting policy: {e}")
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/assign-policies', methods=['POST'])
@login_required
def assign_policies():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    user_id = request.form.get('user_id')
    policy_ids = request.form.getlist('policy_ids')
    
    try:
        # Get existing assignments for the user
        existing_assignments = PolicyAssignment.query.filter_by(
            user_id=user_id,
            status='pending'
        ).all()
        
        # Create a set of existing policy IDs
        existing_policy_ids = {str(assignment.policy_id) for assignment in existing_assignments}
        
        # Add new assignments for policies that aren't already assigned
        for policy_id in policy_ids:
            if policy_id not in existing_policy_ids:
                assignment = PolicyAssignment(
                    user_id=user_id,
                    policy_id=policy_id
                )
                db.session.add(assignment)
        
        db.session.commit()
        flash('Policies assigned successfully')
    except Exception as e:
        db.session.rollback()
        flash('Error assigning policies')
        print(f"Error assigning policies: {e}")
    
    current_tab = request.form.get('current_tab', 'assignments-section')
    return redirect(url_for('admin_dashboard', active_tab=current_tab))

@app.route('/acknowledge-policy/<int:assignment_id>', methods=['POST'])
@login_required
def acknowledge_policy(assignment_id):
    assignment = PolicyAssignment.query.get_or_404(assignment_id)
    
    if assignment.user_id != current_user.id:
        flash('Unauthorized action')
        return redirect(url_for('user_policies'))
    
    try:
        assignment.acknowledged_at = datetime.utcnow()
        assignment.status = 'acknowledged'
        db.session.commit()
        flash('Policy acknowledged successfully')
    except Exception as e:
        db.session.rollback()
        flash('Error acknowledging policy')
        print(f"Error acknowledging policy: {e}")
    
    # Redirect based on user type
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('user_policies'))

@app.route('/admin/assignments/unassign/<int:assignment_id>', methods=['POST'])
@login_required
def unassign_policy(assignment_id):
    if not current_user.is_admin:
        return redirect(url_for('user_policies'))
    
    assignment = PolicyAssignment.query.get_or_404(assignment_id)
    
    try:
        db.session.delete(assignment)
        db.session.commit()
        flash('Policy unassigned successfully')
    except Exception as e:
        db.session.rollback()
        flash('Error unassigning policy')
        print(f"Error unassigning policy: {e}")
    
    return redirect(url_for('admin_dashboard'))

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'xlsx', 'xls'}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/admin/upload-policies', methods=['POST'])
@login_required
def upload_policies():
    if not current_user.is_admin:
        flash('Unauthorized access')
        return redirect(url_for('index'))

    if 'file' not in request.files:
        flash('No file uploaded')
        return redirect(url_for('admin_dashboard'))

    file = request.files['file']
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('admin_dashboard'))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)

        try:
            # Read Excel file
            df = pd.read_excel(filepath)
            
            # Process each row
            for _, row in df.iterrows():
                # Convert Modified date to proper format
                date_str = row['Modified'].split()[0]  # Get only the date part
                policy_date = datetime.strptime(date_str, '%Y-%m-%d').date()

                # Create new policy
                policy = Policy(
                    reference_number=str(row['Policy Reference No.']),
                    name=row['Title'],
                    version=str(row['Version']),
                    url=row['Name'],
                    date=policy_date
                )
                db.session.add(policy)

            db.session.commit()
            flash('Policies uploaded successfully')

        except Exception as e:
            db.session.rollback()
            flash(f'Error processing file: {str(e)}')
            print(f"Error processing Excel file: {e}")

        finally:
            # Clean up uploaded file
            os.remove(filepath)

    else:
        flash('Invalid file type. Please upload an Excel file (.xlsx or .xls)')

    return redirect(url_for('admin_dashboard'))

@app.cli.command("create-admin")
def create_admin():
    """Create an admin user from environment variables."""
    admin_email = os.getenv('ADMIN_EMAIL', 'admin@example.com')
    admin_password = os.getenv('ADMIN_PASSWORD', 'adminpassword')
    
    # Check if admin already exists
    admin = User.query.filter_by(username=admin_email).first()
    if admin:
        print("Admin user already exists")
        return
    
    # Create new admin user
    admin = User(
        username=admin_email,
        first_name='Admin',
        last_name='User',
        is_admin=True
    )
    admin.set_password(admin_password)
    
    db.session.add(admin)
    try:
        db.session.commit()
        print(f"Admin user created successfully: {admin_email}")
    except Exception as e:
        db.session.rollback()
        print(f"Error creating admin user: {e}")

@app.route('/login/microsoft')
def microsoft_login():
    if not session.get("flow"):
        msal_app = ConfidentialClientApplication(
            app.config['MS_CLIENT_ID'],
            authority=app.config['MS_AUTHORITY'],
            client_credential=app.config['MS_CLIENT_SECRET']
        )
        
        flow = msal_app.initiate_auth_code_flow(
            app.config['MS_SCOPE'],
            redirect_uri=request.base_url.replace('/login/microsoft', app.config['MS_REDIRECT_PATH'])
        )
        session["flow"] = flow
        return redirect(flow["auth_uri"])
    return redirect(url_for('index'))

@app.route('/auth/microsoft/callback')
def microsoft_callback():
    if not session.get("flow"):
        return redirect(url_for('login'))
    
    flow = session.get("flow")
    msal_app = ConfidentialClientApplication(
        app.config['MS_CLIENT_ID'],
        authority=app.config['MS_AUTHORITY'],
        client_credential=app.config['MS_CLIENT_SECRET']
    )
    
    result = msal_app.acquire_token_by_auth_code_flow(flow, request.args)
    if "error" in result:
        flash(f"Error: {result.get('error_description', 'Unknown error')}")
        return redirect(url_for('login'))
    
    # Get user info from Microsoft Graph
    user_email = result.get('id_token_claims', {}).get('preferred_username')
    
    if not user_email:
        flash('Could not get user email from Microsoft')
        return redirect(url_for('login'))
    
    # Check if user exists in our database
    user = User.query.filter_by(username=user_email).first()
    if not user:
        flash('User not registered in the system. Please contact your administrator.')
        return redirect(url_for('login'))
    
    login_user(user)
    flash('Logged in successfully via Microsoft')
    return redirect(url_for('index'))

if __name__ == '__main__':
    port = int(os.getenv('PORT', 8080))
    app.run(host='0.0.0.0', port=port) 