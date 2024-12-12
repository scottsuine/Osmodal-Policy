from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')

# Get DATABASE_URL from Fly.io environment
database_url = os.getenv('DATABASE_URL')
if database_url:
    # Replace postgres:// with postgresql:// for SQLAlchemy
    database_url = database_url.replace("postgres://", "postgresql://", 1)
    print(f"Database URL configured: {database_url[:15]}...")  # Log partial URL for debugging
else:
    print("WARNING: No DATABASE_URL found, using SQLite")
    database_url = 'sqlite:///users.db'

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_size': 5,
    'pool_timeout': 30,
    'pool_recycle': 1800,
}

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

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Policy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    version = db.Column(db.String(20), nullable=False)
    date = db.Column(db.Date, nullable=False)
    url = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create tables and admin user
with app.app_context():
    try:
        db.create_all()
        # Check if admin user exists
        admin = User.query.filter_by(username="scott.suine@osmodal.com").first()
        if not admin:
            admin = User(
                username="scott.suine@osmodal.com",
                first_name="Scott",
                last_name="Suine",
                is_admin=True
            )
            admin.set_password("jack8765")
            db.session.add(admin)
            db.session.commit()
    except Exception as e:
        print(f"Database initialization error: {e}")
        raise e

@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_policies'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            user = User.query.filter_by(username=username).first()
            
            if user and user.check_password(password):
                login_user(user)
                if user.is_admin:
                    return redirect(url_for('admin_dashboard'))
                return redirect(url_for('user_policies'))
            
            flash('Invalid username or password')
        except Exception as e:
            flash(f'An error occurred during login. Please try again.')
            print(f"Login error: {e}")  # This will show in your logs
    return render_template('auth/login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for('user_policies'))
    users = User.query.all()
    policies = Policy.query.order_by(Policy.date.desc()).all()
    return render_template('admin/dashboard.html', users=users, policies=policies)

@app.route('/admin/users/add', methods=['POST'])
@login_required
def add_user():
    if not current_user.is_admin:
        return redirect(url_for('user_policies'))
    
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
    return redirect(url_for('admin_dashboard'))

@app.route('/policies')
@login_required
def user_policies():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    return render_template('user/policies.html')

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
        return redirect(url_for('user_policies'))
    
    try:
        policy = Policy(
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
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/policies/edit/<int:policy_id>', methods=['POST'])
@login_required
def edit_policy(policy_id):
    if not current_user.is_admin:
        return redirect(url_for('user_policies'))
    
    policy = Policy.query.get_or_404(policy_id)
    
    try:
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
        db.session.delete(policy)
        db.session.commit()
        flash('Policy deleted successfully')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting policy')
        print(f"Error deleting policy: {e}")
    
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    port = int(os.getenv('PORT', 8080))
    app.run(host='0.0.0.0', port=port) 