from flask import Flask, render_template, request, redirect, session, url_for, abort, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect as sql_inspect
from datetime import datetime
import os

app = Flask(__name__, static_folder='.', static_url_path='/static')
app.secret_key = "aries_vincent_secret"

# Set up database path - use instance folder
basedir = os.path.abspath(os.path.dirname(__file__))
instance_folder = os.path.join(basedir, 'instance')
os.makedirs(instance_folder, exist_ok=True)

# Set up upload folder for images
UPLOAD_FOLDER = os.path.join(basedir, 'static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Database configuration - use absolute path with proper formatting
db_path = os.path.join(instance_folder, 'Sharkwatch.db')
# Convert Windows backslashes to forward slashes for SQLite URI
db_uri = db_path.replace('\\', '/')
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_uri}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# Ensure database tables exist with correct schema
def ensure_tables():
    """Ensure database tables exist with correct schema"""
    try:
        with app.app_context():
            # Check if user table exists and has is_admin column
            inspector = sql_inspect(db.engine)
            tables = inspector.get_table_names()
            
            if 'user' in tables:
                # Check if required columns exist
                columns = [col['name'] for col in inspector.get_columns('user')]
                booking_columns = []
                if 'booking' in tables:
                    booking_columns = [col['name'] for col in inspector.get_columns('booking')]
                if 'is_admin' not in columns or 'role' not in columns or (booking_columns and 'payment_status' not in booking_columns):
                    print("Database schema is outdated. Recreating tables...")
                    # Drop all tables and recreate
                    db.drop_all()
                    db.create_all()
                    print("Database tables recreated successfully.")
                else:
                    # Tables exist with correct schema, just ensure all tables exist
                    db.create_all()
            else:
                # Tables don't exist, create them
                db.create_all()
    except Exception as e:
        print(f"Warning: Could not create database tables: {e}")
        # If inspection fails, try to recreate everything
        try:
            with app.app_context():
                db.drop_all()
                db.create_all()
                print("Database recreated after error.")
        except:
            pass

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    role = db.Column(db.String(20), default='user', nullable=False)  # 'user', 'admin', or 'staff'
    posts = db.relationship('Post', backref='author', lazy=True)
    bookings = db.relationship('Booking', backref='user', lazy=True)
    
    def is_staff(self):
        return self.role == 'staff' or self.is_admin

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Transportation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    price = db.Column(db.Float, nullable=False)
    image_url = db.Column(db.String(500), nullable=True)
    bookings = db.relationship('Booking', backref='transportation', lazy=True)

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    transportation_id = db.Column(db.Integer, db.ForeignKey('transportation.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    total_price = db.Column(db.Float, nullable=False)
    payment_status = db.Column(db.String(20), default='pending', nullable=False)  # 'pending', 'paid', 'cancelled'
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


@app.route('/')
def index():
    # Get featured transportations for homepage (limit to 5 most recent)
    featured_transports = Transportation.query.order_by(Transportation.id.desc()).limit(5).all()
    return render_template('Homepage.html', featured_transports=featured_transports)

@app.route('/loginpage')
def loginpage():
    return render_template('Loginpage.html')

@app.route('/about')
def aboutpage():
    return render_template('Aboutpage.html')

@app.route('/registerpage')
def registerpage():
    return render_template('Register.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('index'))

    current_user = User.query.filter_by(username=session['username']).first()
    if not current_user:
        # User doesn't exist in database, clear session and redirect
        session.pop('username', None)
        return redirect(url_for('index'))
    
    user_bookings = Booking.query.filter_by(user_id=current_user.id).order_by(Booking.created_at.desc()).all()
    transports = Transportation.query.order_by(Transportation.id.desc()).all()
    
    # Get all users for admin management
    all_users = []
    if current_user.is_admin:
        all_users = User.query.order_by(User.username).all()

    return render_template(
        'Dashboard.html',
        username=current_user.username,
        is_admin=current_user.is_admin,
        is_staff=current_user.is_staff(),
        bookings=user_bookings,
        transportations=transports,
        all_users=all_users,
    )

@app.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session['username'] = username
            return redirect(url_for('dashboard'))

    return render_template('Homepage.html', error="Invalid username or password.")

@app.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form.get('new_username', '').strip()
            password = request.form.get('new_password', '').strip()
            
            if not username or not password:
                return render_template('Register.html', error="Username and password are required.")
            
            # Check if user already exists
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                return render_template('Register.html', error="Username already exists. Please choose a different username.")
            
            # Check if this is the first user (make them admin)
            is_first_user = User.query.first() is None
            
            # Create new user
            new_user = User(username=username, is_admin=is_first_user, role='admin' if is_first_user else 'user')
            new_user.set_password(password)
            
            # Add to database
            db.session.add(new_user)
            db.session.commit()
            
            # Set session and redirect
            session['username'] = username
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            db.session.rollback()
            error_msg = str(e)
            # Provide more user-friendly error messages
            if 'no such table' in error_msg.lower() or 'no such column' in error_msg.lower():
                # Tables don't exist or schema is outdated, try to recreate them
                try:
                    with app.app_context():
                        db.drop_all()
                        db.create_all()
                    return render_template('Register.html', error="Database schema was updated. Please try registering again.")
                except Exception as recreate_error:
                    return render_template('Register.html', error=f"Database error: {str(recreate_error)}. Please contact support.")
            return render_template('Register.html', error=f"Registration failed: {error_msg}. Please try again.")

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/post', methods=['POST'])
def post():
    if 'username' not in session:
        return redirect(url_for('index'))

    user = User.query.filter_by(username=session['username']).first()
    if not user:
        session.pop('username', None)
        return redirect(url_for('index'))
    
    content = request.form['content']
    new_post = Post(content=content, user_id=user.id)
    db.session.add(new_post)
    db.session.commit()

    return redirect(url_for('dashboard'))

@app.route('/post/delete/<int:post_id>')
def delete_post(post_id):
    if 'username' not in session:
        return redirect(url_for('index'))

    user = User.query.filter_by(username=session['username']).first()
    if not user:
        session.pop('username', None)
        return redirect(url_for('index'))
    
    post = Post.query.get(post_id)
    if not post or post.user_id != user.id:
        abort(404)

    db.session.delete(post)
    db.session.commit()

    return redirect(url_for('dashboard'))


@app.route('/transportations')
def transportations():
    # Always get all transportations from database, ordered by most recent
    transports = Transportation.query.order_by(Transportation.id.desc()).all()
    is_admin = False
    is_staff = False
    if 'username' in session:
        current_user = User.query.filter_by(username=session['username']).first()
        if current_user:
            is_admin = current_user.is_admin
            is_staff = current_user.is_staff()
    return render_template('Transportation.html', transportations=transports, is_admin=is_admin, is_staff=is_staff)


@app.route('/book/<int:transportation_id>', methods=['POST'])
def book_transportation(transportation_id):
    if 'username' not in session:
        return redirect(url_for('index'))

    transport = Transportation.query.get_or_404(transportation_id)
    current_user = User.query.filter_by(username=session['username']).first()
    if not current_user:
        session.pop('username', None)
        return redirect(url_for('index'))
    
    try:
        quantity = int(request.form.get('quantity', '1'))
        if quantity <= 0:
            quantity = 1
    except ValueError:
        quantity = 1
    total_price = transport.price * quantity

    # Store booking info in session for payment page
    session['pending_booking'] = {
        'transportation_id': transport.id,
        'quantity': quantity,
        'total_price': total_price
    }

    return redirect(url_for('payment'))


@app.route('/payment')
def payment():
    if 'username' not in session:
        return redirect(url_for('index'))
    
    if 'pending_booking' not in session:
        return redirect(url_for('transportations'))
    
    current_user = User.query.filter_by(username=session['username']).first()
    if not current_user:
        session.pop('username', None)
        return redirect(url_for('index'))
    
    pending = session['pending_booking']
    transport = Transportation.query.get_or_404(pending['transportation_id'])
    
    return render_template('Payment.html', 
                         transport=transport, 
                         quantity=pending['quantity'],
                         total_price=pending['total_price'],
                         user=current_user)

@app.route('/process_payment', methods=['POST'])
def process_payment():
    if 'username' not in session:
        return redirect(url_for('index'))
    
    if 'pending_booking' not in session:
        return redirect(url_for('transportations'))
    
    current_user = User.query.filter_by(username=session['username']).first()
    if not current_user:
        session.pop('username', None)
        return redirect(url_for('index'))
    
    pending = session['pending_booking']
    
    # Create booking with payment status
    booking = Booking(
        user_id=current_user.id,
        transportation_id=pending['transportation_id'],
        quantity=pending['quantity'],
        total_price=pending['total_price'],
        payment_status='paid'
    )
    db.session.add(booking)
    db.session.commit()
    
    # Clear pending booking from session
    session.pop('pending_booking', None)
    
    return redirect(url_for('receipt', booking_id=booking.id))

@app.route('/receipt/<int:booking_id>')
def receipt(booking_id):
    if 'username' not in session:
        return redirect(url_for('index'))

    booking = Booking.query.get_or_404(booking_id)
    current_user = User.query.filter_by(username=session['username']).first()
    if not current_user:
        session.pop('username', None)
        return redirect(url_for('index'))
    
    if booking.user_id != current_user.id and not current_user.is_admin:
        abort(404)

    return render_template('Receipt.html', booking=booking, user=current_user)


@app.route('/change_password', methods=['POST'])
def change_password():
    if 'username' not in session:
        return redirect(url_for('index'))
    current_user = User.query.filter_by(username=session['username']).first()
    if not current_user:
        session.pop('username', None)
        return redirect(url_for('index'))
    
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    if not current_user.check_password(current_password):
        return redirect(url_for('dashboard'))
    if not new_password:
        return redirect(url_for('dashboard'))
    current_user.set_password(new_password)
    db.session.commit()
    return redirect(url_for('dashboard'))


def require_admin(user: User):
    if not user or not user.is_admin:
        abort(404)

def require_admin_or_staff(user: User):
    if not user or (not user.is_admin and user.role != 'staff'):
        abort(404)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/admin/transportation/add', methods=['POST'])
def admin_add_transportation():
    if 'username' not in session:
        return redirect(url_for('index'))
    current_user = User.query.filter_by(username=session['username']).first()
    if not current_user:
        session.pop('username', None)
        return redirect(url_for('index'))
    require_admin_or_staff(current_user)
    
    try:
        name = request.form.get('name', '').strip()
        price_raw = request.form.get('price', '0').strip()
        image_url = request.form.get('image_url', '').strip()
        
        # Handle file upload
        if 'image_file' in request.files:
            file = request.files['image_file']
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Add timestamp to make filename unique
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
                filename = timestamp + filename
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                # Store relative URL for the image
                image_url = url_for('static', filename=f'uploads/{filename}')
        
        # Validate inputs
        if not name:
            flash('Transportation name is required.', 'error')
            return redirect(url_for('transportations'))
        
        try:
            price = float(price_raw)
            if price <= 0:
                flash('Price must be greater than 0.', 'error')
                return redirect(url_for('transportations'))
        except ValueError:
            flash('Invalid price format.', 'error')
            return redirect(url_for('transportations'))
        
        # Create and save transportation to database
        transport = Transportation(name=name, price=price, image_url=image_url if image_url else None)
        db.session.add(transport)
        
        # Force flush to get the ID before commit
        db.session.flush()
        transport_id = transport.id
        
        # Commit to database
        db.session.commit()
        
        # Verify it was saved by querying the database
        saved_transport = Transportation.query.get(transport_id)
        if saved_transport:
            flash(f'Transportation "{name}" added successfully!', 'success')
            print(f"Transportation saved: ID={transport_id}, Name={name}, Price={price}")
        else:
            flash('Error: Transportation was not saved to database.', 'error')
            print(f"ERROR: Transportation was not found after commit. ID={transport_id}")
        
        return redirect(url_for('transportations'))
    except Exception as e:
        db.session.rollback()
        flash(f'Error adding transportation: {str(e)}', 'error')
        return redirect(url_for('transportations'))


@app.route('/admin/transportation/<int:transport_id>/edit', methods=['POST'])
def admin_edit_transportation(transport_id):
    if 'username' not in session:
        return redirect(url_for('index'))
    current_user = User.query.filter_by(username=session['username']).first()
    if not current_user:
        session.pop('username', None)
        return redirect(url_for('index'))
    require_admin(current_user)
    transport = Transportation.query.get_or_404(transport_id)
    name = request.form.get('name', '').strip()
    price_raw = request.form.get('price', '').strip()
    image_url = request.form.get('image_url', '').strip()
    if name:
        transport.name = name
    if price_raw:
        try:
            transport.price = float(price_raw)
        except ValueError:
            pass
    transport.image_url = image_url
    db.session.commit()
    return redirect(url_for('dashboard'))


@app.route('/admin/transportation/<int:transport_id>/delete', methods=['POST'])
def admin_delete_transportation(transport_id):
    if 'username' not in session:
        return redirect(url_for('index'))
    current_user = User.query.filter_by(username=session['username']).first()
    if not current_user:
        session.pop('username', None)
        return redirect(url_for('index'))
    require_admin(current_user)
    transport = Transportation.query.get_or_404(transport_id)
    db.session.delete(transport)
    db.session.commit()
    return redirect(url_for('dashboard'))


@app.route('/admin/user/<int:user_id>/update_role', methods=['POST'])
def admin_update_user_role(user_id):
    if 'username' not in session:
        return redirect(url_for('index'))
    current_user = User.query.filter_by(username=session['username']).first()
    if not current_user:
        session.pop('username', None)
        return redirect(url_for('index'))
    require_admin(current_user)
    
    user = User.query.get_or_404(user_id)
    new_role = request.form.get('role', 'user').strip()
    
    # Validate role
    if new_role not in ['user', 'admin', 'staff']:
        return redirect(url_for('dashboard'))
    
    # Update role and is_admin flag
    user.role = new_role
    user.is_admin = (new_role == 'admin')
    
    db.session.commit()
    return redirect(url_for('dashboard'))


# Initialize database when app starts
def init_db():
    """Initialize the database and create all tables"""
    try:
        ensure_tables()
        # Update existing users without role field
        with app.app_context():
            try:
                all_users = User.query.all()
                users_updated = 0
                for user in all_users:
                    if not hasattr(user, 'role') or user.role is None or user.role == '':
                        if user.is_admin:
                            user.role = 'admin'
                        else:
                            user.role = 'user'
                        users_updated += 1
                if users_updated > 0:
                    db.session.commit()
                    print(f"Updated {users_updated} users with role field")
            except Exception as e:
                # Role column might not exist yet, that's okay
                pass
        print(f"Database initialized at: {app.config['SQLALCHEMY_DATABASE_URI']}")
    except Exception as e:
        print(f"Error initializing database: {e}")

# Initialize database on startup
init_db()

if __name__ == '__main__':
    app.run(debug=True)