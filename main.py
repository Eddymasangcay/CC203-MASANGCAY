from flask import Flask, render_template, request, redirect, session, url_for, abort, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__, static_folder='.', static_url_path='/static')
app.secret_key = "aries_vincent_secret"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///Sharkwatch.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    posts = db.relationship('Post', backref='author', lazy=True)
    bookings = db.relationship('Booking', backref='user', lazy=True)

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
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))

    return render_template('Homepage.html')

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
    user_bookings = Booking.query.filter_by(user_id=current_user.id).order_by(Booking.created_at.desc()).all()
    transports = Transportation.query.order_by(Transportation.id.desc()).all()

    return render_template(
        'Dashboard.html',
        username=current_user.username,
        is_admin=current_user.is_admin,
        bookings=user_bookings,
        transportations=transports,
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
        username = request.form['new_username']
        password = request.form['new_password']
        user = User.query.filter_by(username=username).first()
        if user:
            return render_template('Homepage.html', error="Username already exists.")
        else:
            is_first_user = User.query.first() is None
            new_user = User(username=username, is_admin=is_first_user)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            session['username'] = username
            return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/post', methods=['POST'])
def post():
    if 'username' not in session:
        return redirect(url_for('index'))

    content = request.form['content']
    user = User.query.filter_by(username=session['username']).first()
    new_post = Post(content=content, user_id=user.id)
    db.session.add(new_post)
    db.session.commit()

    return redirect(url_for('dashboard'))

@app.route('/post/delete/<int:post_id>')
def delete_post(post_id):
    if 'username' not in session:
        return redirect(url_for('index'))

    post = Post.query.get(post_id)
    user = User.query.filter_by(username=session['username']).first()

    if not post or post.user_id != user.id:
        abort(404)

    db.session.delete(post)
    db.session.commit()

    return redirect(url_for('dashboard'))


@app.route('/transportations')
def transportations():
    transports = Transportation.query.order_by(Transportation.id.desc()).all()
    return render_template('Transportation.html', transportations=transports)


@app.route('/book/<int:transportation_id>', methods=['POST'])
def book_transportation(transportation_id):
    if 'username' not in session:
        return redirect(url_for('index'))

    transport = Transportation.query.get_or_404(transportation_id)
    current_user = User.query.filter_by(username=session['username']).first()
    try:
        quantity = int(request.form.get('quantity', '1'))
        if quantity <= 0:
            quantity = 1
    except ValueError:
        quantity = 1
    total_price = transport.price * quantity

    booking = Booking(
        user_id=current_user.id,
        transportation_id=transport.id,
        quantity=quantity,
        total_price=total_price,
    )
    db.session.add(booking)
    db.session.commit()

    return redirect(url_for('receipt', booking_id=booking.id))


@app.route('/receipt/<int:booking_id>')
def receipt(booking_id):
    if 'username' not in session:
        return redirect(url_for('index'))

    booking = Booking.query.get_or_404(booking_id)
    current_user = User.query.filter_by(username=session['username']).first()
    if booking.user_id != current_user.id and not current_user.is_admin:
        abort(404)

    return render_template('Receipt.html', booking=booking)


@app.route('/change_password', methods=['POST'])
def change_password():
    if 'username' not in session:
        return redirect(url_for('index'))
    current_user = User.query.filter_by(username=session['username']).first()
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


@app.route('/admin/transportation/add', methods=['POST'])
def admin_add_transportation():
    if 'username' not in session:
        return redirect(url_for('index'))
    current_user = User.query.filter_by(username=session['username']).first()
    require_admin(current_user)
    name = request.form.get('name', '').strip()
    price_raw = request.form.get('price', '0').strip()
    image_url = request.form.get('image_url', '').strip()
    try:
        price = float(price_raw)
    except ValueError:
        price = 0.0
    if not name:
        return redirect(url_for('dashboard'))
    transport = Transportation(name=name, price=price, image_url=image_url)
    db.session.add(transport)
    db.session.commit()
    return redirect(url_for('dashboard'))


@app.route('/admin/transportation/<int:transport_id>/edit', methods=['POST'])
def admin_edit_transportation(transport_id):
    if 'username' not in session:
        return redirect(url_for('index'))
    current_user = User.query.filter_by(username=session['username']).first()
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
    require_admin(current_user)
    transport = Transportation.query.get_or_404(transport_id)
    db.session.delete(transport)
    db.session.commit()
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)