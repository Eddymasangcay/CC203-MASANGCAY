from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.secret_key = "aries_vincent_secret"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///Sharkwatch.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    posts = db.relationship('Post', backref='author', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))

    return render_template('SharkWatch Home.HTML')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('index'))

    return render_template('dashboard.html', username=session['username'], posts=Post.query.all())

@app.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session['username'] = username
            return redirect(url_for('dashboard'))

    return redirect(url_for('index'))

@app.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        username = request.form['new_username']
        password = request.form['new_password']
        user = User.query.filter_by(username=username).first()
        if user:
            return render_template('SharkWatch Home.HTML', error="Username already exists.")
        else:
            new_user = User(username=username)
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

    if post and post.user_id == user.id:
        db.session.delete(post)
        db.session.commit()

    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)