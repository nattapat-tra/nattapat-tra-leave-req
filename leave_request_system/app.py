from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///leave_requests.db'
app.config['SECRET_KEY'] = 'be92ae3dcc216202650e97e3e5e1f19b'
db = SQLAlchemy(app)
migrate = Migrate(app, db)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    leave_requests = db.relationship('LeaveRequest', backref='user', lazy=True)

class LeaveRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reason = db.Column(db.String(255), nullable=False)
    date = db.Column(db.String(20), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@app.route('/')
def index():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        leave_requests = user.leave_requests
        return render_template('index.html', user=user, leave_requests=leave_requests)
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))
@app.route('/submit', methods=['POST'])
def submit():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        reason = request.form.get('reason')
        date = request.form.get('date')

        new_leave_request = LeaveRequest(reason=reason, date=date, user=user)
        db.session.add(new_leave_request)
        db.session.commit()

        flash('Leave request submitted successfully!', 'success')

    return redirect(url_for('/index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='testuser').first():
            default_user = User(username='testuser', password=generate_password_hash('testpassword', method='pbkdf2:sha256'))
            db.session.add(default_user)
            db.session.commit()

    app.run(debug=True)