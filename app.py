from flask import Flask, jsonify, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-fallback-key")

CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- MODELS ---

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default="Open")
    priority = db.Column(db.String(20), default="Low")
    submitted_by = db.Column(db.String(100), default="Unknown")
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    activities = db.relationship('Activity', backref='ticket', cascade='all, delete-orphan')

    def serialize(self):
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "status": self.status,
            "priority": self.priority,
            "submitted_by": self.submitted_by,
            "created_at": self.created_at.isoformat()
        }

class Activity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)
    message = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())

    def serialize(self):
        return {
            "id": self.id,
            "ticket_id": self.ticket_id,
            "message": self.message,
            "timestamp": self.timestamp.isoformat()
        }

# --- HELPERS ---

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = User.query.get(session.get('user_id'))
        if not user or user.role != 'admin':
            return jsonify({"error": "Admin only"}), 403
        return f(*args, **kwargs)
    return decorated

# --- AUTH ROUTES ---

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and user.check_password(data['password']):
        session['user_id'] = user.id
        return jsonify({"username": user.username, "role": user.role})
    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"message": "Logged out"})

@app.route('/me')
def get_current_user():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify(None)
    user = User.query.get(user_id)
    return jsonify({"username": user.username, "role": user.role})

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"error": "Username already exists"}), 409

    hashed_pw = generate_password_hash(data['password'])
    new_user = User(username=data['username'], password_hash=hashed_pw, role='user')
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully."}), 201

# --- TICKET ROUTES ---

@app.route("/tickets", methods=["GET", "POST"])
@login_required
def tickets():
    if request.method == "GET":
        tickets = Ticket.query.all()
        return jsonify([t.serialize() for t in tickets])

    if request.method == "POST":
        data = request.get_json()
        new_ticket = Ticket(
            title=data["title"],
            description=data["description"],
            priority=data.get("priority", None),
            submitted_by=data.get("submitted_by", "Unknown")
        )
        db.session.add(new_ticket)
        db.session.commit()

        log = Activity(ticket_id=new_ticket.id, message="Ticket created")
        db.session.add(log)
        db.session.commit()

        return jsonify(new_ticket.serialize()), 201

@app.route("/tickets/<int:ticket_id>", methods=["PATCH"])
@login_required
@admin_required
def update_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    data = request.get_json()
    updated = False

    if "status" in data and data["status"] != ticket.status:
        old_status = ticket.status
        ticket.status = data["status"]
        db.session.commit()
        db.session.add(Activity(ticket_id=ticket.id, message=f"Status changed from {old_status} to {ticket.status}"))
        updated = True

    if "priority" in data and data["priority"] != ticket.priority:
        old_priority = ticket.priority
        ticket.priority = data["priority"]
        db.session.commit()
        db.session.add(Activity(ticket_id=ticket.id, message=f"Priority changed from {old_priority} to {ticket.priority}"))
        updated = True

    if updated:
        db.session.commit()

    return jsonify(ticket.serialize()), 200

@app.route("/tickets/<int:ticket_id>/activities", methods=["GET"])
@login_required
def get_ticket_activities(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    logs = Activity.query.filter_by(ticket_id=ticket.id).order_by(Activity.timestamp.desc()).all()
    return jsonify([log.serialize() for log in logs])

# --- DATABASE RESET & ADMIN SEED ---

@app.route("/seed_admin")
def seed_admin():
    if User.query.filter_by(username="admin").first():
        return "Admin already exists"
    admin = User(
        username="admin",
        password_hash=generate_password_hash("password123"),
        role="admin"
    )
    db.session.add(admin)
    db.session.commit()
    return "Admin user created. Username: admin, Password: password123"


# --- APP START ---

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
