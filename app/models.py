from . import db
from datetime import datetime

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    mobile_number = db.Column(db.String(15), unique=True, nullable=False)
    occupation = db.Column(db.String(100), nullable=True)
    address = db.Column(db.String(200), nullable=True)
    password = db.Column(db.String(60), nullable=False)
    avatar_link = db.Column(db.String(255), nullable=True)
    posts = db.relationship('Post', backref='author', lazy=True)
    interactions = db.relationship('PostInteraction', backref='user', lazy=True)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_text = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    likes = db.Column(db.Integer, default=0)
    unlikes = db.Column(db.Integer, default=0)
    interactions = db.relationship('PostInteraction', backref='post', lazy=True, cascade="all, delete-orphan")

class PostInteraction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    interaction_type = db.Column(db.String(10), nullable=False)  # 'like' or 'unlike'
    date_interacted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)