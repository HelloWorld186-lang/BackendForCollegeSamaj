from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, get_jwt
from . import db, bcrypt, mail
from .models import User, Post, PostInteraction
from flask_mail import Message
import random
import time
import os

main = Blueprint('main', __name__)
OTP = {}

# Get email configuration from environment variables
MAIL_USERNAME = os.getenv('MAIL_USERNAME')
MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')

OTP = {}

# Get email configuration from environment variables
MAIL_USERNAME = os.getenv('MAIL_USERNAME')
MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')

@main.route('/send_verification_otp', methods=["POST"])
def send_verification_otp(): 
    data = request.json
    email = data.get('email')
    if not email:
        return jsonify({'message': 'Email is required'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already registered'}), 400

    otp = random.randint(100000, 999999)
    OTP[email] = {'otp': str(otp), 'timestamp': time.time()}

    msg = Message('College Samaj Email Verification', 
                  sender=(MAIL_USERNAME, MAIL_USERNAME), 
                  recipients=[email])
    msg.body = f"Your OTP (One Time Password) for email verification is: {otp}"
    mail.send(msg)
    return jsonify({'message': 'Verification OTP sent successfully'}), 200

@main.route('/verify_email', methods=['POST'])
def verify_email():
    data = request.json
    email = data.get('email')
    user_otp = data.get('otp')
    
    if not email or not user_otp:
        return jsonify({'message': 'Email and OTP are required'}), 400

    if email not in OTP:
        return jsonify({'message': 'OTP not requested for this email'}), 400

    stored_otp = OTP[email]

    if time.time() - stored_otp['timestamp'] > 600:  # OTP expires after 10 minutes
        del OTP[email]
        return jsonify({'message': 'OTP has expired. Please request a new one'}), 400

    if stored_otp['otp'] == user_otp:
        OTP[email]['verified'] = True
        return jsonify({'message': 'Email verified successfully'}), 200
    else:
        return jsonify({'message': 'Invalid OTP'}), 400

@main.route('/signup', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')

    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already signed up'}), 400

    if email not in OTP or 'verified' not in OTP[email] or not OTP[email]['verified']:
        return jsonify({'message': 'Email not verified. Please verify your email first'}), 400

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    
    new_user = User(
        first_name=data['first_name'],
        last_name=data['last_name'],
        username=data['username'],
        email=email,
        mobile_number=data['mobile_number'],
        occupation=data.get('occupation'),
        address=data.get('address'),
        password=hashed_password,
        avatar_link=data.get('avatar_link')
    )
    db.session.add(new_user)
    db.session.commit()

    del OTP[email]  # Clean up after successful signup
    return jsonify({'message': 'User signed up successfully'}), 201

@main.route('/signin', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token, avatar_link=user.avatar_link), 200
    return jsonify({'message': 'Invalid email or password'}), 401

@main.route('/user', methods=['PATCH', 'GET'])
@jwt_required()
def user_profile():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if request.method == 'GET':
        return jsonify({
            'first_name': user.first_name,
            'last_name': user.last_name,
            "username": user.username,
            "email": user.email,
            "mobile_number": user.mobile_number,
            "occupation": user.occupation,
            "address": user.address,
            "avatar_link": user.avatar_link
        }), 200
    
    elif request.method == "PATCH":
        data = request.json
        for field in ['first_name', 'last_name', 'username', 'email', 'mobile_number', 'occupation', 'address', 'avatar_link']:
            if field in data:
                setattr(user, field, data[field])
        db.session.commit()
        return jsonify({'message': 'User profile updated successfully', 'avatar_link': user.avatar_link}), 200

@main.route('/post', methods=['POST', 'GET'])
@jwt_required()
def handle_posts():
    current_user_id = get_jwt_identity()
    if request.method == 'POST':
        data = request.json
        new_post = Post(
            post_text=data['post_text'],
            user_id=current_user_id
        )
        db.session.add(new_post)
        db.session.commit()
        return jsonify({'message': 'Post created successfully'}), 201
    
    elif request.method == 'GET':
        posts = Post.query.all()
        return jsonify([{
            "id": post.id,
            "post_text": post.post_text,
            "date_posted": post.date_posted.isoformat(),
            "author": post.author.username,
            "likes": post.likes,
            'unlikes': post.unlikes,
            'author_avatar': post.author.avatar_link
        } for post in posts]), 200

@main.route('/post/<int:post_id>', methods=['DELETE'])
@jwt_required()
def handle_post(post_id):
    current_user_id = get_jwt_identity()
    post = Post.query.get_or_404(post_id)
    
    if post.user_id != current_user_id:
        return jsonify({'message': 'You are not authorized to delete this post'}), 403

    try:
        db.session.delete(post)
        db.session.commit()
        return jsonify({'message': 'Post deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to delete post', 'error': str(e)}), 500

@main.route('/post/<int:post_id>/<string:action>', methods=['POST'])
@jwt_required()
def handle_post_interaction(post_id, action):
    if action not in ['like', 'unlike']:
        return jsonify({'message': 'Invalid action'}), 400

    current_user_id = get_jwt_identity()
    post = Post.query.get_or_404(post_id)
    interaction = PostInteraction.query.filter_by(user_id=current_user_id, post_id=post_id).first()

    if interaction:
        if interaction.interaction_type == action:
            return jsonify({'message': f'You have already {action}d this post'}), 400
        interaction.interaction_type = action
        if action == 'like':
            post.unlikes -= 1
            post.likes += 1
        else:
            post.likes -= 1
            post.unlikes += 1
    else:
        interaction = PostInteraction(user_id=current_user_id, post_id=post_id, interaction_type=action)
        if action == 'like':
            post.likes += 1
        else:
            post.unlikes += 1
        db.session.add(interaction)

    db.session.commit()
    return jsonify({
        'message': f'Post {action}d successfully',
        'likes': post.likes,
        'unlikes': post.unlikes
    }), 200

@main.route('/users', methods=['GET'])
@jwt_required()
def get_all_users():
    users = User.query.all()
    return jsonify({
        'users': [{
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'avatar_link': user.avatar_link
        } for user in users]
    }), 200

@main.route('/user/<int:user_id>/posts', methods=['GET'])
@jwt_required()
def get_all_post_user(user_id):
    user = User.query.get_or_404(user_id)
    posts = Post.query.filter_by(user_id=user_id).all()

    return jsonify({
        'posts': [{
            'id': post.id,
            'post_text': post.post_text,
            'date_posted': post.date_posted.isoformat(),
            'likes': post.likes,
            'unlikes': post.unlikes,
            'author_avatar':  post.author.avatar_link
        } for post in posts],
        'userdetail': {
            'user_id': user.id,
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'mobile_number': user.mobile_number,
            'occupation': user.occupation,
            'address': user.address,
            'avatar_link': user.avatar_link
        }
    }), 200

@main.route('/signout', methods=['POST'])
@jwt_required()
def signout():
    jti = get_jwt()['jti']
    # In a real application, you would add this JTI to a blocklist
    # For this example, we'll just pretend we've done that
    return jsonify({'message': 'Successfully signed out'}), 200