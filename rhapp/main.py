from flask import Flask, request, render_template, redirect, session, url_for, render_template_string
from markupsafe import Markup
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import os
from playwright.sync_api import sync_playwright

ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'adminpass'


app = Flask(__name__)
app.secret_key = 'super-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vulnlab.db'
db = SQLAlchemy(app)

# Models

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80))
    comment = db.Column(db.Text)

class AdminNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)

class PublicNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)

class ContactRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80))
    message = db.Column(db.Text)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(80))
    recipient = db.Column(db.String(80))
    content = db.Column(db.Text)

# Auth decorators

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated

def admin_only(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('user') != 'admin':
            return 'Unauthorized', 403
        return f(*args, **kwargs)
    return decorated

# Routes

import asyncio
from playwright.async_api import async_playwright

ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'adminpass'

def bot_contact_xss():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto("http://localhost:5000/login")
        page.fill('input[name="username"]', ADMIN_USERNAME)
        page.fill('input[name="password"]', ADMIN_PASSWORD)
        page.click('button[type="submit"]')
        page.wait_for_url("http://localhost:5000/public_notes")
        page.goto("http://localhost:5000/admin/requests")
        page.wait_for_timeout(3000)
        cookies = page.context.cookies()
        admin_cookie = next((c['value'] for c in cookies if c['name'] == 'session'), None)
        print(f"[Bot Contact XSS] Stolen admin session cookie: {admin_cookie}")
        browser.close()

def bot_messages_xss():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto("http://localhost:5000/login")
        page.fill('input[name="username"]', ADMIN_USERNAME)
        page.fill('input[name="password"]', ADMIN_PASSWORD)
        page.click('button[type="submit"]')
        page.wait_for_url("http://localhost:5000/public_notes")
        page.goto("http://localhost:5000/messages")
        page.wait_for_timeout(3000)
        cookies = page.context.cookies()
        admin_cookie = next((c['value'] for c in cookies if c['name'] == 'session'), None)
        print(f"[Bot Messages XSS] Stolen admin session cookie: {admin_cookie}")
        browser.close()


@app.route('/')
def index():
    return redirect('/public_notes')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form['username']
        pw = request.form['password']
        user_obj = User.query.filter_by(username=user, password=pw).first()
        if user_obj:
            session['user'] = user
            return redirect('/public_notes')
        return 'Login Failed'
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/login')

@app.route('/register', methods=['POST'])
def register():
    data = request.form
    if User.query.filter_by(username=data['username']).first():
        return 'User exists'
    new_user = User(username=data['username'], password=data['password'])
    db.session.add(new_user)
    db.session.commit()
    return 'Registered'

# Public Notes - Visible by everyone, written only by admin with SSTI vuln


@app.route('/public_notes')
def public_notes():
    notes = PublicNote.query.all()
    # Render all notes with SSTI vulnerability
    rendered_notes = []
    for note in notes:
        # Vulnerable: render note.content as template string without sanitization
        rendered = render_template_string(note.content)
        print(rendered)
        rendered_notes.append(rendered)  # Mark as safe to avoid autoescaping
    return render_template('public_notes.html', notes=rendered_notes)


@app.route('/admin/public_notes', methods=['GET', 'POST'])
@login_required
@admin_only
def admin_public_notes():
    if request.method == 'POST':
        content = request.form['content']
        new_note = PublicNote(content=content)
        db.session.add(new_note)
        db.session.commit()
        # Redirect or render safely here as you want
        return redirect('/public_notes')
    
    # Define notes here for GET requests or after POST redirect
    notes = PublicNote.query.all()
    return render_template('admin_public_notes.html', notes=notes)


# Contact form with XSS #1 (unauthenticated)

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name', 'anon')
        message = request.form.get('message', '')
        req = ContactRequest(name=name, message=message)
        db.session.add(req)
        db.session.commit()

        # Run bot inline, blocking request until done
        bot_contact_xss()

        return 'Thank you for your message!'
    return render_template('contact.html')
# Admin view of contact requests (show stored requests)

@app.route('/admin/requests')
@login_required
@admin_only
def admin_requests():
    requests = ContactRequest.query.all()
    response = render_template('admin_requests.html', requests=requests)
    
    # Delete all requests after rendering
    for req in requests:
        db.session.delete(req)
    db.session.commit()

    return response

# Messages (XSS #2 in direct messages)

@app.route('/messages', methods=['GET', 'POST'])
@login_required
def messages():
    if request.method == 'POST':
        recipient = request.form['recipient']
        content = request.form['content']
        msg = Message(sender=session['user'], recipient=recipient, content=content)
        db.session.add(msg)
        db.session.commit()

        if recipient == 'admin':
            bot_messages_xss()  # Or run in thread/async per your preference

    # Query messages for current user
    msgs = Message.query.filter(
        (Message.sender == session['user']) | (Message.recipient == session['user'])
    ).all()

    # If admin viewing, delete messages received by admin after displaying
    if session.get('user') == 'admin':
        for msg in msgs:
            if msg.recipient == 'admin':
                db.session.delete(msg)
        db.session.commit()

    return render_template('messages.html', messages=msgs, user=session['user'])


# Existing comment board (unauthenticated XSS)

@app.route('/comments', methods=['GET', 'POST'])
@login_required
def comment_board():
    if request.method == 'POST':
        name = request.form.get('name', 'anon')
        comment = request.form['comment']
        new_comment = Comment(name=name, comment=comment)
        db.session.add(new_comment)
        db.session.commit()
    comments = Comment.query.all()
    return render_template('comment_board.html', comments=comments)


@app.route('/admin/notes')
@login_required
@admin_only
def admin_notes():
    notes = AdminNote.query.all()
    return render_template('admin_panel.html', notes=notes)

@app.route('/admin/render', methods=['POST'])
@login_required
@admin_only
def render_admin():
    code = request.form['tpl']
    return render_template_string(code)

@app.route('/admin/ldap_lookup', methods=['POST'])
@login_required
@admin_only
def ldap_lookup():
    user = request.form['user']
    query = f"(uid={user})"
    # For demo, returning string. Replace with real LDAP query if needed.
    return f"LDAP Query: {query}"

# Initialize database & fake users

def create_fake_users():
    for i in range(1,6):
        uname = f"user{i}"
        if not User.query.filter_by(username=uname).first():
            u = User(username=uname, password="password")
            db.session.add(u)
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', password='adminpass')
        db.session.add(admin)
    db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_fake_users()
    app.run(debug=True, host='0.0.0.0', port=5000)

