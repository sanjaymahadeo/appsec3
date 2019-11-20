from sqlalchemy import create_engine
from sqlalchemy import Column, Integer, ForeignKey, String, DateTime, select
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from getpass import getpass
from hashlib import sha256 as SHA256
from secrets import token_hex
from datetime import datetime

import subprocess
from flask import Flask, render_template, redirect, url_for, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

BASE = declarative_base()
DBFILE = "users.db"

def setup_db():
    global BASE
    engine = create_engine(f'sqlite:///{DBFILE}')
    BASE.metadata.bind = engine
    # Before doing this, clean up prev DB for testing purposes.
    # Submit to autograder WITHOUT this line.
    BASE.metadata.drop_all(engine)
    # Create DB again.
    BASE.metadata.create_all(engine)
    DBSessionMaker = sessionmaker(bind=engine)
    return DBSessionMaker

DBSessionMaker = setup_db()
# Grab a database session.
session = DBSessionMaker()
#logged_in_user = None

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///{DBFILE}'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

#class User(UserMixin, db.Model):
#    id = db.Column(db.Integer, primary_key=True)
#    username = db.Column(db.String(15), unique=True)
#    email = db.Column(db.String(50), unique=True)
#    password = db.Column(db.String(80))
#    phonenumber = db.Column(db.String(11), unique=True)

class User(BASE):
    __tablename__ = 'users'
    user_id = Column(Integer, primary_key=True, autoincrement=True)
    children = relationship("Text")
    uname = Column(String(25), nullable=False, unique=True)
    pword = Column(String(64), nullable=False)
    salt = Column(String(16), nullable=False)
    email = Column(String(30), nullable=False)
    phone = Column(String(11), nullable=False)

class Text(BASE):
    __tablename__ = 'text'
    text_id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.user_id'), nullable=False)
    intext = Column(String(1000), nullable=False)
    outtext = Column(String(1000), nullable=False)
    user = relationship(User)

class LoginRecord(BASE):
    __tablename__ = 'login_records'
    record_number =  Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.user_id'), nullable=False)
    time_on = Column(DateTime, nullable=False)
    user = relationship(User)

class LogoutRecord(BASE):
    __tablename__ = 'logout_records'
    record_number =  Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.user_id'), nullable=False)
    time_off = Column(DateTime, nullable=False)
    user = relationship(User)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)], id = "uname")
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)], id = "pword")
    phonenumber = StringField('phonenumber', validators=[InputRequired(), Length(min=10, max=11)], id = "2fa")
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)], id = "uname")
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)], id = "pword")
    phonenumber = StringField('phonenumber', validators=[InputRequired(), Length(min=10, max=11)], id = "2fa")

    


@app.route('/spell_check')
@login_required
def spell_check():
    return render_template('spell_check.html', name=current_user.username)

@app.route('/spell_check', methods=['POST'])
@login_required
def index_post():
    f = open("text.txt", "w")
    text = request.form['text']
    f.write(text)
    f.flush()
    f.close()
    proc = subprocess.Popen(["./a.out", "text.txt", "wordlist.txt"], stdout = subprocess.PIPE)
    print(proc)
    output_string = proc.stdout.read()
    print(output_string)
    output_string = ",".join(output_string.decode().split('\n'))
    print(output_string)
    return output_string


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(uname=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                #phonenumber = User.query.filter_by(user.phone=form.phonenumber.data).first()
                #if phonenumber:
                if user.phone==form.phonenumber.data:
                    login_record = LoginRecord(user_id=user_record.user_id, time_on=datetime.now())
                    session.add(login_record)
                    session.commit()
                    login_user(user, remember=form.remember.data)
                    return redirect(url_for('spell_check'))

        return '<h1>Invalid username or password</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hasher = SHA256()
        # Add password to hash algorithm.
        hasher.update(form.password.data.encode('utf-8'))
        # Generate random salt.
        salt = token_hex(nbytes=16)
        # Add random salt to hash algorithm.
        hasher.update(salt.encode('utf-8'))
        # Get the hex of the hash.
        pword_store = hasher.hexdigest()
        #hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(uname=form.username.data, pword=pword_store, salt=salt, email=form.email.data,  phone=form.phonenumber.data)
        db.session.add(new_user)
        db.session.commit()

        return '<h1>New user has been created!</h1>'
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('spell_check'))

if __name__ == '__main__':
    app.run(debug=True)
