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

logged_in_user = None

# First the declarative base we'll be working from.
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

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db' #DBFILE here?
bootstrap = Bootstrap(app)
#db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

#class User(UserMixin, db.Model):
#    id = db.Column(db.Integer, primary_key=True)
#    username = db.Column(db.String(15), unique=True)
#    password = db.Column(db.String(80))
#    phonenumber = db.Column(db.String(11))

class User(BASE):
    __tablename__ = 'users'
    user_id = Column(Integer, primary_key=True, autoincrement=True)
    children = relationship("Text")
    uname = Column(String(25), nullable=False, unique=True)
    pword = Column(String(64), nullable=False)
    salt = Column(String(16), nullable=False)
    #email = Column(String(30), nullable=False)
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
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)], id = "uname")
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)], id = "pword")
    phonenumber = StringField('phonenumber', validators=[InputRequired(), Length(min=10, max=11)], id = "2fa")
    
class SpellCheckForm(FlaskForm):
    inputtext = StringField('inputtext', validators=[InputRequired()], id = "inputtext")


@app.route('/spell_check')
@login_required
def spell_check(session, usr):    #how to call with logged_in_user
    form = SpellCheckForm()
    return render_template('spell_check.html', name=current_user.username, form=form) #revisit

@app.route('/spell_check', methods=['POST'])
@login_required
def index_post(session, usr):

    f = open("text.txt", "w")
    intext = request.form['text'] #input("Enter something you want checked: ")
    f.write(intext)
    f.flush()
    f.close()
    proc = subprocess.Popen(["./a.out", "text.txt", "wordlist.txt"], stdout = subprocess.PIPE)
    outtext = proc.stdout.read()
    outtext = ",".join(outtext.decode().split('\n'))
    print(outtext)

    new_text = Text(user_id=usr.uname, intext=intext, outtext=outtext, user=usr)
    session.add(new_text)
    # Probably want error handling, etc. For this simplified code,
    # we're assuming all is well.
    session.commit()

    usr.intext = intext
    usr.outtext = outtext
    return output_string

    #f = open("text.txt", "w")
    #text = request.form['text']
    #f.write(text)
    #f.flush()
    #f.close()
    #proc = subprocess.Popen(["./a.out", "text.txt", "wordlist.txt"], stdout = subprocess.PIPE)
    #print(proc)
    #output_string = proc.stdout.read()
    #print(output_string)
    #output_string = ",".join(output_string.decode().split('\n'))
    #print(output_string)
    #return output_string


@app.route('/login', methods=['GET', 'POST'])
def login(session):
    form = LoginForm()

    global logged_in_user

    if form.validate_on_submit():

	hasher = SHA256()
    	# Get the user we're attempting to log in as.
    	user_record = session.query(User).filter(User.uname == form.uname.data).first()
    	# Grab their salt.
    	salt = user_record.salt
    	# Add password and salt to hasher.
    	hasher.update(pword.encode('utf-8'))
    	hasher.update(salt.encode('utf-8'))
    	# Get hex digest.
    	password_hash = hasher.hexdigest()
    	# Confirm that the credentials are correct.
    	if(password_hash == user_record.pword):
            if (form.phone.data == user_record.phone):
                # Log this login.
                login_record = LoginRecord(user_id=user_record.user_id, time_on=datetime.now())
                session.add(login_record)
                session.commit()
                logged_in_user = user_record
                # return success.
                #return True, user_record
        # Auth failed.
        #return False
                login_user(user, remember=form.remember.data)
                return redirect(url_for('spell_check'))

        return '<h1 id = "result">Invalid username or password</h1>'
	
        #user = User.query.filter_by(username=form.username.data).first()
        #if user:
        #    if check_password_hash(user.password, form.password.data):
        #        phonenumber = User.query.filter_by(phonenumber=form.phonenumber.data).first()
        #        if phonenumber:
        #            login_user(user, remember=form.remember.data)
        #            return redirect(url_for('spell_check'))

        #return '<h1 id = "result">Invalid username or password</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register(session):
    form = RegisterForm()

    if form.validate_on_submit():
        #if len(form.password.data) > 7:
	pword = form.password.data
        hasher = SHA256()
    	# Add password to hash algorithm.
    	hasher.update(pword.encode('utf-8'))
    	# Generate random salt.
    	salt = token_hex(nbytes=16)
    	# Add random salt to hash algorithm.
    	hasher.update(salt.encode('utf-8'))
    	# Get the hex of the hash.
    	pword_store = hasher.hexdigest()
    	# Store the new user in the database.
    	new_user = User(uname=form.uname.data, pword=pword_store, salt=salt, phone=form.phone.data)
    	session.add(new_user)
    	# Probably want error handling, etc. For this simplified code,
    	# we're assuming all is well.
    	session.commit()


        #hashed_password = generate_password_hash(form.password.data, method='sha256')
        #new_user = User(username=form.username.data, password=hashed_password, phonenumber=form.phonenumber.data)
        #db.session.add(new_user)
        #db.session.commit()
        	#if form.phonenumber.data: 
        return '<h1 id="success">New user has been created! Success !</h1>'
        	#return '<h1 id = "success"> Failure !</h1>'
        	#return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout(session, usr):
    global logged_in_user
    user_record = session.query(User).filter(User.uname == usr).first()
    logout_record = LogoutRecord(user_id=user_record.user_id, time_off=datetime.now())
    session.add(logout_record)
    session.commit()
    logged_in_user = None
    return redirect(url_for('login'))
    #logout_user()
    #return redirect(url_for('spell_check'))


def main():
    global logged_in_user
    # Set up our database.
    DBSessionMaker = setup_db()
    # Grab a database session.
    session = DBSessionMaker()
    logged_in_user = None
    default(session)
    app.run(debug=True)
    #if True:
        #app.run(debug=True)


if __name__ == '__main__':
    main()
    #app.run(debug=True)
