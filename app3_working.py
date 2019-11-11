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
from flask_sqlalchemy  import SQLAlchemy, sqlalchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

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

def history(session, user):
    if user.uname != "admin":
        stmt = select('*').where(Text.user_id == user.user_id)
        result = session.execute(stmt).fetchall()
        print(result)
    else:
        stmt = select('*').select_from(Text)
        result = session.execute(stmt).fetchall()
        print(result)

def default(session):
    uname = "admin"
    pword = "Administrator@1"
    email = "admin@admin.com"
    phone = "12345678901"
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
    new_user = User(uname=uname, pword=pword_store, salt=salt, email=email, phone=phone)
    session.add(new_user)
    # Probably want error handling, etc. For this simplified code,
    # we're assuming all is well.
    session.commit()
 
def register(session):
    # Get username and password.
    uname = input("Username: ")
    pword = getpass("Password: ")
    email = input("Email: ")
    phone = input("Phone Number: ")
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
    new_user = User(uname=uname, pword=pword_store, salt=salt, email=email, phone=phone)
    session.add(new_user)
    # Probably want error handling, etc. For this simplified code,
    # we're assuming all is well.
    session.commit()

def login(session):
    uname = input("Username: ")
    pword = getpass("Password: ")
    phone = input("Phone Number: ")
    hasher = SHA256()
    # Get the user we're attempting to log in as.
    user_record = session.query(User).filter(User.uname == uname).first()
    # Grab their salt.
    salt = user_record.salt
    # Add password and salt to hasher.
    hasher.update(pword.encode('utf-8'))
    hasher.update(salt.encode('utf-8'))
    # Get hex digest.
    password_hash = hasher.hexdigest()
    # Confirm that the credentials are correct.
    if(password_hash == user_record.pword):
        if (phone == user_record.phone):
            # Log this login.
            login_record = LoginRecord(user_id=user_record.user_id, time_on=datetime.now())
            session.add(login_record)
            session.commit()
            # return success.
            return True, user_record
    # Auth failed.
    return False

def logout(session, usr):
    #uname = usr
    user_record = session.query(User).filter(User.uname == usr).first()
    logout_record = LogoutRecord(user_id=user_record.user_id, time_off=datetime.now())
    session.add(logout_record)
    session.commit()

def login_history(session):
    stmt = select('*').select_from(LoginRecord)
    result = session.execute(stmt).fetchall()
    print(result)
    stmt = select('*').select_from(LogoutRecord)
    result = session.execute(stmt).fetchall()
    print(result)

def spell_check(session, usr):
    f = open("text.txt", "w")
    intext = input("Enter something you want checked: ")
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

def main():
    # Set up our database.
    DBSessionMaker = setup_db()
    # Grab a database session.
    session = DBSessionMaker()
    logged_in_user = None
    default(session)
    while True:
        mode = int(input("1. Register\n2. Login\n3. Quit\nChoice: "))
        if mode == 1:
            register(session)
        elif mode == 2:
            success, logged_in_user = login(session)
            if success:
                print(f"You are now logged in as {logged_in_user.uname}.")
                if(logged_in_user.uname != "admin"):
                    while True:
                        mode = int(input("1. Spell Check\n2. History\n3. Logout\nChoice: "))
                        if mode == 1:
                            spell_check(session, logged_in_user)
                        elif mode == 2:
                            history(session, logged_in_user)
                        elif mode == 3:
                            logout(session, logged_in_user.uname)
                            logged_in_user = None
                            break
                        else:
                            continue
                else:
                    while True:
                        mode = int(input("1. Spell Check\n2. History\n3. Login History\n4. Logout\nChoice: "))
                        if mode == 1:
                            spell_check(session, logged_in_user)
                        elif mode == 2:
                            history(session, logged_in_user)
                        elif mode == 3:
                            login_history(session)
                        elif mode == 4:
                            logout(session, logged_in_user.uname)
                            logged_in_user = None
                            break
                        else:
                            continue
            else:
                print("Login failed.")
        elif mode == 3:
            session.close()
            break
        else:
            continue

if __name__ == '__main__':
    main()
