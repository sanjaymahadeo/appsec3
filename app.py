import subprocess
from flask import Flask, render_template, redirect, url_for, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    password = db.Column(db.String(80))
    phonenumber = db.Column(db.String(11))

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
def spell_check():
    form = SpellCheckForm()
    return render_template('spell_check.html', name=current_user.username, form=form)

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
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                phonenumber = User.query.filter_by(phonenumber=form.phonenumber.data).first()
                if phonenumber:
                    login_user(user, remember=form.remember.data)
                    return redirect(url_for('spell_check'))

        return '<h1 id = "result">Invalid username or password</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        #if len(form.password.data) > 7:
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, password=hashed_password, phonenumber=form.phonenumber.data)
        db.session.add(new_user)
        db.session.commit()
        #if form.phonenumber.data: 
        return '<h1 id="success">New user has been created! Success !</h1>'
        #return '<h1 id = "success"> Failure !</h1>'
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('spell_check'))

if __name__ == '__main__':
    app.run(debug=True)
