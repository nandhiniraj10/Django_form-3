from flask import Flask, render_template, url_for, redirect, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_required, login_user, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, length, ValidationError
from flask_bcrypt import Bcrypt
from datetime import timedelta
import logging

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/Users/nandh/Downloads/flask-login/myenv/database.db'
app.config['SECRET_KEY']= 'thisisasecretkey'

# Extend the session timeout (optional)
app.permanent_session_lifetime = timedelta(days=7)  # Extend the session to 7 days

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader  #the purpose of the userloader, callback is retrive user object base on your user id in the session
def load_user(user_id):
    return User.query.get(int(user_id))

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(20), nullable = False,unique = True)
    password = db. Column(db.String(80), nullable = False)
    
    def __init__(self, username, password):
        self.username = username
        self.password = password
        
    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)
    
class RegisterForm(FlaskForm):
    username = StringField(validators = [InputRequired(), length(min = 4, max = 20)], render_kw={"placeholder":"Username"})
    password = PasswordField(validators = [InputRequired(), length(min = 4, max = 20)], render_kw={"placeholder":"Password"})
    submit = SubmitField("Register")
    
    def validate_username(self,username):
        existing_user_username = User.query.filter_by(username = username.data).first()
        
        if existing_user_username:
            raise ValidationError("That username already exists. please choose a different name")
    
    
class LoginForm(FlaskForm):
    username = StringField(validators = [InputRequired(), length(min = 4, max = 20)], render_kw={"placeholder":"Username"})
    password = PasswordField(validators = [InputRequired(), length(min = 4, max = 20)], render_kw={"placeholder":"Password"})
    submit = SubmitField("Login")
    

@app.route('/')
def home():
    return render_template("home.html")

@app.route('/login', methods = ['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username = form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user, remember = True)
                return redirect(url_for('dashboard'))
                
    return render_template("login.html",form = form)


@app.route('/dashboard', methods = ['GET','POST'])
@login_required
def dashboard():
    # You can access the current user's attributes like username
    username = current_user.username
    #flash("Welcome, {}!".format(username))
    return render_template('success.html', username=username)
    # return render_template('success.html')


@app.route('/logout', methods = ['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
    

@app.route('/register',methods = ['GET','POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        # hashed_password = bcrypt.generate_password_hash(form.password.data)
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username= form.username.data, password = hashed_password)
        db.session.add(new_user)
        db.session.commit()
        # flash("User created successfully!")
        # message = flash('Registration successful. You can now log in.', category = 'success')
        # flash_message = "User created successfully!"
        return redirect(url_for('login'))
        
    return render_template("signup.html",form = form)


# Store the current user's details in the session
@app.before_request
def get_current_user():
    if current_user.is_authenticated:
        session['current_user'] = current_user.username
    else:
        session.pop('current_user', None)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error_code=404, error_message="Page not found"), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('error.html', error_code=500, error_message="Internal Server Error"), 500


    
if __name__ == "__main__":
    with app.app_context():
        try:
            db.create_all()
            # db.drop_all()
            logging.info("Database tables created successfully.")
        except Exception as e:
            logging.error(f"Database table creation failed: {str(e)}")
    app.run(debug=True)
    

    
    
 