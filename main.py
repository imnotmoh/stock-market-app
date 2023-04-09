

from flask import Flask, redirect, render_template, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, Email,EqualTo, ValidationError
from wtforms import StringField,PasswordField, SubmitField, EmailField, SearchField
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
import os

portfolio_data = None
# creatimg the flask app and initializing the other modukles to be used
app = Flask(__name__)
app.config['SECRET_KEY'] = "dev"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///stock_app.db"
login_manager = LoginManager(app)
db = SQLAlchemy(app)
Bootstrap(app)

# login form
class LoginForm(FlaskForm):
    username_or_email = StringField("username or email", validators=[DataRequired()])
    password = PasswordField('password')
    submit = SubmitField('log in')
# sign up form
class Signup(FlaskForm):
    email = EmailField("email", validators=[Email("please enter a valid email adress"), DataRequired()])
    username = StringField("username", validators=[DataRequired()])
    password = PasswordField("enter password",validators=[DataRequired(),EqualTo('password')])
    confirm_password = PasswordField("confirm password",validators=[DataRequired()])
    submit = SubmitField('sign up')
    # validate if email or user name not already in the data base
    def validate_email(form, field):
        with app.app_context():
            check_email = db.session.query(Users).filter_by(email=field.data).first()
            if check_email != None:
                raise ValidationError('email is already registered')
    def validate_username(form, field):
        with app.app_context():
             check_username = db.session.query(Users).filter_by(user_name=field.data).first()
             if check_username != None:
                raise ValidationError('username is already registered')


# for fetching data from the api
def get_data(symbol:str):
    import requests
    end = "http://api.marketstack.com/v1/eod/latest"


    params = {
        "access_key":os.environ.get('stock_market_api_key');
        "symbols": symbol
    }
    response = requests.get(end,params=params)
    response.raise_for_status()
    return response.json()

# creating user data base(relational)
class Users(db.Model,UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True, nullable=False, unique=True)
    user_name = db.Column(db.String, nullable=False, unique=True)
    email = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String, nullable=False)
    stocks = db.relationship("Stocks", back_populates="user")
# creating stock data table
class Stocks(db.Model):
    __tablename__="stocks"
    id = db.Column(db.Integer,primary_key=True,nullable=False, unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    stock_ticker = db.Column(db.String, nullable=False)
    user = db.relationship("Users", back_populates="stocks")

with app.app_context():
    db.create_all()
#  search form
class Search(FlaskForm):
    search = SearchField("",render_kw={"placeholder":"search"})
    submit = SubmitField()

 
@login_manager.user_loader
def get_id(id):
    return db.session.query(Users).get(id)
    
# to login users
@app.route("/login",methods=["GET","POST"])
def login():
    global portfolio_data
    log_form = LoginForm()
    if log_form.validate_on_submit():
           user =  db.session.query(Users).filter_by(email=log_form.username_or_email.data).first()
           if user == None:
               user =  db.session.query(Users).filter_by(user_name=log_form.username_or_email.data).first()
           if check_password_hash(user.password,log_form.password.data):
               login_user(user) 
               return redirect(url_for('home'))
           else:
               flash("incorrect password")
               return redirect(url_for('login'))
        
    return render_template("login.html", form=log_form, user=current_user)

# to register new users
@app.route("/signup",methods=["GET","POST"])
def sign_up():
    sign_form = Signup()
    if sign_form.validate_on_submit():
        password = generate_password_hash(sign_form.password.data)
        new_user =Users(user_name=sign_form.username.data, email=sign_form.email.data,password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect (url_for('login'))
    return render_template("signup.html", form=sign_form, user=current_user)

@app.route('/',methods=["GET","POST"])
def home():
    search_form = Search()
    portfolio_data = None
    queryy = None
    if search_form.validate_on_submit():
        queryy = get_data(search_form.search.data).get('data')[0]  
        # calculate percentage change of searched stock
        queryy['percent'] = round(((float(queryy.get('close')) - float(queryy.get('open'))) / float(queryy.get('open'))) * 100, 2)
    if current_user.is_authenticated:
        user_stock = current_user.stocks
        portfolio_data = [get_data(stock.stock_ticker).get("data")[0] for stock in user_stock] 
        for i in portfolio_data:
            # calculate percentage change of each stock
            i['percent']=round(((float(i.get('close')) - float(i.get('open'))) / float(i.get('open'))) * 100, 2)
    user = current_user
    return render_template("index.html", form=search_form, stocks = portfolio_data, user=user, result=queryy)

@app.route('/logout', methods=["GET","POST"])
def log_out():
    logout_user()
    return redirect(url_for('home'))

# to add new stock
@app.route('/add/<ticker>')
def add(ticker):
    already_in_portfolio = False
    if current_user.is_authenticated:
        print('hri')
        for i in current_user.stocks:
            if i.stock_ticker == ticker:
                already_in_portfolio =True
        if not already_in_portfolio:
            new_stock = Stocks(stock_ticker=ticker, user=current_user)
            db.session.add(new_stock)
            db.session.commit()
        return redirect(url_for('home'))
    else:
        return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(debug=True)