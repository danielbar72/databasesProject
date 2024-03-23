from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'secretkey'

db = SQLAlchemy(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(80), nullable=False)
    firstname = db.Column(db.String(20), nullable=False)
    lastname = db.Column(db.DateTime(20), nullable=False, default=datetime.now)

class RegistrationForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
            min=4, max=20)], render_kw={"placeholder" : "Username"})
    
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder" : "Password"})
                           

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/genie')
def genie():
    return render_template('genie.html')

@app.route('/', methods = ['GET'])
def index():    
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
    with app.app_context():
        db.create_all()