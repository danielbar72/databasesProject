from flask import Flask, render_template, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import csv, os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'secretkey'
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = "login"


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class Disease(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(1000))
    gene = db.relationship('Gene', uselist=False, back_populates='disease')
    treatment = db.relationship('Treatment', uselist=False, back_populates='disease')

class Gene(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False, unique=True)
    disease_id = db.Column(db.Integer, db.ForeignKey('disease.id'), unique=True)
    disease = db.relationship('Disease', back_populates='gene')

class Treatment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(200))
    disease_id = db.Column(db.Integer, db.ForeignKey('disease.id'), unique=True)
    disease = db.relationship('Disease', back_populates='treatment')

class RegistrationForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
            min=4, max=20)], render_kw={"placeholder" : "Username"})
    
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder" : "Password"})
    
    submit = SubmitField("Register")

    def validate_username(self, username):
        username_from_db = User.query.filter_by(username = username.data).first()

        if username_from_db:
            raise ValidationError("Username already taken")
        
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
            min=4, max=20)], render_kw={"placeholder" : "Username"})
    
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder" : "Password"})
    
    submit = SubmitField("Login")

@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    return user

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        usr = User.query.filter_by(username= form.username.data).first()
        if usr is None:
            return render_template('login.html', form = form)

        user = load_user(usr.id)
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect('/genie')
            
    return render_template('login.html', form = form)


@app.route('/logout', methods = ['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        db.Model()
        hashed_pwd = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_pwd)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/login')

    return render_template('register.html', form = form)

@app.route('/genie', methods=['GET', 'POST'])
@login_required
def genie():
    if request.method == 'GET':
        options = [d[0] for d in Disease.query.with_entities(Disease.name).all()]
        return render_template('genie.html', options=options, username=current_user.username)
    
    disease_name = request.form['option']
    d = Disease.query.filter_by(name=disease_name).first()
    treatment = Treatment.query.filter_by(disease_id=d.id).first()
    gene = Gene.query.filter_by(disease_id=d.id).first()
    return render_template('info.html', disease_name=disease_name, treatment_desc=treatment.description, gene_name=gene.name, username=current_user.username)

@app.route('/', methods = ['GET'])
def index():    
    return redirect('/login')



def fill_db():
    """    
    Fill the database with 
    Disease, gene, description, treatment
    """
    
    # Open the CSV file
    with open('diseases.csv', newline='') as csvfile:
        # Create a CSV reader object
        csv_reader = csv.reader(csvfile)
        
        # Iterate over each row in the CSV file
        for row in csv_reader:
            t = Treatment(description=row[3])
            d = Disease(name=row[0], description=row[2])
            g = Gene(name=row[1])
            d.treatment = t
            t.disease = d
            d.gene = g
            g.disease = d
            db.session.add_all([t,d,g])
        db.session.commit()




if __name__ == '__main__':
    if not os.path.exists('instance/database.db'):
    # Create the database if it doesn't exist
        
        with app.app_context():
            db.drop_all()
            try:
                db.create_all()
                print("Tables created successfully!")
                fill_db()
            except Exception as e:
                print("Error creating tables:", e)

    
    app.run(debug=True)
