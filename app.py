from flask import Flask, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import csv

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
    #firstname = db.Column(db.String(20))
    #lastname = db.Column(db.String(20))
    #registration_date = db.Column(db.DateTime(20), default=datetime.now)




disease_gene = db.Table('disease_gene', 
    db.Column('disease_id', db.Integer, db.ForeignKey('disease.id')),
    db.Column('gene_id', db.Integer, db.ForeignKey('gene.id')))



"""
    disease_drug = db.Table('disease_treatment', 
    db.Column('disease_id', db.Integer, db.ForeignKey('disease.id')),
    db.Column('treatment_id', db.Integer, db.ForeignKey('treatment.id')))

"""
class Disease(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    description = db.Column(db.String(200))
    symptoms = db.Column(db.String(200))
    genes = db.relationship('Gene', secondary=disease_gene, backref='genes')
    treatment = db.relationship('Treatment', uselist=False, back_populates='disease')

class Gene(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False, unique=True)
    chromosome = db.Column(db.Integer)
    function = db.Column(db.String(200))

class Treatment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    #name = db.Column(db.String(200), nullable=False, unique=True)
    description = db.Column(db.String(200))
    disease_id = db.Column(db.Integer, db.ForeignKey('disease.id'), unique=True)
    disease = db.relationship('Disease', back_populates='treatment')
    #mechanism_of_action = db.Column(db.String(200))
    #side_effects = db.Column(db.String(200))

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

    return render_template('index.html', form = form)

@app.route('/genie')
@login_required
def genie():
    return render_template('genie.html')

@app.route('/', methods = ['GET'])
def index():    
    return render_template('index.html')



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
            d.genes.append(g)
            db.session.add_all([t,d,g])
        db.session.commit()




if __name__ == '__main__':
    with app.app_context():
        db.drop_all()
        try:
            db.create_all()
            print("Tables created successfully!")
            fill_db()
        except Exception as e:
            print("Error creating tables:", e)

    
    app.run(debug=True)
