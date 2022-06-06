import sqlite3
from flask import Flask, render_template, flash, redirect, request, url_for
from flask_wtf import FlaskForm
from sqlalchemy.orm import backref, relationship
from sqlalchemy.exc import IntegrityError, InterfaceError, InternalError
from wtforms import StringField, IntegerField, SelectField, SubmitField, TextAreaField, \
    EmailField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, EqualTo, DataRequired, Length
from wtforms import ValidationError
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy import Column, ForeignKey, String, Table
import os
import csv
from flask_login import LoginManager, UserMixin, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_required
from flask_migrate import Migrate
from sqlalchemy.engine import Engine
from sqlalchemy import event, create_engine

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///pharm.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your secret key'


login_manager = LoginManager()
login_manager.init_app(app)


# initialize the database
db = SQLAlchemy(app)
migrate = Migrate(app, db) #for updates/migration

# Then run 'flask db init' and "flask db migrate -m 'Added foreign key'", then "flask db upgrade"


# Create a User Class
class Pharm_User(UserMixin, db.Model): #owner
    __tablename__ = 'pharm_user'
    #__table_args__ = {'schema': 'pharm'}
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), index=True, unique=True)
    email = db.Column(db.String(150), unique=True, index=True)
    password_hash = db.Column(db.String(150))
    joined_at = db.Column(db.DateTime(), default=datetime.utcnow, index=True)
    inputter = relationship("Pharmacy", backref="Pharm_User.id")


    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='sha256')


    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<Name %r>' % self.id


class Pharmacy(db.Model):
    __tablename__ = "pharmacy"
    #__table_args__ = {'schema': 'pharm'}
    id = db.Column(db.Integer, primary_key=True)
    input_date = db.Column(db.DateTime, default=datetime.today())
    emr = db.Column(db.Integer, nullable=False)
    scheme = db.Column(db.String(200), nullable=False)
    medication1 = db.Column(db.String(200), nullable=False)
    medication2 = db.Column(db.String(200))
    medication3 = db.Column(db.String(200))
    medication4 = db.Column(db.String(200))
    payment = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(200), nullable=False)
    remark = db.Column(db.String(200))
    input_by = db.Column(db.Integer, ForeignKey("pharm_user.id"))
    pharm_user = relationship(Pharm_User, primaryjoin=input_by == Pharm_User.id)


##################################
# to effect change, do migration: flask db init, flask db migrate -m 'Added foreign key'

# Create a string
def __repr__(self):
    return '<Name %r>' % self.id

# For foreign to be displayed in the db

engine = create_engine('sqlite:///pharm.db', echo=True)

def _fk_pragma_on_connect(dbapi_con, con_record):
    dbapi_con.execute('pragma foreign_keys=ON')
event.listen(engine, 'connect', _fk_pragma_on_connect)

@login_manager.user_loader
def load_user(id):
    return Pharm_User.query.filter(Pharm_User.id==int(id)).first()


class RegistrationForm(FlaskForm):
    username = StringField('username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password1 = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField('Confirm Password', validators=[DataRequired(),
                                          EqualTo('password1', message="Passwords must match !"),
                                                              ])
    submit = SubmitField('Register')


def validate_email(self, email):
    if Pharm_User.query.filter_by(email=email.data).first():
        raise ValidationError("Email already registered!")

def validate_username (self, username):
    if Pharm_User.query.filter_by(username=username.data).first():
        raise ValidationError("Username already taken!")

#@app.route("/forbidden",methods=['GET', 'POST'])
#@login_required
#def protected():
 #   return redirect(url_for('login'))

@login_manager.unauthorized_handler
def unauthorized_callback():
    flash(f"login required", "success")
    return redirect(url_for('login'))


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


# Create a Form Class
class pharmform(FlaskForm):
    emr = IntegerField("EMR", validators=[InputRequired()])
    scheme = SelectField("Scheme", choices=[('', ''), ('cash', 'Cash'), ('nhis', 'NHIS'), ('phis', 'PHIS'),
                                            ('ghis', 'GHIS'), ('fhss', 'FHSS'), ('corporate', 'CORPORATE')],
                         validators=[InputRequired()])
    medication1 = StringField("Medication1", validators=[InputRequired()])
    medication2 = StringField("Medication2")
    medication3 = StringField("Medication3")
    medication4 = StringField("Medication4")
    payment = IntegerField("payment", validators=[InputRequired()])
    status = SelectField("Status", choices=[('', ''), ('available', 'Available'), ('stock_out', 'Out of Stock')],
                         validators=[InputRequired()])
    remark = TextAreaField("Remark")
    submit = SubmitField("Submit")


# @app.route("/forbidden",methods=['GET', 'POST'])
# @login_required
# def protected():
#   return redirect('forbidden.html')

@app.route("/", methods=("GET", "POST"))
def index():

    return render_template("index.html")


@app.route('/register/', methods=['POST', 'GET'])
def register():
    form = RegistrationForm()
    username = form.username
    if form.validate_on_submit():
        try:
            user = Pharm_User(username=form.username.data, email=form.email.data)
            user.set_password(form.password1.data)
            if user.username == "admin":
                try:
                    db.session.add(user)
                    db.session.commit()
                    flash("User added successfully. Now you can log in", "success")
                finally:
                    return redirect(url_for('login'))
            else:
                flash("Only Admin can add User", "danger")
                return redirect(url_for('login'))
        except IntegrityError:
            flash('You might have an account, if not contact admin', 'danger')
            return redirect(url_for('login'))

        except InterfaceError:
            flash('You might have an account, if not contact admin', 'danger')
            return redirect(url_for('register'))

        except InternalError:
            flash('You might have an account, if not contact Admin. Thank you', 'danger')
            redirect(url_for('login'))
    return render_template('register.html', form=form)





@app.route('/login/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
            user = Pharm_User.query.filter_by(email=form.email.data).first()
            if user is not None and user.check_password(form.password.data):
                login_user(user)
                next = request.args.get("next")
                flash(f"Login Successfull!!!!.", "success")
            return redirect(url_for('pharma_rec'))
    #else:
       # flash("You need to register", "warning")
       # return redirect(url_for('register'))
    return render_template('login.html', form=form)


@app.route("/logout/")
def logout():
    logout_user()
    flash("You have been logged out", "success")
    return redirect(url_for('login'))



@app.route('/pharma_rec/', methods=['GET', 'POST'])
@login_required
def pharma_rec():
    emr = None
    scheme = None
    medication1 = None
    medication2 = None
    medication3 = None
    medication4 = None
    payment = None
    status = None
    remark = None
    form = pharmform()
    if form.validate_on_submit():
        new_rec = Pharmacy(emr=form.emr.data, scheme=form.scheme.data.upper(),
                           medication1=form.medication1.data.upper(), medication2=form.medication2.data.upper(),
                           medication3=form.medication3.data.upper(), medication4=form.medication4.data.upper(),
                           payment=form.payment.data, status=form.status.data.upper(),
                           remark=form.remark.data.upper())

        db.session.add(new_rec)
        db.session.commit()

        emr = form.emr.data
        form.emr.data = ''

        scheme = form.scheme.data
        form.scheme.data = ''

        medication1 = form.medication1.data
        form.medication1.data = ''

        medication2 = form.medication2.data
        form.medication2.data = ''

        medication3 = form.medication4.data
        form.medication4.data = ''

        payment = form.payment.data
        form.payment.data = ''

        status = form.status.data
        form.status.data = ''

        remark = form.remark.data
        form.remark.data = ''

        flash("Record added successfully", "success")
        recs = Pharmacy.query.order_by(Pharmacy.input_date)
    return render_template("pharma_rec.html", emr=emr, scheme=scheme, medication1=medication1,
                           medication2=medication2, medication3=medication3, medication4=medication4,
                           payment=payment, status=status, remark=remark, form=form)


@app.route("/records")
@login_required
def records():
    con = sqlite3.connect("pharm.db")
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("select * from Pharmacy order by input_date desc")
    rows = cur.fetchall()
    return render_template("records.html", rows=rows)


@app.route("/prescription_report")
@login_required
def prescription_report():
    conn = sqlite3.connect("pharm.db")
    cursor = conn.cursor()
    cursor.execute("select * from Pharmacy")
    with open("pharmacy_records.csv", "w") as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow([i[0] for i in cursor.description])
        csv_writer.writerows(cursor)

        dirpath = os.getcwd() + "/pharmarcy_record.csv"
        flash("Data exported Successfully into {}".format(dirpath), "success")
        return render_template("prescription_report.html")
        conn.close()



if __name__ == "__main__":
    app.run(debug=True)
