import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, EmailField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from flask_bcrypt import Bcrypt
import re

app = Flask(__name__)

# Load sensitive settings from environment variables
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')  # Use a default in dev
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///secureapp.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Security settings
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class Student(db.Model):
    sno = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(50), nullable=False)
    lastname = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, raw_password):
        self.password_hash = bcrypt.generate_password_hash(raw_password).decode('utf-8')

    def check_password(self, raw_password):
        return bcrypt.check_password_hash(self.password_hash, raw_password)

class StudentForm(FlaskForm):
    firstname = StringField("First Name", validators=[DataRequired(), Length(min=2, max=50)])
    lastname = StringField("Last Name", validators=[DataRequired(), Length(min=2, max=50)])
    email = EmailField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[
        DataRequired(),
        Length(min=6),
        EqualTo('confirm_password', message="Passwords must match.")
    ])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired()])
    submit = SubmitField("Submit")

@app.route("/", methods=["GET", "POST"])
def home():
    form = StudentForm()
    if form.validate_on_submit():
        firstname = form.firstname.data.strip()
        lastname = form.lastname.data.strip()
        email = form.email.data.strip()
        password = form.password.data.strip()

        if re.search(r"(\bSELECT\b|\bDELETE\b|\bDROP\b|\bINSERT\b|\bUPDATE\b)", firstname + lastname, re.IGNORECASE):
            flash("Invalid input detected! Avoid SQL keywords.", "danger")
            return redirect(url_for('home'))

        new_student = Student(firstname=firstname, lastname=lastname, email=email)
        new_student.set_password(password)
        db.session.add(new_student)
        db.session.commit()
        flash("Student added successfully!", "success")
        return redirect(url_for('home'))

    records = Student.query.all()
    return render_template('index.html', form=form, records=records)

@app.route("/update/<int:sno>", methods=["GET", "POST"])
def update_student(sno):
    student = Student.query.get_or_404(sno)
    form = StudentForm()

    if form.validate_on_submit():
        student.firstname = form.firstname.data.strip()
        student.lastname = form.lastname.data.strip()
        student.email = form.email.data.strip()
        student.set_password(form.password.data.strip())
        db.session.commit()
        flash("Student record updated successfully!", "success")
        return redirect(url_for('home'))

    form.firstname.data = student.firstname
    form.lastname.data = student.lastname
    form.email.data = student.email
    return render_template('update.html', form=form)

@app.route("/delete/<int:sno>", methods=["POST"])
def delete_student(sno):
    student_to_delete = Student.query.get_or_404(sno)
    db.session.delete(student_to_delete)
    db.session.commit()
    flash("Student record deleted successfully.", "success")
    return redirect(url_for('home'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    port = int(os.environ.get("PORT", 5000))  # Railway needs to bind to the dynamic port
    app.run(host="0.0.0.0", port=port, debug=True)
