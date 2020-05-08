from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired, Email, Length, EqualTo
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = "SECRET_KEY"
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    username = db.Column(db.String(50), unique=True)
    email = db.Column(db.String(50))
    pswd = db.Column(db.String(80))

class Admin(UserMixin, db.Model):
    eid = db.Column(db.String(8), primary_key=True)
    name = db.Column(db.String(50))
    username = db.Column(db.String(50), unique=True)
    email = db.Column(db.String(50))
    pswd = db.Column(db.String(80))

class Emp(UserMixin, db.Model):
    empid = db.Column(db.String(8), primary_key=True)
    name = db.Column(db.String(50))
    username = db.Column(db.String(50), unique=True)
    email = db.Column(db.String(50))
    pswd = db.Column(db.String(80))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class RegisterForm(FlaskForm):
    name = StringField('Full Name', validators=[InputRequired(), Length(min=6, max=50)], render_kw={"placeholder": "Full Name"})
    username = StringField('Username', validators=[InputRequired(), Length(min=2, max=50)], render_kw={"placeholder": "Username"})
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(min=7, max=50)], render_kw={"placeholder": "Email"})
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80), EqualTo('conf_password', message='Passwords must match')],  render_kw={"placeholder": "Password"})
    conf_password=PasswordField('Repeat Password',  render_kw={"placeholder": "Repeat Password"})

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=2, max=50)], render_kw={"placeholder": "Username"})
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)],  render_kw={"placeholder": "Password"})

class ChangePassword(FlaskForm):
    oldp = PasswordField('Current Password', validators=[InputRequired(), Length(min=8, max=80)],  render_kw={"placeholder": "Current Password"})
    newp = PasswordField('New Password', validators=[InputRequired(), Length(min=8, max=80), EqualTo('conf_newp', message='Passwords must match')],  render_kw={"placeholder": "New Password"})
    conf_newp = PasswordField('Confirm New Password',  render_kw={"placeholder": "Confirm New Password"})

@app.route('/home')
def home():
    if current_user.is_authenticated:
        id = current_user.id
        return render_template('home_user.html', id=id)
    else:
        return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form=LoginForm()
    error=None
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.pswd, form.password.data):
                login_user(user)
                return redirect(url_for('home'))
            else:
                error = 'Invalid Username or Password. Please try again.'
                return render_template('login.html', form=form, error=error)
        else:
            admin = Admin.query.filter_by(username=form.username.data).first()
            if admin:
                if (admin.pswd==form.password.data):
                    #login_user(admin)
                    return redirect(url_for('admin_dashboard', eid=admin.eid))
                else:
                    error = 'Invalid Username or Password. Please try again.'
                    return render_template('login.html', form=form, error=error)
            else:
                emp = Emp.query.filter_by(username=form.username.data).first()
                if emp:
                    if check_password_hash(emp.pswd, form.password.data):
                        #login_user(emp)
                        return redirect(url_for('staff_dashboard', empid=emp.empid))
                    else:
                        error = 'Invalid Username or Password. Please try again.'
                        return render_template('login.html', form=form, error=error)
                else:
                    error = 'Invalid Username or Password. Please try again.'
                    return render_template('login.html', form=form, error=error)

    return render_template('login.html', form=form, error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(name=form.name.data, username=form.username.data, email=form.email.data, pswd=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Sucessfully Signed Up! Please login to proceed.')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/dashboard/<int:id>')
@login_required
def dashboard(id):
    user= User.query.get_or_404(id)

    return render_template('dashboard.html', user=user)

@app.route('/admin_dashboard/<string:eid>')
#@login_required
def admin_dashboard(eid):
    user= Admin.query.get_or_404(eid)
    
    return render_template('admin_dashboard.html', user=user)

@app.route('/staff_dashboard/<string:empid>')
#@login_required
def staff_dashboard(empid):
    user= Emp.query.get_or_404(empid)

    return render_template('staff_dashboard.html', user=user)

@app.route('/dashboard/chpswd/<id>', methods=['GET', 'POST'])
def change_password(id):
    form = ChangePassword()
    error=None
    if form.validate_on_submit():
        user=User.query.get_or_404(id)
        if user:
            if check_password_hash(user.pswd, form.oldp.data):
                pass
            else:
                error = 'Current Password is incorrect. Please try again.'
                return render_template('change_password.html', form=form, error=error)

        #else:
        #    user=Admin.query.get_or_404(id)
        #    if user:

        #    else:
        #        user=Emp.query.get_or_404(id)
        #        if user:


    return render_template('change_password.html', form=form, error=error)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/ulogout')
#@login_required
def ulogout():
    return redirect(url_for('home'))

if __name__ == "__main__":
    app.run(debug=True)
