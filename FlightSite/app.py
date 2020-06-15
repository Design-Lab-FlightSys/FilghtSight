from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, IntegerField, SelectField
from wtforms.fields.html5 import DateTimeLocalField, DateField
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
    name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(50), nullable=False)
    pswd = db.Column(db.String(80), nullable=False)

class Admin(UserMixin, db.Model):
    eid = db.Column(db.String(8), primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(50), nullable=False)
    pswd = db.Column(db.String(80), nullable=False)

class Emp(UserMixin, db.Model):
    empid = db.Column(db.String(8), primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(50), nullable=False)
    pswd = db.Column(db.String(80), nullable=False)

class Announcements(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    datePosted = db.Column(db.DateTime, nullable=False, default = datetime.utcnow)
    body = db.Column(db.Text, nullable=False)
    postedBy = db.Column(db.String(50), nullable=False)

class Flights(UserMixin, db.Model):
    fid = db.Column(db.String(6), primary_key=True)
    src = db.Column(db.String(200), nullable=False)
    dest = db.Column(db.String(200), nullable=False)
    arrtime = db.Column(db.DateTime, nullable=False)
    deptime = db.Column(db.DateTime, nullable=False)
    tzone = db.Column(db.String(10), nullable=False)
    eprice = db.Column(db.Integer, nullable=False)
    bprice = db.Column(db.Integer, nullable=False)
    seats = db.Column(db.Integer, nullable=False)
    airline = db.Column(db.String(50), nullable=False)

class Passenger(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mob = db.Column(db.String(10), nullable=False)
    age = db.Column(db.Integer, nullable = False)
    gender = db.Column(db.String(1), nullable=False)
    idDoc = db.Column(db.String(20), nullable=False)
    typ = db.Column(db.String(20), nullable=False)

class Booking(UserMixin, db.Model):
    bookid = db.Column(db.Integer, primary_key=True)
    bdate = db.Column(db.DateTime, default = datetime.utcnow)
    fid = db.Column(db.String(6), nullable=False)
    uid = db.Column(db.Integer, nullable=False)
    clss = db.Column(db.String(10), nullable=False)
    airline = db.Column(db.String(50), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    tdate = db.Column(db.DateTime, nullable=False)
    ddate = db.Column(db.DateTime, nullable=False)
    src = db.Column(db.String(200), nullable=False)
    dest = db.Column(db.String(200), nullable=False)

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
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4, max=80)],  render_kw={"placeholder": "Password"})

class ChangePassword(FlaskForm):
    oldp = PasswordField('Current Password', validators=[InputRequired(), Length(min=4, max=80)],  render_kw={"placeholder": "Current Password"})
    newp = PasswordField('New Password', validators=[InputRequired(), Length(min=8, max=80), EqualTo('conf_newp', message='Passwords must match')],  render_kw={"placeholder": "New Password"})
    conf_newp = PasswordField('Confirm New Password',  render_kw={"placeholder": "Confirm New Password"})

class AddStaff(FlaskForm):
    empid = StringField('Employee ID', validators=[InputRequired(), Length(min=8, max=8)], render_kw={"placeholder": "Employee ID"})
    name = StringField('Full Name', validators=[InputRequired(), Length(min=6, max=50)], render_kw={"placeholder": "Full Name"})
    username = StringField('Username', validators=[InputRequired(), Length(min=2, max=50)], render_kw={"placeholder": "Username"})
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(min=7, max=50)], render_kw={"placeholder": "Email"})

class AnnouncementForm(FlaskForm):
    body = TextAreaField('Announcement', validators=[InputRequired(), Length(max=10000)], render_kw={"placeholder": "Make Announcement"})

class AddFlights(FlaskForm):
    fid = StringField('Flight ID', validators=[InputRequired(), Length(min=6, max=6)], render_kw={"placeholder": "Flight ID"})
    src = StringField('Source', validators=[InputRequired(), Length(max=200)], render_kw={"placeholder": "Source Airport"})
    dest = StringField('Destination', validators=[InputRequired(), Length(max=200)], render_kw={"placeholder": "Destination Airport"})
    arrtime = DateTimeLocalField('arrtime', format='%Y-%m-%dT%H:%M')
    deptime = DateTimeLocalField('deptime', format='%Y-%m-%dT%H:%M')
    tzone = StringField('Timezone', validators=[InputRequired(), Length(max=10)], render_kw={"placeholder": "Timezone"})
    eprice = IntegerField('EclassPrice', validators=[InputRequired()], render_kw={"placeholder": "Ticket price"})
    bprice = IntegerField('BclassPrice', validators=[InputRequired()], render_kw={"placeholder": "Ticket price"})
    seats = IntegerField('seats', validators=[InputRequired()], render_kw={"placeholder": "Numbers of Seats"})
    airline = StringField('Airline', validators=[InputRequired(), Length(max=50)], render_kw={"placeholder": "Airline"})

class SearchFlights(FlaskForm):
    fid = StringField('Flight ID', render_kw={"placeholder": "Flight ID"})
    tdate = DateField('tdate', format='%Y-%m-%d')
    src = SelectField('src' ,choices=[])
    dest = SelectField('dest' ,choices=[])

class BookFlights(FlaskForm):
    mob = StringField('mobile', validators=[InputRequired(), Length(min=10,max=10)], render_kw={"placeholder": "Mobile No."})
    age = StringField('age', validators=[InputRequired(), Length(min=1,max=3)], render_kw={"placeholder": "Age"})
    gen = SelectField('Gender', choices=[('Male','Male'), ('Female','Female'), ('Other','Other')])
    clss = SelectField('Class', choices=[('Economy','Economy'), ('Business','Business')])
    typ = SelectField('IDtyp', choices=[('Aadhar Card','Aadhar Card'), ('Pan Card','Pan Card'), ('Driving License','Driving License'), ('Election Commission ID Card','Election Commission ID Card')])
    idDoc = StringField('mobile', validators=[InputRequired(), Length(min=6,max=20)], render_kw={"placeholder": "ID No."})

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
        else:
            admin = Admin.query.filter_by(username=form.username.data).first()
            if admin:
                if (admin.pswd==form.password.data):
                    #login_user(admin)
                    return redirect(url_for('admin_dashboard', eid=admin.eid))
                else:
                    error = 'Invalid Username or Password. Please try again.'
            else:
                emp = Emp.query.filter_by(username=form.username.data).first()
                if emp:
                    if check_password_hash(emp.pswd, form.password.data):
                        #login_user(emp)
                        if check_password_hash(emp.pswd, form.username.data):
                            flash('Default Password currently set. Please change your password')
                        return redirect(url_for('staff_dashboard', empid=emp.empid))
                    else:
                        error = 'Invalid Username or Password. Please try again.'
                else:
                    error = 'Invalid Username or Password. Please try again.'

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
    announcements = Announcements.query.all()
    psngr = Passenger.query.get(id)

    if(psngr):
        return render_template('dashboard.html', user=user, announcements=announcements, psngr=psngr)
    else:
        return render_template('dashboard.html', user=user, announcements=announcements, psngr=None)

@app.route('/admin_dashboard/<string:eid>')
def admin_dashboard(eid):
    user= Admin.query.get_or_404(eid)
    
    return render_template('admin_dashboard.html', user=user)

@app.route('/admin_dashboard/<string:eid>/add_staff', methods=['GET', 'POST'])
def add_staff(eid):
    form = AddStaff()
    usernameCheck=None
    if form.validate_on_submit():
        l=Emp.query.all()
        unames=[i.username for i in l]
        if form.username.data not in unames:
            pword = generate_password_hash(form.username.data, method='sha256')
            staff = Emp(empid=form.empid.data, name=form.name.data, username=form.username.data, email=form.email.data, pswd=pword)
            db.session.add(staff)
            db.session.commit()
            flash('New Employee added successfully. Default password is username itself!')
            return redirect(url_for('admin_dashboard', eid=eid))
        else:
            usernameCheck='Username already exists.Please try something else'

    return render_template('add_staff.html', form=form, usernameCheck=usernameCheck, eid=eid)

@app.route('/admin_dashboard/<string:eid>/view_staff')
def view_staff(eid):
    staff = Emp.query.all()

    return render_template('view_staff.html', staff=staff, eid=eid)

@app.route('/admin_dashboard/<string:eid>/view_staff/delete_staff/<string:empid>')
def delete_staff(empid,eid):
    staff = Emp.query.get_or_404(empid)
    db.session.delete(staff)
    db.session.commit()
    return redirect(url_for('view_staff', eid=eid))

@app.route('/staff_dashboard/<string:empid>')
def staff_dashboard(empid):
    user= Emp.query.get_or_404(empid)

    return render_template('staff_dashboard.html', user=user)

@app.route('/staff_dashboard/<string:empid>/make_announcements', methods=['GET', 'POST'])
def make_announcements(empid):
    announcements = Announcements.query.all()
    staff= Emp.query.get_or_404(empid)
    form = AnnouncementForm()

    if form.validate_on_submit():
        new_announcement = Announcements(body= form.body.data, postedBy= staff.name)
        db.session.add(new_announcement)
        db.session.commit()

    return render_template('announcements.html', empid=empid, form=form, announcements=announcements)

@app.route('/staff_dashboard/<string:empid>/make_announcements/delete_ann/<int:id>')
def delete_ann(empid, id):
    ann = Announcements.query.get_or_404(id)
    db.session.delete(ann)
    db.session.commit()
    return redirect(url_for('make_announcements', empid=empid))

@app.route('/staff_dashboard/<string:empid>/add_flights', methods=['GET', 'POST'])
def add_flights(empid):
    form = AddFlights()
    if form.validate_on_submit():
        flight = Flights(fid=form.fid.data, src=form.src.data, dest=form.dest.data, arrtime=form.arrtime.data, deptime=form.deptime.data, tzone=form.tzone.data, eprice=form.eprice.data, bprice=form.bprice.data, seats=form.seats.data, airline=form.airline.data)
        db.session.add(flight)
        db.session.commit()
        flash('Flight added successfully')
        return redirect(url_for('staff_dashboard', empid=empid))

    return render_template('add_flights.html', form=form, empid=empid)

@app.route('/staff_dashboard/<string:empid>/view_flight', methods=['GET','POST'])
def view_flight(empid):
    flights = Flights.query.all()

    return render_template('view_flight.html', empid=empid, flights=flights)

@app.route('/staff_dashboard/<string:empid>/del_flight/<string:fid>')
def del_flight(empid, fid):
    flight = Flights.query.get_or_404(fid)
    booking = Booking.query.filter_by(fid=fid)
    db.session.delete(flight)
    for b in booking:
        db.session.delete(b)
    db.session.commit()
    return redirect(url_for('view_flight', empid=empid))

@app.route('/chpswd/<id>', methods=['GET', 'POST'])
def change_password(id):
    form = ChangePassword()
    error=None
    if form.validate_on_submit():
        if len(str(id))<8:    
            user=User.query.get(id)
            if user:
                if check_password_hash(user.pswd, form.oldp.data):
                    user.pswd=generate_password_hash(form.newp.data, method='sha256')
                    db.session.commit()
                    flash('Password Changed successfully')
                    return redirect(url_for('dashboard', id=id))
                else:
                    error = 'Current Password is incorrect. Please try again.'
        else:
            user=Admin.query.get(id)
            if user:
                if user.pswd == form.oldp.data:
                    user.pswd = form.newp.data
                    db.session.commit()
                    flash('Password Changed successfully')
                    return redirect(url_for('admin_dashboard', eid=id))    
                else:
                    error = 'Current Password is incorrect. Please try again.'
            else:
                user=Emp.query.get(id)
                if user:
                    if check_password_hash(user.pswd, form.oldp.data):
                        user.pswd=generate_password_hash(form.newp.data, method='sha256')
                        db.session.commit()
                        flash('Password Changed successfully')
                        return redirect(url_for('staff_dashboard', empid=id))
                    else:
                        error = 'Current Password is incorrect. Please try again.'

    return render_template('change_password.html', form=form, error=error, id=id)

@app.route('/dashboard/<int:id>/view_flight_user', methods=['GET', 'POST'])
@login_required
def view_flight_user(id):
    flights = Flights.query.all()
    src = [(i.src,i.src) for i in flights]
    dest = [(i.dest,i.dest) for i in flights]
    form = SearchFlights()
    form.src.choices = src
    form.dest.choices = dest

    if form.validate_on_submit():
        if(form.fid.data and form.src.data and form.dest.data):
            flights=Flights.query.filter_by(fid=form.fid.data, src=form.src.data, dest=form.dest.data)
        elif(form.fid.data and form.src.data):
            flights=Flights.query.filter_by(fid=form.fid.data, src=form.src.data)
        elif(form.fid.data and form.dest.data):
            flights=Flights.query.filter_by(fid=form.fid.data, dest=form.dest.data)
        elif(form.src.data and form.dest.data):
            flights=Flights.query.filter_by(src=form.src.data, dest=form.dest.data)
        elif(form.fid.data):
            flights=Flights.query.filter_by(fid=form.fid.data)
        elif(form.src.data):
            flights=Flights.query.filter_by(src=form.src.data)
        elif(form.dest.data):
            flights=Flights.query.filter_by(dest=form.dest.data)

    return render_template('view_flight_user.html', id=id, flights=flights, form=form)

@app.route('/dashboard/<int:id>/view_flight_user/<string:fid>/book_flights', methods=['GET', 'POST'])
@login_required
def book_flights(id,fid):
    booking = Booking.query.filter_by(fid=fid, uid=id).first()
    if(booking):
        flash('Flight already Booked, refer View Booked Flights for details')
        return redirect(url_for('view_flight_user', id=id))

    user = User.query.get_or_404(id)
    flight = Flights.query.get_or_404(fid)
    form = BookFlights()
    psngr = Passenger.query.get(id)

    if form.validate_on_submit():
        if(not(psngr)):
            psngr = Passenger(id=id, mob=form.mob.data, age=form.age.data, gender=form.gen.data, idDoc=form.idDoc.data, typ=form.typ.data)
            db.session.add(psngr)
        if(form.clss.data == "Economy"):
            price=flight.eprice
        elif(form.clss.data == "Business"):
            price=flight.bprice
        if(not(price)):
            flash('Business class not available')
            return redirect(url_for('book_flights', id=id, fid=fid))
        book = Booking(fid=fid, uid=id, clss=form.clss.data, airline=flight.airline, price=price, tdate=flight.arrtime, ddate=flight.deptime, src=flight.src, dest=flight.dest)
        db.session.add(book)
        flight.seats=flight.seats-1
        db.session.commit()
        return redirect(url_for('payment', id=id, fid=fid))

    return render_template('booking.html' , form=form, user=user, flight=flight, psngr=psngr)

@app.route('/dashboard/<int:id>/view_flight_user/<string:fid>/book_flights/payment', methods=['GET','POST'])
@login_required
def payment(id,fid):
    booking = Booking.query.filter_by(fid=fid, uid=id).first()
    if request.method=='POST':
        return redirect(url_for('paymentg', id=id))

    return render_template('payment.html', booking=booking)

@app.route('/dashboard/<int:id>/paymentg')
@login_required
def paymentg(id):
    return render_template('paymentG.html', id=id)

@app.route('/dashboard/<int:id>/view_booked')
@login_required
def view_booked(id):
    booking = Booking.query.filter_by(uid=id)
    user = User.query.get_or_404(id)

    return render_template('view_booked.html', booking=booking, user=user)

@app.route('/dashboard/<int:id>/view_booked/<int:bid>/cancel_booking')
@login_required
def cancel_booking(id,bid):
    booking = Booking.query.get_or_404(bid)
    db.session.delete(booking)
    flight=Flights.query.get_or_404(booking.fid)
    flight.seats=flight.seats+1
    db.session.commit()
    return redirect(url_for('view_booked', id=id))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/ulogout')
def ulogout():
    return redirect(url_for('home'))

if __name__ == "__main__":
    app.run(debug=True)
