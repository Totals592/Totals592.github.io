from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo
import secrets
import stripe

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)  # Generate a secure secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'  # Use SQLite for simplicity
db = SQLAlchemy(app)

# Stripe API Keys (replace with your actual keys)
stripe.api_key = "YOUR_STRIPE_SECRET_KEY"
PUBLISHABLE_KEY = "YOUR_STRIPE_PUBLISHABLE_KEY"

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    iptv_subscription = db.Column(db.Boolean, default=False)
    gift_cards = db.relationship('GiftCard', backref='owner', lazy=True)

class GiftCard(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.Integer, nullable=False)
    used = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class IPTVSubscriptionForm(FlaskForm):
    duration = SelectField('Subscription Duration', choices=[('1', '1 Month'), ('3', '3 Months'), ('12', '12 Months')], validators=[DataRequired()])
    submit = SubmitField('Subscribe')

class GiftCardForm(FlaskForm):
    value = SelectField('Gift Card Value', choices=[('10', '$10'), ('25', '$25'), ('50', '$50'), ('100', '$100')], validators=[DataRequired()])
    submit = SubmitField('Purchase Gift Card')

# Routes
@app.route('/')
def home():
    return render_template('home.html', publishable_key=PUBLISHABLE_KEY)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Hash password before storing it!
        # password_hash = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=form.password.data) #In production hash the password
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.password == form.password.data: # In production compare hashed passwords
            flash('You have been logged in!', 'success')
            return redirect(url_for('home')) # Change to profile page in production
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/iptv', methods=['GET', 'POST'])
def iptv():
    form = IPTVSubscriptionForm()
    if form.validate_on_submit():
        duration = int(form.duration.data)
        amount = 0
        if duration == 1:
            amount = 1000  # Example price in cents
        elif duration == 3:
            amount = 2700
        elif duration == 12:
            amount = 10000

        try:
            charge = stripe.Charge.create(
                amount=amount,
                currency='usd',
                description='IPTV Subscription',
                source=request.form['stripeToken']
            )
            # Update user's IPTV subscription status in the database
            # Example: user.iptv_subscription = True
            flash('Subscription successful!', 'success')
        except stripe.error.CardError as e:
            flash(str(e), 'danger')
        except Exception as e:
            flash('An error occurred.', 'danger')

        return redirect(url_for('home')) #change to profile page.

    return render_template('iptv.html', form=form, publishable_key=PUBLISHABLE_KEY)

@app.route('/giftcard', methods=['GET', 'POST'])
def giftcard():
    form = GiftCardForm()
    if form.validate_on_submit():
        value = int(form.value.data) * 100 #convert to cents
        try:
            charge = stripe.Charge.create(
                amount=value,
                currency='usd',
                description=f'Gift Card - ${form.value.data}',
                source=request.form['stripeToken']
            )
            # Generate a unique gift card code and store it in the database
            import uuid
            gift_card_code = str(uuid.uuid4())
            gift_card = GiftCard(code=gift_card_code, value=int(form.value.data))
            db.session.add(gift_card)
            db.session.commit()

            flash(f'Gift card purchased! Code: {gift_card_code}', 'success')
        except stripe.error.CardError as e:
            flash(str(e), 'danger')
        except Exception as e:
            flash('An error occurred.', 'danger')

        return redirect(url_for('home'))

    return render_template('giftcard.html', form=form, publishable_key=PUBLISHABLE_KEY)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables
    app.run(debug=True)
