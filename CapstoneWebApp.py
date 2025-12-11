from flask import Flask, request, render_template, redirect, url_for, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests

# --------------------------------
# Initialize Flask + Security
# --------------------------------
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SECRET_KEY"] = "secret"

# Google reCAPTCHA v2 Checkbox Keys
app.config["RECAPTCHA_SITE_KEY"] = "6Lez4ycsAAAAAMJphvyRiJFmwhRsj1UfWJeZV84X"
app.config["RECAPTCHA_SECRET_KEY"] = "6Lez4ycsAAAAACUwl7c2i-G-SGMlWFK2eJnSSyt2"

db = SQLAlchemy(app)

# Enable CSRF Protection
csrf = CSRFProtect(app)

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# --------------------------------
# INTRUSION DETECTION SYSTEM (IDS)
# --------------------------------

# A list of banned IPs in memory
banned_ips = set()

def get_client_ip():
    """Extract real IP safely."""
    return request.headers.get("X-Forwarded-For", request.remote_addr)

@app.before_request
def block_banned_ips():
    """Block banned IPs from accessing ANY route except localhost."""
    ip = get_client_ip()

    if ip in banned_ips and ip != "127.0.0.1":
        return "❌ Access denied. Your IP has been banned.", 403


# --------------------------------
# DATABASE MODELS
# --------------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)


# --------------------------------
# HOME ROUTES
# --------------------------------
@app.route("/")
def home():
    return render_template("home.html", title="Home")


@app.route("/about")
def about():
    return render_template("about.html", title="About")


# --------------------------------
# SIGNUP ROUTE
# --------------------------------
@app.route("/signup", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def signup():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return render_template("signup.html", error="Username already taken.")

        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for("login"))

    return render_template("signup.html")


# --------------------------------
# LOGIN ROUTE
# --------------------------------
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        # Only log the username, not the token
        app.logger.info(f"Login attempt for user: {username}")

        # Google reCAPTCHA verification
        token = request.form.get("g-recaptcha-response")
        if not token:
            return render_template("login.html", error="Please complete the reCAPTCHA.")

        verify_url = "https://www.google.com/recaptcha/api/siteverify"
        payload = {
            "secret": app.config["RECAPTCHA_SECRET_KEY"],
            "response": token
        }

        response = requests.post(verify_url, data=payload)
        result = response.json()

        if not result.get("success"):
            return render_template("login.html",
                                   error="Captcha validation failed. Try again.")

        # Validate user login
        user = User.query.filter_by(username=username).first()
        if user is None or user.password != password:
            return render_template("login.html",
                                   error="User or Password incorrect, please try again.")

        # Optional Admin Login
        if user.username == "admin" and user.password == "password":
            session["username"] = "admin"
            return redirect(url_for("admin_dashboard"))

        # Successful user login
        session["username"] = username
        return redirect(url_for("home"))

    return render_template(
        "login.html",
        recaptcha_site_key=app.config["RECAPTCHA_SITE_KEY"]
    )


# --------------------------------
# LOGOUT
# --------------------------------
@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("home"))


# --------------------------------
# ADMIN HONEYPOT SYSTEM
# --------------------------------

@app.route("/admin")
def admin_dashboard():
    ip = get_client_ip()

    # Only allow localhost: intrusion detection
    if ip != "127.0.0.1":
        banned_ips.add(ip)
        return render_template("fake404.html"), 404

    return render_template("admin_home.html")


@app.route("/admin/logs")
def admin_logs():
    ip = get_client_ip()

    if ip != "127.0.0.1":
        banned_ips.add(ip)
        return render_template("fake404.html"), 404

    return render_template("admin_logs.html")


@app.route("/admin/settings")
def admin_settings():
    ip = get_client_ip()

    if ip != "127.0.0.1":
        banned_ips.add(ip)
        return render_template("fake404.html"), 404

    return render_template("admin_settings.html")

# -------------------------
# User's Products Route
# -------------------------
@app.route("/your_products")
def your_products():
    # Only accessible if the user is logged in
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]

    # Here you can query the products specific to this user if you have a Product model
    # For demonstration, I'll just make a placeholder list
    user_products = [
        {"name": "Bizora CRM Suite", "price": "$49.99/month"},
        {"name": "Bizora Analytics", "price": "$29.99/month"},
        {"name": "Bizora Cloud Storage", "price": "$9.99/month"},
    ]

    return render_template(
        "your_products.html",
        username=username,
        products=user_products
    )



# --------------------------------
# Run App
# --------------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
