# Capstone Web App

## Project Overview

This is a secure Flask web application built as a capstone project. It features user authentication, Google reCAPTCHA v2 integration, CSRF protection, rate limiting, and an admin interface. Users can sign up, log in, and view their personal products page. Admin-only pages include logs, settings, and a home page.

---

## Features

### User Features

* **Sign Up**: Users can create an account with a unique username and password.
* **Login**: Users can log in using their credentials.
* **CSRF Protection**: All forms include CSRF tokens to prevent cross-site request forgery.
* **reCAPTCHA v2**: Login form includes Google reCAPTCHA to prevent automated login attempts.
* **Rate Limiting**: Limits login and signup attempts to mitigate brute force attacks.
* **Personal Products Page**: Logged-in users can view a page showing their own products, e.g., `John's Products`.

### Admin Features

* **Admin Login**: Access to admin-only pages.
* **Fake Admin Pages**: `admin_home.html`, `admin_logs.html`, `admin_settings.html`, `fake404.html`.
* **IP Restriction**: Admin pages only accessible from localhost; other IPs are blocked.

### Security Measures

* **Flask-Limiter**: Rate limiting to prevent brute force login/signups.
* **CSRF Protection**: Implemented using Flask-WTF.
* **Google reCAPTCHA**: Prevents bots from logging in automatically.
* **Session Management**: Sessions are stored securely with a secret key.
* **Input Validation**: Prevents duplicate usernames and invalid form submissions.

---

## Project Structure

```
Final/
├── secureApp.py               # Main Flask application
├── users.db                   # SQLite database for users
├── templates/
│   ├── base.html              # Base template with navigation and footer
│   ├── home.html
│   ├── about.html
│   ├── login.html
│   ├── signup.html
│   ├── your_products.html
│   ├── admin_home.html
│   ├── admin_logs.html
│   ├── admin_settings.html
│   └── fake404.html
├── static/
│   ├── css/                   # CSS files
│   ├── js/                    # JavaScript files
│   └── images/                # Optional images for products
└── README.txt
```

---

## Installation

1. **Clone the repository**:

```bash
git clone <repository_url>
cd Final
```

2. **Create a virtual environment**:

```bash
python3 -m venv .venv
source .venv/bin/activate   # Linux / Mac
.venv\Scripts\activate      # Windows
```

3. **Install dependencies**:

```bash
pip install -r requirements.txt
```

> Required packages include:
>
> * Flask
> * Flask-SQLAlchemy
> * Flask-WTF
> * Flask-Limiter
> * Requests

---

## Configuration

* Set the secret keys for Flask session and Google reCAPTCHA in `secureApp.py`:

```python
app.config["SECRET_KEY"] = "your-secret-key"
app.config["RECAPTCHA_SITE_KEY"] = "<your-site-key>"
app.config["RECAPTCHA_SECRET_KEY"] = "<your-secret-key>"
```

* Ensure `users.db` is created automatically on first run.

---

## Running the App

```bash
python secureApp.py
```

* Visit [http://localhost:5000](http://localhost:5000) in your browser.
* Access admin pages only from `localhost`.

---

## Usage

1. Sign up for a new user account.
2. Log in with your credentials (complete the reCAPTCHA checkbox).
3. Once logged in, the navigation bar will show “Your Products”.
4. Admin users can log in with username `admin` and password `password` to access admin pages.

---

## Security Considerations

* **Do not use this exact setup for production.**
* Passwords are stored as plain text in the database; consider using hashing (e.g., bcrypt) in a real application.
* reCAPTCHA and CSRF tokens help prevent automated attacks and CSRF, but additional security measures may be required for production.

---

## License

This project is for educational purposes as part of a capstone project.

