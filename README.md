<div align="center">

# MyTodo Flask App

### A secure, responsive todo manager built with Flask, PostgreSQL, SQLAlchemy, and SendGrid.

<p>
  <img src="https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Flask-3.1-000000?style=for-the-badge&logo=flask&logoColor=white" alt="Flask">
  <img src="https://img.shields.io/badge/PostgreSQL-Database-4169E1?style=for-the-badge&logo=postgresql&logoColor=white" alt="PostgreSQL">
  <img src="https://img.shields.io/badge/Bootstrap-5.3-7952B3?style=for-the-badge&logo=bootstrap&logoColor=white" alt="Bootstrap">
  <img src="https://img.shields.io/badge/SendGrid-Email-1A82E2?style=for-the-badge&logo=sendgrid&logoColor=white" alt="SendGrid">
</p>

<p>
  <a href="https://github.com/karangupta12-stack/Todo-python_flasks">View Repository</a>
</p>

</div>

---

## Overview

MyTodo is a full-stack Flask web application for managing personal tasks with user authentication, email verification, password reset, and database-backed todo storage. It is designed as a clean, practical productivity app with a Bootstrap interface and a secure backend foundation.

<table>
  <tr>
    <td><strong>Backend</strong></td>
    <td>Flask, Flask-SQLAlchemy, Flask-Migrate</td>
  </tr>
  <tr>
    <td><strong>Database</strong></td>
    <td>PostgreSQL</td>
  </tr>
  <tr>
    <td><strong>Auth</strong></td>
    <td>Hashed passwords, sessions, OTP email verification</td>
  </tr>
  <tr>
    <td><strong>Email</strong></td>
    <td>SendGrid Web API for OTP and password reset emails</td>
  </tr>
  <tr>
    <td><strong>Frontend</strong></td>
    <td>Jinja templates, Bootstrap 5, custom CSS</td>
  </tr>
</table>

## Features

- User registration and login
- Secure password hashing with Werkzeug
- Email OTP verification during account creation
- Resend OTP support
- Forgot password and reset password flow
- Create, read, update, and delete personal todos
- User-specific todo isolation
- Search todos from the navigation bar
- Flash messages for user feedback
- Responsive Bootstrap layout
- SQLAlchemy models and Flask-Migrate migrations
- Environment-based configuration for secrets, database, and email

## Tech Stack

| Layer | Tools |
| --- | --- |
| Framework | Flask 3.1 |
| Database ORM | Flask-SQLAlchemy |
| Migrations | Flask-Migrate, Alembic |
| Database | PostgreSQL |
| Email | SendGrid, Flask-Mail |
| Authentication | Werkzeug password hashing, Flask sessions |
| UI | Bootstrap 5, Jinja2, custom CSS |
| Deployment | Gunicorn-ready Python app |

## Project Structure

```text
Todo-python_flasks-main/
├── app.py
├── requirements.txt
├── procfile
├── static/
│   ├── favicon.png
│   └── css/
│       └── style.css
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── verify_email.html
│   ├── forgot_password.html
│   ├── reset_password.html
│   ├── update.html
│   └── emails/
│       ├── otp_template.html
│       └── reset_password_template.html
└── migrations/
```

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/karangupta12-stack/Todo-python_flasks.git
cd Todo-python_flasks
```

### 2. Create and activate a virtual environment

```bash
python -m venv .venv
```

Windows:

```bash
.venv\Scripts\activate
```

macOS/Linux:

```bash
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Create a `.env` file in the project root:

```env
SECRET_KEY=change-this-secret-key
SQLALCHEMY_DATABASE_URI=postgresql://username:password@localhost:5432/tododb
MAIL_PASSWORD=your-sendgrid-api-key
MAIL_DEFAULT_SENDER=your-verified-sender@example.com
```

Optional SMTP-style values are also supported by the app configuration:

```env
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=your-email@example.com
```

### 5. Run database migrations

```bash
flask db upgrade
```

### 6. Start the application

```bash
flask run
```

Open the app at:

```text
http://127.0.0.1:5000
```

## Environment Variables

| Variable | Required | Description |
| --- | --- | --- |
| `SECRET_KEY` | Yes | Secret key used for sessions and password reset tokens |
| `SQLALCHEMY_DATABASE_URI` | Yes | PostgreSQL connection string |
| `MAIL_PASSWORD` | Yes | SendGrid API key used to send OTP and password reset emails |
| `MAIL_DEFAULT_SENDER` | Yes | Verified sender email address |
| `MAIL_SERVER` | No | SMTP server fallback configuration |
| `MAIL_PORT` | No | SMTP port fallback configuration |
| `MAIL_USE_TLS` | No | Enables TLS for SMTP fallback configuration |
| `MAIL_USERNAME` | No | SMTP username fallback configuration |

## Routes

| Route | Description |
| --- | --- |
| `/` | Todo dashboard for logged-in users |
| `/about` | About page |
| `/register` | Create an account |
| `/verify-email` | Verify account with OTP |
| `/resend-otp` | Request a new OTP |
| `/login` | Sign in |
| `/forgot-password` | Request a password reset link |
| `/reset-password/<token>` | Set a new password |
| `/logout` | Sign out |
| `/update/<Sno>` | Update a todo |
| `/delete/<Sno>` | Delete a todo |
| `/email-setup` | Email setup page |



## Author

Built by [Karan Gupta](https://github.com/karangupta12-stack).

---

<div align="center">

<strong>MyTodo Flask App</strong><br>
Clean task management with authentication, email verification, and a professional Flask backend.

</div>
