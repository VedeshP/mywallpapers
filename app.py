import os
import json
from contextlib import contextmanager
# for below pip install python-dotenv
from dotenv import load_dotenv

from flask import Flask, flash, redirect, render_template, request, session, jsonify, url_for
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

import cloudinary
import cloudinary.uploader
import cloudinary.api

import datetime

import sqlitecloud

from helpers import login_required, check_password_strength_basic, apology

app = Flask(__name__)

# Load environment variables from the .env file
load_dotenv()


# Get the secret key from an environment variable
#app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SECRET_KEY'] = 'trial-secret-key-123'


cloudinary.config(
    cloud_name= 'dwi054oye',
    api_key= os.getenv("CLOUDINARY_API_KEY"),
    api_secret= os.getenv("CLOUDINARY_API_SECRET")
)


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


SQLITECLOUD_DATABASE_URL = os.getenv('SQLC_DB_URL')


@contextmanager
def get_db_connection():
    db = sqlitecloud.connect(SQLITECLOUD_DATABASE_URL)
    try:
        yield db  # Setup: Provide the connection to the block
    finally:
        db.close()  # Teardown: Close the connection after the block


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    user_id = session["user_id"]
    if request.method == "POST":
        image = request.files.get("image")

        if not image:
            return apology("Please add image", 403)

        # Upload image to Cloudinary
        upload_result = cloudinary.uploader.upload(image)
        image_url = upload_result['url']

        with get_db_connection() as db:
            try:
                db.execute("BEGIN")
                db.execute(
                    """
                    INSERT INTO wallpapers (user_id, url)
                    VALUES (?, ?)
                    """,
                    (user_id, image_url)
                )
                db.execute("COMMIT")
            except Exception as e:
                db.execute("ROLLBACK")
                return apology(f"An error occured {str(e)}")
        return redirect(url_for('index'))
    else:
        with get_db_connection() as db:
            query = "SELECT * FROM wallpapers WHERE user_id = ?"
            params = (user_id,)
            rows = db.execute(query, params).fetchall()

            column_names = [desc[0] for desc in db.execute(query, params).description]
            images = [dict(zip(column_names, row)) for row in rows]

        #return jsonify(images)
        return render_template("index.html", images=images)


@app.route("/login", methods = ["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    if request.method == "POST":
        # Get details from the form
        username = request.form.get("username")
        username = username.strip()
        password = request.form.get("password")
        # Ensure username was submitted
        if not username:
            return apology("Must provide username", 403)

        # Ensure password was submitted
        elif not password:
            return apology("Must provide password", 403)

        with get_db_connection() as db:
            rows = db.execute("SELECT * FROM  users where username = ?", (username,))
        rows = [list(row) for row in rows]

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0][2], password 
        ):
            return apology("invalid username and/or password", 403)
        
        # Remember which user has logged in
        session["user_id"] = rows[0][0]

        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log User out"""
    # Forget user
    session.clear()
    return redirect("/login")


@app.route("/signup", methods = ["GET", "POST"])
def signup():
    """Register user"""
    # Forget any user_id
    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        username = username.strip()
        display_name = request.form.get("display_name")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        for i in username:
            if i == ' ':
                return apology("username must not contain space", 400)
        if not username:
            return apology("Must provide username", 400)
        if not display_name:
            return apology("Must provide Display Name", 400)
        if not password:
            return apology("Please set a password", 400)
        if not confirm_password:
            return apology("Must confirm password", 400)
        if password != confirm_password:
            return apology("Both password must be same", 403)

        if check_password_strength_basic(password):
            return apology("Password must contain atleast 8 characters, a special character, letters and numbers", 403)
        
        # Get password hash to store in the database
        hash = generate_password_hash(password)

        with get_db_connection() as db:
            try:
            # Register user 
            # Add user details to the database
                db.execute("BEGIN")
                db.execute(
                    """
                    INSERT INTO users (username, password, display_name)
                    VALUES (?, ?, ?)
                    """,
                    (username, hash, display_name)
                )
                db.execute("COMMIT")
            except Exception as e:
                # Rollback execution on error
                db.execute("ROLLBACK")
                error_message = str(e)
                if "UNIQUE constraint failed: users.username" in error_message:
                    return apology("Username already exists")
                else:
                    return apology("An integrity error occurred: " + error_message)

        flash("Signed Up! Login to Proceed")
        return redirect(url_for('login'))
    else:
        return render_template("signup.html")
