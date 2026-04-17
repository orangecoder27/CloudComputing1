from flask import Flask, render_template, request, redirect, session, url_for
from db import get_db_connection
import bcrypt
import boto3
import os
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
app.secret_key = "supersecretkey"  # change in production


def login_required(func):
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

s3 = boto3.client(
    "s3",
    region_name=os.getenv("AWS_REGION")
)
BUCKET = os.getenv("S3_BUCKET")


@app.route("/")
def home():
    return redirect("/login")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

        conn = get_db_connection()
        cur = conn.cursor()

        try:
            cur.execute(
                "INSERT INTO users (email, password_hash) VALUES (%s, %s)",
                (email, hashed.decode())
            )
            conn.commit()
        except:
            conn.rollback()
            return "User already exists!"

        cur.close()
        conn.close()

        return redirect("/login")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute(
            "SELECT id, password_hash FROM users WHERE email=%s",
            (email,)
        )
        user = cur.fetchone()

        cur.close()
        conn.close()

        if user:
            user_id, stored_hash = user

            if bcrypt.checkpw(password.encode(), stored_hash.encode()):
                session["user_id"] = user_id
                session["email"] = email
                return redirect("/dashboard")

        return "Invalid credentials"

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", email=session["email"])


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/test_s3")
def test_s3():
    import boto3
    import os

    s3 = boto3.client("s3", region_name=os.getenv("AWS_REGION"))
    
    buckets = s3.list_buckets()
    return str([b["Name"] for b in buckets["Buckets"]])

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        file = request.files["file"]

        if file:
            filename = secure_filename(file.filename)
            user_id = session["user_id"]

            s3_key = f"{user_id}/{filename}"

            # Upload to S3
            s3.upload_fileobj(file, BUCKET, s3_key)

            # Save to DB
            conn = get_db_connection()
            cur = conn.cursor()

            cur.execute(
                "INSERT INTO files (user_id, filename, s3_key) VALUES (%s, %s, %s)",
                (user_id, filename, s3_key)
            )

            conn.commit()
            cur.close()
            conn.close()

            return "Upload successful!"

    return render_template("upload.html")

@app.route("/files")
@login_required
def list_files():
    user_id = session["user_id"]

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        "SELECT id, filename, s3_key, uploaded_at FROM files WHERE user_id=%s",
        (user_id,)
    )

    files = cur.fetchall()

    cur.close()
    conn.close()

    return render_template("files.html", files=files)

@app.route("/download/<int:file_id>")
@login_required
def download(file_id):
    user_id = session["user_id"]

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT filename, s3_key FROM files WHERE id=%s AND user_id=%s",
        (file_id, user_id)
    )
    file = cur.fetchone()
    cur.close()
    conn.close()

    if not file:
        return "Unauthorized access", 403

    filename, s3_key = file

    fresh_s3 = boto3.client(
    "s3",
    region_name=os.getenv("AWS_REGION"),
    endpoint_url="https://s3.ap-south-1.amazonaws.com"
    )

    url = fresh_s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": BUCKET, "Key": s3_key},
        ExpiresIn=300
    )

    return redirect(url)




@app.route("/debug_time")
def debug_time():
    from datetime import datetime, timezone
    return str(datetime.now(timezone.utc))



@app.route("/admin")
def admin():
    # simple protection
    if session.get("email") != "admin@gmail.com":
        return "Unauthorized", 403

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT users.id, users.email, COUNT(files.id)
        FROM users
        LEFT JOIN files ON users.id = files.user_id
        GROUP BY users.id
    """)

    data = cur.fetchall()

    cur.close()
    conn.close()

    return render_template("admin.html", data=data)



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)