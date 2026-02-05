from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
import bcrypt
from database import get_db

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "secret123"
jwt = JWTManager(app)

# Create database table (runs once)
db = get_db()
db.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password BLOB)")
db.commit()

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    hashed_password = bcrypt.hashpw(
        data["password"].encode("utf-8"),
        bcrypt.gensalt()
    )

    db = get_db()
    db.execute(
        "INSERT INTO users VALUES (?, ?)",
        (data["username"], hashed_password)
    )
    db.commit()

    return jsonify(message="User registered successfully")

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE username=?",
        (data["username"],)
    ).fetchone()

    if user and bcrypt.checkpw(
        data["password"].encode("utf-8"),
        user[1]
    ):
        token = create_access_token(identity=data["username"])
        return jsonify(token=token)

    return jsonify(message="Invalid username or password"), 401

@app.route("/dashboard")
@jwt_required()
def dashboard():
    return jsonify(message="Welcome! You are authenticated.")

if __name__ == "__main__":
    app.run(debug=True)
