import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "cambia_esto_por_algo_muy_secreto"  # necesario para sesiones

# ---------- CONEXIÓN A LA BD ----------
def get_db_connection():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn

# ---------- CREAR TABLA USERS SI NO EXISTE ----------
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
        """
    )
    conn.commit()
    conn.close()

# Ejecutar al iniciar la app
init_db()

# ---------- RUTA PRINCIPAL ----------
@app.route("/")
def index():
    # Siempre arrancamos en la pantalla de login
    return redirect(url_for("login"))


# ---------- REGISTER ----------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")   
        email = request.form.get("email")
        password = request.form.get("password")
        confirm = request.form.get("confirm")

        if not username or not email or not password or not confirm:
            flash("Completa todos los campos.", "error")
            return redirect(url_for("register"))

        if password != confirm:
            flash("Las contraseñas no coinciden.", "contraseña_error")
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (username, email, password_hash),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            flash("El rut o correo ya existen", "register_error")
            conn.close()
            return redirect(url_for("register"))
        
        conn.close()
        return render_template("ventana.html")

    # GET → mostrar formulario de registro
    return render_template("register.html")


# ---------- LOGIN ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username_or_email = request.form.get("username_or_email")
        password = request.form.get("password")

        if not username_or_email or not password:
            flash("Ingresa usuario y contraseña.", "error")
            return render_template("login.html")

        # Buscar usuario por username o email
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (username_or_email, username_or_email),
        )
        user = cursor.fetchone()
        conn.close()

        # Verificar que exista Y que la contraseña sea correcta
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("home"))
        else:
            flash("Usuario o contraseña incorrectos.", "login_error")
            return redirect(url_for('login'))

    # GET → mostrar login
    return render_template("login.html")


# ---------- PÁGINA PROTEGIDA ----------
@app.route("/home")
def home():
    if "user_id" not in session:
        flash("Debes iniciar sesión primero.", "error")
        return redirect(url_for("login"))
    return render_template("home.html", username=session["username"])


# ---------- LOGOUT ----------
@app.route("/logout")
def logout():
    session.clear()
    flash("Sesión cerrada.", "success")
    return redirect(url_for("login"))

# ---------- OLVIDASTE TU CONTRASEÑA ----------
@app.route("/olvidaste", methods=["GET", "POST"])
def olvidaste():
    if request.method == "POST":
        username_or_email = request.form.get("username_or_email")
        new_password = request.form.get("password")
        confirm = request.form.get("confirm")

        # Validaciones básicas
        if not username_or_email or not new_password or not confirm:
            flash("Completa todos los campos.", "error")
            return redirect(url_for("olvidaste"))

        if new_password != confirm:
            flash("Las contraseñas no coinciden.", "error")
            return redirect(url_for("olvidaste"))

        conn = get_db_connection()
        cursor = conn.cursor()

        # Buscar usuario por RUT o correo
        cursor.execute(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (username_or_email, username_or_email),
        )
        user = cursor.fetchone()

        if not user:
            conn.close()
            flash("No encontramos un usuario con ese RUT o correo.", "error")
            return redirect(url_for("olvidaste"))

        # Actualizar contraseña
        password_hash = generate_password_hash(new_password)
        cursor.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (password_hash, user["id"]),
        )
        conn.commit()
        conn.close()

        flash("Contraseña actualizada correctamente. Ahora puedes iniciar sesión.", "success")
        return redirect(url_for("login"))

    # GET → mostrar formulario para recuperar contraseña
    return render_template("olvidaste.html")


if __name__ == "__main__":
    app.run(debug=True)