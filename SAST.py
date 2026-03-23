import sqlite3
import pickle
import base64
from flask import Flask, request

app = Flask(__name__)

# 1. HARDCODED SECRET (Detectado pelo Semgrep Secrets/Pro)
SECRET_KEY = "super-secret-key-12345"
API_TOKEN = "ghp_1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ"

@app.route("/perfil")
def get_user():
    user_id = request.args.get("id")
    
    # 2. SQL INJECTION (OWASP Top 10)
    # Nunca concatene strings diretamente em queries SQL
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = '" + user_id + "'" 
    cursor.execute(query)
    
    return str(cursor.fetchone())

@app.route("/process")
def process_data():
    # 3. INSECURE DESERIALIZATION (Security Audit)
    # Receber dados do usuário e passar para o pickle é extremamente perigoso
    data = request.args.get("data")
    decoded_data = base64.b64decode(data)
    obj = pickle.loads(decoded_data) 
    return "Data processed"

@app.route("/say-hello")
def hello():
    name = request.args.get("name")
    # 4. CROSS-SITE SCRIPTING (XSS)
    # Refletir entrada do usuário sem sanitização
    return f"<h1>Hello {name}</h1>"

if __name__ == "__main__":
    app.run(debug=True) # 5. DEBUG MODE ON (Má prática de segurança)