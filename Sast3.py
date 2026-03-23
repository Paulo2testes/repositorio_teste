import os
import subprocess
import sqlite3
import hashlib
import jwt # PyJWT
from flask import Flask, request, make_response

app = Flask(__name__)

# --- 1. SEVERIDADE: CRITICAL (Score 9.5) ---
# Remote Code Execution (RCE) via descarregamento de ficheiro e execução
@app.route("/execute")
def execute_command():
    # Input do utilizador que vai direto para a shell do sistema
    cmd = request.args.get("command")
    # CRITICAL: Permite que um atacante tome controlo total do servidor
    os.system(cmd) 
    return "Executado"

# --- 2. SEVERIDADE: HIGH (Score 8.5) ---
# SQL Injection Clássico
@app.route("/login")
def login():
    username = request.args.get("username")
    password = request.args.get("password")
    
    db = sqlite3.connect("users.db")
    # HIGH: Concatenação de strings em SQL sem parametrização
    query = f"SELECT * FROM users WHERE user='{username}' AND pass='{password}'"
    db.execute(query)
    return "Tentativa de login registada"

# --- 3. SEVERIDADE: MEDIUM (Score 5.5) ---
# JWT sem verificação de assinatura e Flask Debug Mode
@app.route("/admin")
def admin_zone():
    token = request.headers.get("Authorization")
    # MEDIUM: Descodificar JWT sem verificar a assinatura (verify=False)
    payload = jwt.decode(token, options={"verify_signature": False})
    
    if payload.get("user") == "admin":
        return "Bem-vindo, Admin"
    return "Acesso negado"

# --- 4. SEVERIDADE: LOW / INFO (Score 2.5) ---
# Uso de algoritmos de hashing fracos (MD5)
def hash_password(password):
    # LOW: MD5 é considerado criptograficamente quebrado/fraco para passwords
    return hashlib.md5(password.encode()).hexdigest()

# --- 5. SEVERIDADE: MEDIUM (Configuração Insegura) ---
# Cookie sem flag HttpOnly ou Secure
@app.route("/set-cookie")
def set_cookie():
    resp = make_response("Cookie definido")
    # MEDIUM: Cookie sensível sem proteção contra XSS (httponly=False)
    resp.set_cookie("session_id", "12345", httponly=False, secure=False)
    return resp

if __name__ == "__main__":
    # MEDIUM: Correr a app com modo debug ativo em rede pública
    app.run(host="0.0.0.0", debug=True)