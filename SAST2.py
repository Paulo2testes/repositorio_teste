import sqlite3
import base64
import pickle
import os
from flask import Flask, request, render_template_string

app = Flask(__name__)

# 1. SQL Injection (Severidade: CRITICAL / HIGH)
# O Semgrep vai detetar que user_id vem do request e vai direto para a query
@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    
    # VULNERABILIDADE: Concatenação de strings em SQL
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
    return str(cursor.fetchone())

# 2. Insecure Deserialization (Severidade: HIGH / ERROR)
# O uso de pickle.loads com dados do utilizador permite Execução Remota de Código (RCE)
@app.route("/deserialize")
def unserialize():
    data = request.args.get("data")
    decoded_data = base64.b64decode(data)
    
    # VULNERABILIDADE: Pickle é inseguro para dados não confiáveis
    obj = pickle.loads(decoded_data)
    return "Objeto carregado"

# 3. Cross-Site Scripting - XSS (Severidade: MEDIUM / WARNING)
# Renderizar HTML diretamente de input do utilizador
@app.route("/hello")
def hello():
    name = request.args.get("name", "Guest")
    
    # VULNERABILIDADE: render_template_string com f-string causa XSS
    return render_template_string(f"<h1>Hello {name}</h1>")

# 4. Command Injection (Severidade: HIGH)
# Passar input do utilizador diretamente para o sistema operativo
@app.route("/ping")
def ping():
    hostname = request.args.get("host")
    
    # VULNERABILIDADE: os.system com input direto
    os.system("ping -c 1 " + hostname)
    return "Ping enviado"

# 5. Hardcoded Secret (Severidade: INFO / WARNING)
# Guardar chaves de API diretamente no código
API_KEY = "1a2b3c4d5e6f7g8h9i0j" 

if __name__ == "__main__":
    # 6. Debug Mode Enabled (Severidade: MEDIUM / WARNING)
    # Nunca deve estar ativo em produção
    app.run(debug=True)