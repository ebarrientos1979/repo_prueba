import os
import pickle
import subprocess
import sqlite3
from flask import Flask, request, render_template_string

app = Flask(__name__)


# Vulnerabilidad 1: Inyección SQL
@app.route('/login', methods=['GET', 'POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Inyección SQL deliberada
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return "Login exitoso!"
    else:
        return "Credenciales inválidas", 401

# Vulnerabilidad 2: Ejecución de comandos OS
@app.route('/ping')
def ping():
    host = request.args.get('host', '8.8.8.8')
    
    # Ejecución de comandos sin sanitización
    command = f"ping -c 4 {host}"
    output = subprocess.check_output(command, shell=True)
    
    return output.decode()

# Vulnerabilidad 3: Deserialización insegura
@app.route('/load')
def load_data():
    data = request.args.get('data')
    
    # Deserialización insegura
    loaded_data = pickle.loads(bytes.fromhex(data))
    return str(loaded_data)

# Vulnerabilidad 4: XSS (Cross-Site Scripting)
@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    # XSS deliberado
    template = f"<h1>Resultados para: {query}</h1>"
    return render_template_string(template)

# Vulnerabilidad 5: Hardcoded credentials
DB_PASSWORD = "supersecret123"  # Contraseña hardcodeada

# Vulnerabilidad 6: Uso de algoritmos criptográficos débiles
import hashlib
def hash_password(password):
    # Uso de MD5 que es inseguro
    return hashlib.md5(password.encode()).hexdigest()

# Vulnerabilidad 7: Path traversal
@app.route('/read_file')
def read_file():
    filename = request.args.get('file', 'example.txt')
    
    # Path traversal deliberado
    with open(filename, 'r') as f:
        content = f.read()
    
    return content

# Vulnerabilidad 8: Logging de información sensible
@app.route('/pay')
def make_payment():
    card_number = request.form.get('card_number')
    
    # Logging de información sensible
    app.logger.info(f"Procesando pago con tarjeta: {card_number}")
    return "Pago procesado"

if __name__ == '__main__':
    # Vulnerabilidad 9: Configuración insegura
    app.run(debug=True)  # Modo debug activado en producción
