from flask import Flask, jsonify, request

app = Flask(__name__)

@app.route('/confirm_payment', methods=['POST'])
def confirm_payment():
    try:
        # Imprimir los datos recibidos para ver qué estamos recibiendo
        print("Headers:", request.headers)  # Imprime los encabezados de la solicitud
        print("Content-Type:", request.content_type)  # Verifica si es application/json
        print("Request data:", request.data)  # Imprime el cuerpo en bruto

        # Intentar parsear los datos JSON
        data = request.json  # Esto convierte el cuerpo a un dict en Python

        # Extraemos los datos del JSON (podrían ser diferentes según lo que envíes)
        payment_received = data.get("payment_confirmed", False)

        # Imprimimos los datos extraídos para ver qué contiene
        print("Payment confirmed:", payment_received)

        # Si se recibe el pago, solo confirmamos la recepción
        if payment_received:
            return jsonify({"message": "Pago confirmado."}), 200
        else:
            return jsonify({"message": "Pago no confirmado."}), 400
    except Exception as e:
        print("Error:", str(e))  # Si hay error, lo mostramos
        return jsonify({"error": str(e)}), 400


# Iniciar el servidor Flask
def run_flask():
    app.run(host="0.0.0.0", port=5000)

if __name__ == "__main__":
    run_flask()
