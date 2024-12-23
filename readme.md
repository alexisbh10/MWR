# Simular ataque

Para simular cómo funcionaría un ataque de este ransomware entre un atacante y una víctima, se deben de seguir unos pasos. A continuación, se detalla como funcionaría el proceso, tanto desde el punto de vista del atacante como de la víctima.

## **Atacante**
### Paso 1 - ejecutar servidor flask.
El atacante debe ejecutar en primer lugar el servidor flask con el siguiente comando: 

 		python servidor.py
 
Esto hará que el servidor Flask se inicie y esté a la escucha en el puerto 5000 de la máquina del atacante. Con el fin de gestionar las claves y coordinar la comunicación con la víctima. 

### Paso 2 - esperar a la víctima.
Una vez que el servidor Flask esté en ejecución, el atacante deberá esperar a que la víctima ejecute el ransomware y se envíen las claves generadas (pública y privada), para luego procesar la confirmación de pago.



## **Víctima**
### Paso 1 - ejecutar ransomware.
En el lado de la víctima, el proceso de ataque se lleva a cabo al ejecutar el ransomware. En este caso, se simula en una máquina virtual de windows 10 para aislar el ataque en un entorno controlado.

### Paso 2 - cifrado.
El ransomware comienza a cifrar los archivos de la víctima (Downloads, Documents, Pictures, Music y Videos ) utilizando la clave pública generada. Los archivos cifrados tendrán una extensión específica (.encrypted) para indicar que están cifrados.

### Paso 3 - enviar claves servidor.
Una vez que el ransomware haya cifrado los archivos, enviará las claves (pública y privada) al servidor Flask del atacante.

### Paso 4 - mostra mensaje.
El ransomware en la víctima muestra un mensaje en pantalla que informa a la víctima que sus archivos han sido cifrados y que deben pagar un rescate para obtener la clave privada y poder desencriptarlos. Además, se deshabilita el administrador de tareas para que sea imposible que la víctima pueda cerrarlo.

### Paso 5 - esperar la confirmación de pago.
Finalmente, la víctima debe pagar el rescate solicitado para recibir la clave privada que permitirá desencriptar sus archivos. Una vez que la víctima realiza el pago, el atacante puede confirmar que el pago se ha procesado y desencriptar los archivos de manera automática.
