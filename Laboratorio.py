from Crypto.Cipher import AES, DES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import pyfiglet
import base64

#para aes-256 se necesitan 32 bytes
#para DES se necesitan 8 bytes
#para 3DES se necesitan 24 bytes

#se completan los bytes que faltan a la clave ingresada
def keyComplete(key, tamanio_req):
    key = key.encode()
    if len(key) < tamanio_req:
        key += get_random_bytes(tamanio_req - len(key))
    return key[:tamanio_req]


def cifradoAES256(action,word, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)

    if action == "cifrar":
        textBytes= pad(word.encode(), AES.block_size) #se convierte a bytes
        texto_cifrado = cipher.encrypt(textBytes)
        textB64 = base64.b64encode(texto_cifrado).decode()
        return textB64

    elif action == "descifrar":
        textoBytes = base64.b64decode(word)
        texto_plano = unpad(cipher.decrypt(textoBytes), AES.block_size)
        return texto_plano.decode()
    
def cifradoDes(accion, word, key, iv):
    cipher = DES.new(key, DES.MODE_CBC, iv)

    if accion == "cifrar":
        textBytes= pad(word.encode(), DES.block_size)
        texto_cifrado = cipher.encrypt(textBytes)
        textB64 = base64.b64encode(texto_cifrado).decode()
        return textB64
    
    elif accion == "descifrar":
        textBytes = base64.b64decode(word)
        texto_plano = unpad(cipher.decrypt(textBytes), DES.block_size)
        return texto_plano.decode()
    
def cifrado3des(accion, word, key, iv):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)

    if accion == "cifrar":
        textBytes= pad(word.encode(), DES3.block_size)
        texto_cifrado = cipher.encrypt(textBytes)
        textB64 = base64.b64encode(texto_cifrado).decode()
        return textB64
    
    elif accion == "descifrar":
        textBytes = base64.b64decode(word)
        texto_plano = unpad(cipher.decrypt(textBytes), DES3.block_size)
        return texto_plano.decode()
    

def main():

    print(pyfiglet.figlet_format("LABORATORIO 4"))  

    print("OPCIONES [aes, des, 3des]")

    algorithm = input("INGRESE TIPO DE CIFRADO: ")
    accion = input("INGRESE ACCION A REALIZAR: ")
    key = input("INGRESE CLAVE: ")
    iv = input("INGRESE IV: ")

    if algorithm == "aes":
        key = keyComplete(key, 32)
        iv =  keyComplete(iv, 16)
        word = input("INGRESE TEXTO A CIFRAR: ")
        print(cifradoAES256(accion, word, key, iv))

    elif algorithm == "des":
        key = keyComplete(key, 8)
        iv =  keyComplete(iv, 8)
        word = input("INGRESE TEXTO A CIFRAR: ")
        print(cifradoDes(accion, word, key, iv))

    elif algorithm == "3des":
        key = keyComplete(key, 24)
        iv =  keyComplete(iv, 8)
        word = input("INGRESE TEXTO A CIFRAR: ")
        print(cifrado3des(accion, word, key, iv))
        


if __name__ == "__main__":
    main()