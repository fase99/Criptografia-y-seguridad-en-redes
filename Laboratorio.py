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
    if len(key) > tamanio_req:
        key = key[:tamanio_req]
    elif len(key) < tamanio_req:
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
    
    try:
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
    except ValueError:
        key = DES3.adjust_key_parity(key)
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

    print(pyfiglet.figlet_format("LABORATORIO 4\n",)) 

    while True:
        print("OPCIONES [1 -> aes | 2 -> des | 3 -> 3des]")
        algorithm = input("INGRESE TIPO DE CIFRADO: \n")
        if algorithm in ["1", "2", "3"]:
            break
    
    while True:
        print("OPCIONES [1 -> cifrar | 2 -> descifrar]")
        accion = input("INGRESE ACCION A REALIZAR: \n")
        if accion in ["1", "2"]:
            break

    key = input("INGRESE CLAVE: \n")
    iv = input("INGRESE IV: \n")
    
    if accion == "1":
        act = "cifrar"
    elif accion == "2":
        act = "descifrar"

    if algorithm == "1":
        key = keyComplete(key, 32)
        iv =  keyComplete(iv, 16)
        if act == "cifrar":
            word = input("INGRESE TEXTO A CIFRAR: \n")
            #print(cifradoAES256(act, word, key, iv), "\n")
            print(f"Clave: {key}")
            print(f"IV: {iv}\n")
        else:
            while True:
                word = input("INGRESE CODIGO A DESCIFRAR (en base64): ")
                try:
                    base64.b64decode(word)
                    break
                except:
                    print("CODIGO NO VALIDO, INGRESE NUEVAMENTE") 
        print(cifradoAES256(act, word, key, iv))

    elif algorithm == "2":
        key = keyComplete(key, 8)
        iv =  keyComplete(iv, 8)
        if act == "cifrar":
            word = input("INGRESE TEXTO A CIFRAR: \n")
            #print(cifradoDes(act, word, key, iv), "\n")
            print(f"Clave: {key}")
            print(f"IV: {iv}\n")
        else:
            while True:
                word = input("INGRESE CODIGO A DESCIFRAR (en base64): ")
                try:
                    base64.b64decode(word)
                    break
                except:
                    print("CODIGO NO VALIDO, INGRESE NUEVAMENTE") 
        print(cifradoDes(act, word, key, iv))

    elif algorithm == "3":
        key = keyComplete(key, 24)
        iv =  keyComplete(iv, 8)
        if act == "cifrar":
            word = input("INGRESE TEXTO A CIFRAR: ")
            print(f"Clave: {key}")
            print(f"IV: {iv}\n")
        else:
            while True:
                word = input("INGRESE CODIGO A DESCIFRAR (en base64): ")
                try:
                    print(cifrado3des(act, word, key, iv))
                    break
                except Exception as e:
                    print(f"Error al descifrar: {e}. Por favor, intente de nuevo.")
        print(cifrado3des(act, word, key, iv), "\n")
        

if __name__ == "__main__":
    main()