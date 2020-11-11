import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT_B = 2000
PORT_KM = 3000
BLOCK_SIZE = 16
K3 = "sGcLSEDUWUWTfW9j"
cheia = ""
cifru = AES.new(K3.encode(), AES.MODE_ECB)
IV = b'00000000'


def bxor(b1, b2): #xor intre primul byte din IV criptat si un byte cryptotext
    # print("\nUn xor:")
    # print(b1[0])
    # print(b2)
    xor = b1[0] ^ b2
    # print(xor)
    return xor


def continua_procedura(modul): #aici primim cheia_privata necesara si o decriptam
    global cheia
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as con2:
        con2.connect((HOST, PORT_KM))
        ceva = con2.recv(1024)
        if ceva:
            print(ceva.decode())
            print('Conexiune reusita cu nodul KM')
            con2.sendall(modul.encode())
            cheia = con2.recv(1024)
            cheia = cifru.decrypt(cheia).decode()
            if modul == 'ECB' or modul == 'ecb':
                print("Am primit cheia ECB: " + cheia)
            if modul == 'OFB' or modul == 'ofb':
                print("Am primit cheia OFB: " + cheia)


def initial(): #initializam B ca server la care se va conecta A
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT_B))
        s.listen()
        print("Asteptam la 2000...")
        conn, addr = s.accept()
        with conn:
            print('Client conectat! ', addr)
            conn.sendall('OK'.encode())
            modul = conn.recv(1024).decode() #primim modul de operare de la A
            if modul:
                print('Am primit de la client mesajul:', modul)
                conn.sendall('OK'.encode()) #ii spunem lui A ca poate incepe sa ia cheia de la KM
                d = conn.recv(1024)  # asteptam sa termine nodul A conexiune cu nodul KM
                continua_procedura(modul) #aici facem ca la A, decriptam cheia primita
                conn.sendall("Putem incepe".encode()) #il informam pe A ca poate incepe incriptarea
                plaintext = ""
                cifru_privat = AES.new(cheia.encode(), AES.MODE_ECB)
                #aici vom primi blocuri de cryptotext si le vom decripta
                if modul == 'ECB' or modul == 'ecb':
                    while True:
                        cryptotext = conn.recv(64)
                        if cryptotext == b"Gata": #stop
                            break
                        else:
                            decript = cifru_privat.decrypt(cryptotext)
                            decript = decript.rstrip(b'\x06') #caractere in plus care apar ca ?
                            decript = decript.rstrip(b'\x04')
                            plaintext += decript.decode() #si adaugam bucata cu bucata la plaintext-ul mare
                elif modul == 'OFB' or modul == 'ofb':
                    block_cipher_encryption = cifru_privat.encrypt(pad(IV, BLOCK_SIZE))
                    # print(block_cipher_encryption)
                    while True:
                        cryptotext = conn.recv(8) # luam cate un byte o data
                        # print(cryptotext)
                        if cryptotext == b"Gata": #stop
                            break
                        else:
                            plaintext += chr(bxor(block_cipher_encryption, ord(cryptotext))) #aplicam xor intre cryptotext si IV-ul criptat
                            block_cipher_encryption = cifru_privat.encrypt(block_cipher_encryption) #si mai criptam inca o data IV cu cifrul cheii K2
                print("Am decriptat:", plaintext)


if __name__ == "__main__":
    initial()
