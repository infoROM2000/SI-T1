import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

# specifice pentru deschiderea fisierului text
current_dir = os.path.dirname(__file__)
rel_path = "test.txt"
abs_path = os.path.join(current_dir, rel_path)

HOST = '127.0.0.1'  # localhost
PORT_B = 2000
PORT_KM = 3000
# A e doar client, nu are nevoie de PORT
BLOCK_SIZE = 16
K3 = "sGcLSEDUWUWTfW9j"  # cheia publica, cunoscuta de toate nodurile, generata in prealabil
cheia = ""  # cheia ce urmeaza a fi ceruta
moduri = ['ECB', 'ecb', 'OFB', 'ofb']  # modurile acceptate de incriptare
cifru = AES.new(K3.encode(), AES.MODE_ECB)  # generam inca de acum cifrul caracteristic K3
IV = b'00000000'  # vectorul de initializare pentru OFB


def bxor(b1, b2):  # operatia de xor pe biti dintre un caracter plaintext si primul byte din IV-ul incriptat cu cheia
    # print("\nUn xor:")
    # print(b1[0])
    # print(b2)
    xor = b1[0] ^ b2
    # print(xor)
    return xor


def criptare(fisier, cheie, mod,conn):  # aici aplicam efectiv ECB sau OFB si trimitem lui B rand pe rand text incriptat
    cifru_privat = AES.new(cheie.encode(), AES.MODE_ECB)  # cifrul specific cheii cerute
    # deschidem fisierul pentru a citi textul din el
    f = open(fisier, 'r')
    continut = f.read()
    f.close()
    i = 0
    if mod == 'ECB' or mod == 'ecb':
        bloc = ""
        while i < len(continut):
            bloc += continut[i]
            i += 1
            if i % 16 == 0:  # la ECB citim blocuri de cate 16 bytes/caractere si le incriptam cu cifrul_privat generat prin K1
                cyphertext = cifru_privat.encrypt(bloc.encode())  # incriptam fiecare bloc de text
                conn.sendall(cyphertext)  # il trimitem
                bloc = ""  # si reinitialiam blocul
        cyphertext = cifru_privat.encrypt(
            pad(bloc.encode(), BLOCK_SIZE))  # la ultimul bloc este necesar sa facem padding
        conn.sendall(cyphertext)  # si trimitem lui B ultimul bloc criptat
        conn.sendall("Gata".encode())  # mesaj de stop
    elif mod == 'OFB' or mod == 'ofb':
        block_cipher_encryption = cifru_privat.encrypt(pad(IV, 16)) #generam prima incriptare la IV
        while i < len(continut):
            # print(continut[i])
            cyphertext = bxor(block_cipher_encryption, ord(continut[i])) #facem xor intre IV incriptat si un caracter
            conn.sendall(cyphertext.to_bytes(1, 'big')) #trimitem byte-ul rezultat
            block_cipher_encryption = cifru_privat.encrypt(block_cipher_encryption) #si aplicam o noua incriptare lui IV incriptat
            i += 1
    conn.sendall("Gata".encode()) #mesaj de stop


def continua_procedura(modul): #aici ne conectam la KM si primim cheia specifica modului de incriptare pe care l-am cerut
    global cheia
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as con2:
        con2.connect((HOST, PORT_KM))
        ceva = con2.recv(1024)
        if ceva:
            print('Conexiune reusita cu nodul KM')
            con2.sendall(modul.encode())
            cheia = con2.recv(1024)
            cheia = cifru.decrypt(cheia).decode()  # aici decriptam cheia primit cu ajutorul cifrului generat de cheia publica K3
            if modul == 'ECB' or modul == 'ecb':
                print("Am primit cheia ECB: " + cheia)
            if modul == 'OFB' or modul == 'ofb':
                print("Am primit cheia OFB: " + cheia)


def initial(): # aici stabilim conexiunea cu B si ii trimitem modul (ECB sau OFB) dorit
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT_B))
        data = s.recv(1024).decode()
        if data:
            print(data)
            print('Conexiune reusita cu nodul B')
            print('Introduceti modul de operare dorit; ECB sau OFB')
            while True: #stam in while pana cand e introdus corect modul
                mod = input()
                if mod in moduri:
                    break
                else:
                    print("Mod invalid, mai introduceti o data!")
            s.sendall(mod.encode()) #trimitem modul dorit
            data = s.recv(1024).decode() #asteptam ca B sa primeasca si sa trimita OK
            continua_procedura(mod) #apoi cerem cheia specifica modului dorit de la KM
            s.sendall("Gata".encode()) #il informam pe B ca am terminat si se poate conecta si el la KM
            data = s.recv(1024).decode() #asteptam ca B sa termine
            criptare(abs_path, cheia, mod, s) #si aici incepem criptarea efectiv


if __name__ == "__main__":
    initial()
