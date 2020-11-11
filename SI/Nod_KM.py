import socket  # comunicare cu celelalte noduri
from Crypto.Cipher import AES  # pentru criptarea cu K3 a K1 si K2

HOST = '127.0.0.1'  # localhost
PORT_KM = 3000
K3 = "sGcLSEDUWUWTfW9j"  # toate cheile generate aleator inainte
K1 = "UeHDgyGRfVh3wugh"  # ECB
K2 = "wx8JFyWajpQmKQFQ"  # OFB
BLOCK_SIZE = 16  # bytes


def conexiune():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT_KM))
        s.listen()
        print("Asteptam la 3000...")
        conn, addr = s.accept()
        with conn:
            print('Client conectat! ', addr)
            conn.sendall('OK'.encode())
            data = conn.recv(1024).decode()  # aici primim modul de criptare dorit
            if data:
                print('Am primit de la client mesajul:', data)
                cifru = AES.new(K3.encode(), AES.MODE_ECB) # se genereaza cifrul pe baza cheii K3, care e pe 64 de biti
                if data == 'ecb' or data == 'ECB': # se incripta cheia ceruta
                    mesaj = cifru.encrypt(K1.encode())
                elif data == 'ofb' or data == 'OFB':
                    mesaj = cifru.encrypt(K2.encode())
                print('Am trimis:',print(mesaj))
                conn.sendall(mesaj) #se trimite cheia criptata


if __name__ == "__main__":
    conexiune()  # instanta pentru nodul A
    conexiune()  # instanta pentru nodul B
    # ele se vor executa in serie, si de aceea avem nevoie ca B sa astepte ca A sa temrine conexiunea cu KM
