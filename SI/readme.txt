Tema a fost lucrata si testata(functionala) pe Windows 10 64-bit, cu intrepretator Python3.8 in Pycharm, dar functional si din linia de comanda:
Se executa in aceasta ordine comenzile, fiecare intr-un terminal diferit(Win):
python Nod_B.py
python Nod_A.py
python Nod_KM.py

Pe Linux in loc de python se va folosi python3

Dupa aceea se va introduce in consola lui A modul de operare dorit (ECB,ecb,OFB,ofb)
Textul folosit pentru testare se afla in fisierul test.txt, din acelasi director

Am utilizat biblioteca Crypto pentru AES, pentru care este posibil necesar si rularea comenzii "pip install pycryptodome" in prealabil
Rezolvarea urmeaza pasii din cerinte (care descriu precis ca ce pasi sunt urmati) si de asemenea prin comentariile din cod
Pentru implementarea modurilor ECB si OFB am urmarit diagramele ce descriu aceste moduri, prezente pe Wikipedia