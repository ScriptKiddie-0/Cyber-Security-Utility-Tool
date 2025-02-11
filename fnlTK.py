import tkinter as tk
from tkinter import simpledialog, messagebox
from tkinter.scrolledtext import ScrolledText
from PIL import Image, ImageTk
import cv2
import numpy as np
import os
import socket
import random
import string
import requests
import re
import concurrent.futures
import argparse

class Application(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Utility Tool")
        self.geometry("400x400")

        self.create_widgets()

    def create_widgets(self):
        self.function_buttons = []
        functions = [
            ("Website Lookup", self.func1),
            ("Generate Password", self.func2),
            ("Port Scanner", self.func3),
            ("Password Guesser", self.func4),
            ("Encryption", self.func5),
            ("Hash Cracker", self.func6),
            ("Modify Image", self.func7),
            ("Quit", self.quit)
        ]

        for idx, (text, command) in enumerate(functions):
            button = tk.Button(self, text=text, command=command)
            button.grid(row=idx, column=0, padx=10, pady=5, sticky="ew")
            self.function_buttons.append(button)

    def func1(self):
        domain = simpledialog.askstring("Domain Lookup", "Enter the domain name:")
        if domain:
            response = self.website_lookup(domain)
            messagebox.showinfo("Domain Lookup Result", response)

    def website_lookup(self, domain):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("whois.iana.org", 43))
            s.send(f"{domain}\r\n".encode())
            response = s.recv(4096).decode()
            s.close()
            return response
        except Exception as e:
            return str(e)

    def func2(self):
        password = self.generate_password()
        messagebox.showinfo("Generated Password", f"Generated password: {password}")

    def generate_password(self, length=10):
        alphabet = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(alphabet) for _ in range(length))
        return password

    def func3(self):
        target = simpledialog.askstring("Port Scanner", "What website to scan?")
        if target:
            response = self.port_scanner(target)
            messagebox.showinfo("Port Scanner Result", response)

    def port_scanner(self, target):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = []
        for port in range(1, 5):
            if s.connect_ex((target, port)) == 0:
                result.append(f"Port {port} is open")
            else:
                result.append(f"Port {port} is closed")
        s.close()
        return '\n'.join(result)

    def func4(self):
        password = simpledialog.askstring("Password Guesser", "Enter the password:")
        if password:
            self.password_guesser(password)

    def password_guesser(self, password):
        letters = list(string.ascii_lowercase)
        guess = ""
        while guess != password:
            guess = ""
            for _ in password:
                guess_letter = random.choice(letters)
                guess = guess_letter + guess
            print(guess)
        messagebox.showinfo("Password Guesser", "Password guessed!")

    def func5(self):
        message = simpledialog.askstring("Encryption", "Enter text to be encrypted:")
        if message:
            key = 3
            encrypted_message = self.encrypt(message, key)
            decrypted_message = self.caesar_decrypt(encrypted_message, key)
            messagebox.showinfo("Encryption Result", f"Encrypted message: {encrypted_message}\nDecrypted message: {decrypted_message}")

    def encrypt(self, message, key):
        shift = key % 26
        cipher = str.maketrans(string.ascii_lowercase, string.ascii_lowercase[shift:] + string.ascii_lowercase[:shift])
        encrypted_message = message.lower().translate(cipher)
        return encrypted_message

    def caesar_decrypt(self, encrypted_message, key):
        shift = 26 - (key % 26)
        cipher = str.maketrans(string.ascii_lowercase, string.ascii_lowercase[shift:] + string.ascii_lowercase[:shift])
        decrypted_message = encrypted_message.translate(cipher)
        return decrypted_message

    def func6(self):
        # Create a new window for the hash cracker function
        self.hash_cracker_window = tk.Toplevel(self)
        self.hash_cracker_window.title("Hash Cracker")
        self.hash_cracker_window.geometry("400x200")

        # Create labels and entry for hash input
        tk.Label(self.hash_cracker_window, text="Enter Hash:").grid(row=0, column=0, padx=10, pady=5)
        self.hash_entry = tk.Entry(self.hash_cracker_window)
        self.hash_entry.grid(row=0, column=1, padx=10, pady=5)

        # Create a button to initiate the cracking process
        tk.Button(self.hash_cracker_window, text="Crack Hash", command=self.crack_hash).grid(row=1, column=0, columnspan=2, padx=10, pady=5)

    def crack_hash(self):
        hash_value = self.hash_entry.get()
        if hash_value:
            result = self.crack(hash_value)
            messagebox.showinfo("Hash Cracker Result", result)
        else:
            messagebox.showerror("Error", "Please enter a hash value.")

    def crack(self, hash_value):
        parser = argparse.ArgumentParser()
        parser.add_argument('-s', help='hash', dest='hash')
        parser.add_argument('-f', help='file containing hashes', dest='file')
        parser.add_argument('-d', help='directory containing hashes', dest='dir')
        parser.add_argument('-t', help='number of threads', dest='threads', type=int)
        args = parser.parse_args()

        # Colors and shit like that
        end = '\033[0m'
        red = '\033[91m'
        green = '\033[92m'
        white = '\033[97m'
        dgreen = '\033[32m'
        yellow = '\033[93m'
        back = '\033[7;91m'
        run = '\033[97m[~]\033[0m'
        que = '\033[94m[?]\033[0m'
        bad = '\033[91m[-]\033[0m'
        info = '\033[93m[!]\033[0m'
        good = '\033[92m[+]\033[0m'

        cwd = os.getcwd()
        directory = args.dir
        file = args.file
        thread_count = args.threads or 4

        if directory:
            if directory[-1] == '/':
                directory = directory[:-1]

        def alpha(hashvalue, hashtype):
            return False

        def beta(hashvalue, hashtype):
            response = requests.get('https://hashtoolkit.com/reverse-hash/?hash=' + hashvalue).text
            match = re.search(r'/generate-hash/\?text=(.*?)"', response)
            if match:
                return match.group(1)
            else:
                return False

        def gamma(hashvalue, hashtype):
            response = requests.get('https://www.nitrxgen.net/md5db/' + hashvalue, verify=False).text
            if response:
                return response
            else:
                return False

        def delta(hashvalue, hashtype):
            return False

        def theta(hashvalue, hashtype):
            response = requests.get('https://md5decrypt.net/Api/api.php?hash=%s&hash_type=%s&email=deanna_abshire@proxymail.eu&code=1152464b80a61728' % (hashvalue, hashtype)).text
            if len(response) != 0:
                return response
            else:
                return False

        print ('''_  _ ____ ____ _  _    ___  _  _ ____ ___ ____ ____
    |__| |__| [__  |__|    |__] |  | [__   |  |___ |__/
    |  | |  | ___] |  |    |__] |__| ___]  |  |___ |  \  ''')

        md5 = [gamma, alpha, beta, theta, delta]
        sha1 = [alpha, beta, theta, delta]
        sha256 = [alpha, beta, theta]
        sha384 = [alpha, beta, theta]
        sha512 = [alpha, beta, theta]

        def crack(hashvalue):
            result = False
            if len(hashvalue) == 32:
                if not file:
                    print ('%s Hash function : MD5' % info)
                for api in md5:
                    r = api(hashvalue, 'md5')
                    if r:
                        return r
            elif len(hashvalue) == 40:
                if not file:
                    print ('%s Hash function : SHA1' % info)
                for api in sha1:
                    r = api(hashvalue, 'sha1')
                    if r:
                        return r
            elif len(hashvalue) == 64:
                if not file:
                    print ('%s Hash function : SHA-256' % info)
                for api in sha256:
                    r = api(hashvalue, 'sha256')
                    if r:
                        return r
            elif len(hashvalue) == 96:
                if not file:
                    print ('%s Hash function : SHA-384' % info)
                for api in sha384:
                    r = api(hashvalue, 'sha384')
                    if r:
                        return r
            elif len(hashvalue) == 128:
                if not file:
                    print ('%s Hash function : SHA-512' % info)
                for api in sha512:
                    r = api(hashvalue, 'sha512')
                    if r:
                        return r
            else:
                if not file:
                    print ('%s This hash type is not supported.' % bad)
                    quit()
                else:
                    return False

        result = {}

        def threaded(hashvalue):
            resp = crack(hashvalue)
            if resp:
                print (hashvalue + ' : ' + resp)
                result[hashvalue] = resp

        def grepper(directory):
            os.system('''grep -Pr "[a-f0-9]{128}|[a-f0-9]{96}|[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32}" %s --exclude=\*.{png,jpg,jpeg,mp3,mp4,zip,gz} |
                grep -Po "[a-f0-9]{128}|[a-f0-9]{96}|[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32}" >> %s/%s.txt''' % (directory, cwd, directory.split('/')[-1]))
            print ('%s Results saved in %s.txt' % (info, directory.split('/')[-1]))

        def miner(file):
            lines = []
            found = set()
            with open(file, 'r') as f:
                for line in f:
                    lines.append(line.strip('\n'))
            for line in lines:
                matches = re.findall(r'[a-f0-9]{128}|[a-f0-9]{96}|[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32}', line)
                if matches:
                    for match in matches:
                        found.add(match)
            print ('%s Hashes found: %i' % (info, len(found)))
            threadpool = concurrent.futures.ThreadPoolExecutor(max_workers=thread_count)
            futures = (threadpool.submit(threaded, hashvalue) for hashvalue in found)
            for i, _ in enumerate(concurrent.futures.as_completed(futures)):
                if i + 1 == len(found) or (i + 1) % thread_count == 0:
                    print('%s Progress: %i/%i' % (info, i + 1, len(found)), end='\r')

        def single(args):
            result = crack(args.hash)
            if result:
                print (result)
            else:
                print ('%s Hash was not found in any database.' % bad)

        if directory:
            try:
                grepper(directory)
            except KeyboardInterrupt:
                pass

        elif file:
            try:
                miner(file)
            except KeyboardInterrupt:
                pass
            with open('cracked-%s' % file.split('/')[-1], 'w+') as f:
                for hashvalue, cracked in result.items():
                    f.write(hashvalue + ':' + cracked + '\n')
            print ('%s Results saved in cracked-%s' % (info, file.split('/')[-1]))

        elif args.hash:
            single(args)

    def func7(self):
        self.modify_image()

    def modify_image(self):
        image_location = simpledialog.askstring("Modify Image", "Enter image location:")
        if image_location:
            image = cv2.imread(image_location)
            brightness = 10
            contrast = 2.3
            modified_image = cv2.addWeighted(image, contrast, np.zeros(image.shape, image.dtype), 0, brightness)
            cv2.imwrite('modified_image.jpg', modified_image)
            cv2.imshow("Modified Image", modified_image)
            cv2.waitKey(0)
            cv2.destroyAllWindows()

if __name__ == "__main__":
    app = Application()
    app.mainloop()
