# combined_script.py


import random
import string
import socket
from random import *
import re
import os
import requests
import argparse
import concurrent.futures
import cv2 
import matplotlib.pyplot as plt 
import numpy as np 


def func1():
    #import socket
    def website_lookup(domain: str):
   
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("whois.iana.org", 43))
        s.send(f"{domain}\r\n".encode())
        response = s.recv(4096).decode()
        s.close()
    
    return response
    domain = input("Enter the domain name: ")
    print(website_lookup(domain))    


def func2():
    #import random
    #import string

    def generate_password(length:int=10):
    
        alphabet = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(alphabet) for i in range(length))
    
        return password
    print(f"Generated password: {generate_password()}")    


def func3():
    #import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    target = input('What website to scan?: ')
    def pscan(port):
        try:
            con = s.connect((target,port))
            return True
        except:
            return False


    for x in range(1,5):
        if pscan(x):
            print('Port',x,'is open')
        else: 
            print("port" ,x, "is closed")    	


def func4():
    #from random import *
    guess = ""
    password = input("Password: ")
    letters = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"]
    while (guess != password):
        guess = ""
        for letter in password:
            guessletter = letters[randint(0, 25)]
            guess = str(guessletter) + str(guess)
        print(guess)
    print("Password guessed!")
    input("")

    

def func5():
    #import string

    def caesar_encrypt(message, key):

        shift = key % 26
        cipher = str.maketrans (string.ascii_lowercase, string.ascii_lowercase [shift:] + string.ascii_lowercase[:shift])
        encrypted_message = message.lower().translate (cipher)
        return encrypted_message

    def caesar_decrypt(encrypted_message, key):

         shift = 26 - (key % 26)
         cipher = str.maketrans (string.ascii_lowercase, string.ascii_lowercase [shift:] + string.ascii_lowercase[:shift])
         message = encrypted_message.translate(cipher)
         return message

    message = input('Enter text to be encrypted:')

    key = 3

    encrypted_message = caesar_encrypt(message, key) 
    print(f'Encrypted message: {encrypted_message}')

    decrypted_message = caesar_decrypt(encrypted_message, key) 
    print(f'Decrypted message: {decrypted_message}')

    
    

def func6():
    #!/usr/bin/env python3

    #import re
    #import os
    #import requests
    #import argparse
    #import concurrent.futures

    parser = argparse.ArgumentParser()
    parser.add_argument('-s', help='hash', dest='hash')
    parser.add_argument('-f', help='file containing hashes', dest='file')
    parser.add_argument('-d', help='directory containing hashes', dest='dir')
    parser.add_argument('-t', help='number of threads', dest='threads', type=int)
    args = parser.parse_args()

    #Colors and shit like that
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
        #data = {'auth':'8272hgt', 'hash':hashvalue, 'string':'','Submit':'Submit'}
        #response = requests.post('http://hashcrack.com/index.php' , data).text
        #match = re.search(r'<span class=hervorheb2>(.*?)</span></div></TD>', response)
        #if match:
        #    return match.group(1)
        #else:
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

            

def func7():
    #Import the necessary libraries 
    #import cv2 
    #import matplotlib.pyplot as plt 
    #import numpy as np 

    # Load the image 
    image = cv2.imread(input("enter image location:")) 

    #Plot the original image 
    plt.subplot(1, 2, 1) 
    plt.title("Original") 
    plt.imshow(image) 

    # Adjust the brightness and contrast 
    # Adjusts the brightness by adding 10 to each pixel value 
    brightness = 10
    # Adjusts the contrast by scaling the pixel values by 2.3 
    contrast = 2.3
    image2 = cv2.addWeighted(image, contrast, np.zeros(image.shape, image.dtype), 0, brightness) 

    #Save the image 
    cv2.imwrite('modified_image.jpg', image2) 
    #Plot the contrast image 
    plt.subplot(1, 2, 2) 
    plt.title("Brightness & contrast") 
    plt.imshow(image2) 
    plt.show()

# Main logic



if __name__ == "__main__":
       while True:
       
            print("Select a function to run:")
            print("1. website_lookup")
            print("2. generate_password")
            print("3. message encryptor")
            print("4. message decryptor")
            print("5. port scanner")
            print("6. quit")
       
            choice = input("Enter your choice : ")

            if choice == '1':
                func1()
       
            elif choice == '2':
                func2()
       
            elif choice == '3':
                func3()
        
            elif choice == '4': 
                func4()
                
            elif choice == '5':
                func5()
            
            elif choice == '6':
                func6()
                
            elif choice == '7':
                func7()    
            else:
                print("Invalid choice.")
   
if __name__ == "__main__":
    main()
  
   
   
