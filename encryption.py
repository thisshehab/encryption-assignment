#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
import math
import numpy as np


def cipher(text,s):
    result = "" 
    for i in range(len(text)):
     char = text[i]
# Encrypt uppercase characters
     if (char.isupper()):
        result += chr((ord(char) + s-65) % 26 + 65)
# Encrypt lowercase characters
     else:
      result += chr((ord(char) + s - 97) % 26 + 97)
    return result


def decriptcipher(text,s):
    result = "" 
    for i in range(len(text)):
     char = text[i]
# Encrypt uppercase characters
     if (char.isupper()):
      result += chr((ord(char) - s-65) % 26 + 65)
# Encrypt lowercase characters
     else:
      result += chr((ord(char) - s - 97) % 26 + 97)
    return result
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
def multiplicative_cypher(text,mode,key):
    char_dict={}
    cipher_message = ''
    for i in range(26):
         char_dict[chr(ord('a') + i)]=i
    key_list=list(char_dict.keys())
    inv_char_dict = dict(zip(char_dict.values(),char_dict.keys()))
    
    if mode == 'encrypt':
            for char in text:
                if char in key_list:
                    new_index=(char_dict[char]*key)%26
                    cipher_message=cipher_message+inv_char_dict[new_index]
                else:
                    cipher_message=cipher_message+char

            
            return cipher_message         
        
    if mode == 'decrypt':
        for char in text:
            if char in key_list:
                new_index=(char_dict[char]*key)%26
                cipher_message=cipher_message+inv_char_dict[new_index]
            else:
                cipher_message=cipher_message+char
    
    return cipher_message
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
alphabet= "abcdefghijklmnopqrstuvwxyz"
index = dict(zip(alphabet, range(len(alphabet))))
letter = dict(zip (range(len(alphabet)), alphabet))

def autokeyencrypt(message,key):
    cipher=''
    cipher=cipher + letter[((index[message[0]]+ index[key[0]]) %26)]
    for i in range(1,len(message)):
        cipher = cipher + letter[((index[message[i]]+index[message[i-1]])%26)]
    return cipher

def autokeydecrypt(message,key):
    plain=''
    plain=plain + letter[((index[message[0]]- index[key[0]]) %26)]
    for i in range(1,len(message)):
        plain = plain + letter[((index[message[i]]-index[message[i-1]])%26)]
        return plain
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
def doplaintext (plainText):
# append X if Two letters are being repeated
    for s in range(0,len(plainText)+1,2):
      if s<len(plainText)-1:
        if plainText[s]==plainText[s+1]:
           plainText=plainText[:s+1]+'x'+plainText[s+1:]

    if len(plainText)%2 != 0:
     plainText = plainText[:]+'x'
    return plainText
def key_gen ():
    key_5x5 = [['l','g','d','b','a'],
['q','m','h','e','c'],
['u','r','n',
'i'
,'f'], 
['x','v','s','o','k'],
['z','y','w','t','p']]
    return key_5x5

def encryptionplayfair(text):
    message = doplaintext(text)
    k = key_gen()
    message.replace("j","i")
    cipher=''
    for m in range(0, len(message)- 1, 2):
     for i in range(5):
      for j in range(5):
       if message[m] == k[i][j]:
        i1=i
        j1=j
       if message[m+1] == k[i][j]:
         i2=i
         j2=j
         if i1==i2:
          if j1 != 4:
           cipher=cipher+k[i1][j1+1]
          else:
           cipher=cipher+k[i1][0]
          if j2!=4:
            cipher=cipher+k[i2][j2+1]
          else:
           cipher=cipher+k[i2][0]
         if j1==j2:
          if i1 != 4:
           cipher=cipher+k[i1+1][j1]
         else:
          cipher=cipher+k[0][j1]
         if i2!=4:
          cipher=cipher+k[i2+1][j2]
         else:
          cipher=cipher+k[0][j2]
       if i1 != i2 and j1 != j2:
        cipher=cipher+k[i1][j2]
        cipher=cipher+k[i2][j1]
    return cipher

ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

def autokey():
    message = input('enter message:\n')
    key = input('enter your key:\n')
    mode = input('encrypt or decrypt\n')
    ## if len(key) < len(message):
        ## key = key[0:] + message[:100]
    #print(key)
    if mode == 'encrypt':
       cipher = encryptMessage(message, key)
    elif mode == 'decrypt':
       cipher = decryptMessage(message, key)
    #print(' message:',  (mode.title()))
    print(cipher)


def encryptMessage (messages, keys):  
    return cipherMessage(messages, keys, 'encrypt')

def decryptMessage(messages, keys):
    return cipherMessage(messages, keys, 'decrypt')


def cipherMessage (messages, keys, mode):
    cipher = []
    k_index = 0
    key = keys.upper()
    for i in messages:
        text = ALPHA.find(i.upper())
        if mode == 'encrypt':
             text += ALPHA.find(key[k_index])
             key += i.upper()  

        elif mode == 'decrypt':
             text -= ALPHA.find(key[k_index])
             key += ALPHA[text] 
        text %= len(ALPHA)
        k_index += 1
        cipher.append(ALPHA[text])
    return ''.join(cipher)


def egcd(a, b): 
  x,y, u,v = 0,1, 1,0
  while a != 0: 
    q, r = b//a, b%a 
    m, n = x-u*q, y-v*q 
    b,a, x,y, u,v = a,r, u,v, m,n 
  gcd = b 
  return gcd, x, y 
def modinv(a, m): 
  gcd, x, y = egcd(a, m) 
  if gcd != 1: 
    return None 
  else: 
    return x % m 
 
def encrypt(text, key): 
  return ''.join([ chr((( key[0]*(ord(t) - ord('A')) + key[1] ) % 26) + ord('A')) for t in text.upper().replace(' ', '') ]) 
def decrypt(cipher, key): 
  return ''.join([ chr((( modinv(key[0], 26)*(ord(c) - ord('A') - key[1])) % 26) + ord('A')) for c in cipher ]) 



def generateKey(string, key): 
  key = list(key) 
  if len(string) == len(key): 
    return(key) 
  else: 
    for i in range(len(string) -len(key)): 
      key.append(key[i % len(key)]) 
  return("" . join(key)) 
  
def encryptionVigenere(string, key): 
  encrypt_text = [] 
  for i in range(len(string)): 
    x = (ord(string[i]) +ord(key[i])) % 26
    x += ord('A') 
    encrypt_text.append(chr(x)) 
  return("" . join(encrypt_text)) 
def decryptionVigenere(encrypt_text, key): 
  orig_text = [] 
  for i in range(len(encrypt_text)): 
    x = (ord(encrypt_text[i]) -ord(key[i]) + 26) % 26
    x += ord('A') 
    orig_text.append(chr(x)) 
  return("" . join(orig_text)) 
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
def encrypthill(msg):
    # Replace spaces with nothing
    msg = msg.replace(" ", "")
    # Ask for keyword and get encryption matrix
    C = make_key()
    # Append zero if the messsage isn't divisble by 2
    len_check = len(msg) % 2 == 0
    if not len_check:
        msg += "0"
    # Populate message matrix
    P = create_matrix_of_integers_from_string(msg)
    # Calculate length of the message
    msg_len = int(len(msg) / 2)
    # Calculate P * C
    encrypted_msg = ""
    for i in range(msg_len):
        # Dot product
        row_0 = P[0][i] * C[0][0] + P[1][i] * C[0][1]
        # Modulate and add 65 to get back to the A-Z range in ascii
        integer = int(row_0 % 26 + 65)
        # Change back to chr type and add to text
        encrypted_msg += chr(integer)
        # Repeat for the second column
        row_1 = P[0][i] * C[1][0] + P[1][i] * C[1][1]
        integer = int(row_1 % 26 + 65)
        encrypted_msg += chr(integer)
    return encrypted_msg

def decrypthill(encrypted_msg):
    # Ask for keyword and get encryption matrix
    C = make_key()
    # Inverse matrix
    determinant = C[0][0] * C[1][1] - C[0][1] * C[1][0]
    determinant = determinant % 26
    multiplicative_inverse = find_multiplicative_inverse(determinant)
    C_inverse = C
    # Swap a <-> d
    C_inverse[0][0], C_inverse[1][1] = C_inverse[1, 1], C_inverse[0, 0]
    # Replace
    C[0][1] *= -1
    C[1][0] *= -1
    for row in range(2):
        for column in range(2):
            C_inverse[row][column] *= multiplicative_inverse
            C_inverse[row][column] = C_inverse[row][column] % 26

    P = create_matrix_of_integers_from_string(encrypted_msg)
    msg_len = int(len(encrypted_msg) / 2)
    decrypted_msg = ""
    for i in range(msg_len):
        # Dot product
        column_0 = P[0][i] * C_inverse[0][0] + P[1][i] * C_inverse[0][1]
        # Modulate and add 65 to get back to the A-Z range in ascii
        integer = int(column_0 % 26 + 65)
        # Change back to chr type and add to text
        decrypted_msg += chr(integer)
        # Repeat for the second column
        column_1 = P[0][i] * C_inverse[1][0] + P[1][i] * C_inverse[1][1]
        integer = int(column_1 % 26 + 65)
        decrypted_msg += chr(integer)
    if decrypted_msg[-1] == "0":
        decrypted_msg = decrypted_msg[:-1]
    return decrypted_msg

def find_multiplicative_inverse(determinant):
    multiplicative_inverse = -1
    for i in range(26):
        inverse = determinant * i
        if inverse % 26 == 1:
            multiplicative_inverse = i
            break
    return multiplicative_inverse


def make_key():
     # Make sure cipher determinant is relatively prime to 26 and only a/A - z/Z are given
    determinant = 0
    C = None
    while True:
        cipher = input("Input 4 letter cipher: ")
        C = create_matrix_of_integers_from_string(cipher)
        determinant = C[0][0] * C[1][1] - C[0][1] * C[1][0]
        determinant = determinant % 26
        inverse_element = find_multiplicative_inverse(determinant)
        if inverse_element == -1:
            print("Determinant is not relatively prime to 26, uninvertible key")
        elif np.amax(C) > 26 and np.amin(C) < 0:
            print("Only a-z characters are accepted")
            print(np.amax(C), np.amin(C))
        else:
            break
    return C

def create_matrix_of_integers_from_string(string):
    # Map string to a list of integers a/A <-> 0, b/B <-> 1 ... z/Z <-> 25
    integers = [chr_to_int(c) for c in string]
    length = len(integers)
    M = np.zeros((2, int(length / 2)), dtype=np.int32)
    iterator = 0
    for column in range(int(length / 2)):
        for row in range(2):
            M[row][column] = integers[iterator]
            iterator += 1
    return M

def chr_to_int(char):
    # Uppercase the char to get into range 65-90 in ascii table
    char = char.upper()
    # Cast chr to int and subtract 65 to get 0-25
    integer = ord(char) - 65
    return integer

    encrypted_msg = encrypt(msg)
    print(encrypted_msg)
    decrypted_msg = decrypt(encrypted_msg)
    print(decrypted_msg)

def hillcipher():
    print("hill Encryption >>>>>>>>>>>>>>>>>>>>>>>>>>>")
    print("1)encrypt")
    print("2)decrypt")
    choice= input("choice")
    if(choice=='1'):
        thetext = input("Enter the Text:")
        encrypted_msg = encrypthill(thetext)
        print(encrypted_msg)
    elif(choice=='2'):
        thetext = input("Enter the Text:")
        encrypted_msg = decrypthill(thetext)
        print(encrypted_msg)

def Vigenere():
    print("Vigenere Encryption >>>>>>>>>>>>>>>>>>>>>>>>>>>")
    print("1)encrypt")
    print("2)decrypt")
    choice= input("choice")
    if(choice=='1'):
        keyword = input("Enter the keyword: ")
        thetext = input("Enter the Text:")
        key = generateKey(thetext, keyword)
        encrypt_text = encryptionVigenere(thetext,key)
        print("Encrypted message:", encrypt_text)
    elif(choice=='2'):
        keyword = input("Enter the keyword: ")
        thetext = input("Enter the Text:")
        key = generateKey(thetext, keyword)
        encrypt_text = decryptionVigenere(thetext,key)
        print("Decrypted message:", encrypt_text) 

def playfiar():
    print("flayfiar cipher >>>>>>>>>>>>>>>>>>>>>>>>>>>")
    print("1)encrypt")
    print("2)decrypt")
    choice= input("choice")
    if(choice=='1'):
        thetext = input("Enter the Text:")
        print(encryptionplayfair(thetext))
    elif(choice=='2'):
        thetext = input("Enter the Text:")
        print(autokeydecrypt(thetext,4))



def addtiveciper():
    print("addtive cipher >>>>>>>>>>>>>>>>>>>>>>>>>>>")
    print("1)encrypt")
    print("2)decrypt")
    choice= input("choice")
    if(choice=='1'):
        thetext = input("Enter the Text:")
        print(cipher(thetext,4))
    elif(choice=='2'):
        thetext = input("Enter the Text:")
        print(decriptcipher(thetext,4))

def mlticiper():
    print("multi cipher >>>>>>>>>>>>>>>>>>>>>>>>>>>")
    print("1)encrypt")
    print("2)decrypt")
    choice= input("choice")
    if(choice=='1'):
        thetext = input("Enter the Text:")
        print(multiplicative_cypher(thetext,"encrypt",4))
    elif(choice=='2'):
        thetext = input("Enter the Text:")
        print(multiplicative_cypher(thetext,"decrypt",4))

def offinsipher():
    key = [7, 20] 
    print("offin cipher >>>>>>>>>>>>>>>>>>>>>>>>>>>")
    print("1)encrypt")
    print("2)decrypt")
    choice= input("choice")
    if(choice=='1'):
        thetext = input("Enter the Text:")
        enc_text = encrypt(thetext, key) 
        print('Encrypted Text: {}'.format(enc_text)) 
    elif(choice=='2'):
        thetext = input("Enter the Text:")
        print('Decrypted Text: {}'.format(decrypt(thetext, key) )) 
    


print("Enter the type of encryption:")
print("1)Addtive cipher Encrp")
print("2)Multiciper Encryption")
print("3)Auto Encryption")
print("4)Play Encrption")
print("5)Offin Encryption")
print("6)Vigenere Encryption")
print("7)Hill Encryption")
choice = input("Enter your choice: ")
if(choice=='1'):
    addtiveciper()
elif(choice=='2'):
    mlticiper()
elif(choice=='3'):
    autokey()
elif(choice=='4'):
    playfiar()
elif(choice=='5'):
    offinsipher()
elif(choice=='6'):
    Vigenere()
# print(cipher("shehab",4))