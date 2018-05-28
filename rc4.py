# coding: UTF8

'''
    Trabalho 1 - Criptografia          
    SSC0747 - Engenharia de Segurança  
    Giovani Ortolani Barbosa  8936648   
    Gustavo Lima Lopes - 8910142
    Luciano Augusto Campagnoli da Silva - 9313367   
    
    RC4 + ROT encypytion and decyrption

    Read/write functions refer to:
        https://github.com/g2jun/RC4-Python                
'''

import sys

def readTextFile(file):
    '''
    Reads text file, transforms the characters read into int representation
    and returns them as a list 
    '''

    byte_text = list()

    try:
        with open(file, "r") as f:  
            text = f.read()
            for byte in text:
                byte_text.append(ord(byte)) # transforms into int representation
        return byte_text
    except IOError:
            print("Could not open file.")

def readHexFile(file):
    '''
    Reads file containing the hex representation of characters, converts the characters read into int representation
    and return them as a list 
    '''

    byte_text = list()

    try:
        with open(file, "r") as f:  
            text = f.read()
            for i in range(0, len(text), 2):
                byte = text[i:i+2] # reads one hex at a time, each hex has 2 digits in the file
                byte_text.append(int('0X' + byte, 16))
        return byte_text
    except IOError:
            print("Could not open file.")

def writeTextFile(file, text):
    '''
    Converts text characters represented as int to char and writes to file 
    '''

    _text = ""

    try:
        with open(file, "w") as f: 
            for byte in text:
                _text += chr(byte)  # converts int into char representation 
            f.write(_text)
    except IOError:
            print("Could not open file.")

def writeHexFile(file, text):
    '''
    Converts text characters represented as int to hex and writes to file
    '''

    try:
        with open(file, "w") as f: 
            for byte in text:
                hexByte = '0' + hex(byte)[2:]
                #print(hex(byte), hex(byte)[2:], hexByte, hexByte[-2:].upper())
                f.write(hexByte[-2:].upper())
    except IOError:
            print("Could not open file.")

def KSA(key):
    '''
    Key-scheduling algorithm used as the first step of RC4
    '''

    S = list(range(256))

    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    return S

def PRGA(S, text):
    '''
    Pseudo-Random Generating Algorithm used as the second step of RC4
    '''

    converted_text = list()

    i = j = 0
    for text_char in text:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        converted_text_char = S[(S[i] + S[j]) % 256] ^ text_char   # bitwise XOR
        converted_text.append(converted_text_char)

    return converted_text

def RC4(key, text):
    '''
    Performs RC4 encrpytion and decryption
    Takes a key and a text (plain/cipher) and returns them encrypted or decrypted
    '''

    S = KSA(key)

    converted_text = PRGA(S, text)

    return converted_text

def ROT(n, text):
    '''
    Performs ROT encrpytion and decryption
    Takes a key and a text (plain/cipher) and returns them encrypted or decrypted
    '''

    for i in range(len(text)):
        char = text[i]
        if char >= ord('a') and char <= ord('z'):
            text[i] = ((char - 97 + n) % 26) + 97
        elif char >= ord('A') and char <= ord('Z'):
            text[i] = ((char - 65 + n) % 26) + 65

    return text

def encrypt(key, plain):
    '''
    Generic encryption function with RC4 and ROT2 encryption
    '''

    text = ROT(2, plain)
    return RC4(key, text)

def decrypt(key, cipher):
    '''
    Generic encryption function with RC4 and ROT2 decryption
    '''

    text = RC4(key, cipher)
    return ROT(-2, text)

def main():
    '''
    Handles input arguments 
    '''
    if len(sys.argv) == 6:
        if sys.argv[2] == 'C':
            key = readTextFile(sys.argv[3])
            plain = readTextFile(sys.argv[4])
            cipher_name = sys.argv[5]
            cipher_text = encrypt(key, plain)
            writeHexFile(cipher_name, cipher_text)
        elif sys.argv[2] == 'D':
            key = readTextFile(sys.argv[3])
            cipher = readHexFile(sys.argv[4])
            plain_name = sys.argv[5]
            plain_text = decrypt(key, cipher)
            writeTextFile(plain_name, plain_text)
        else:
            print("Argumento inválido. C - criptografia, D - descriptografia.")
    elif len(sys.argv) == 4 or len(sys.argv) == 5:
        if sys.argv[2] == 'K':
            pass
        else:
            print("Argumento inválido. K - gerar chave.")
    else:
        print(
            "Usage:\n"
            "python3 rc4.py 1 [C/D] <key_file.txt> [plain_text.txt/cipher_text.txt] [cipher_text.txt/plain_text.txt]\n"
            "or\n"
            "python3 rc4.py 1 K <key_file.txt> [seed (optional)]"
        )

if __name__ == '__main__':
    main()
