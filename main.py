import re
import binascii
from base64 import b64encode, b64decode
import random


class aes:
    def __init__(self, initialkey):
        self.initialkey = initialkey

        # S-box for substitution operation
        self.sbox = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]

        # Inverted S-box
        self.rsbox = [
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]

        self.rcon = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

    def StateMatrix(self, state):
        # Formats a State string to a formatted list.

        new_state = []
        split = re.findall('.' * 2, state)
        for x in range(4):
            new_state.append(split[0:4][x])
            new_state.append(split[4:8][x])
            new_state.append(split[8:12][x])
            new_state.append(split[12:16][x])
        return new_state

    def RevertStateMatrix(self, state):
        # Reverts State Matrix from a list to a string

        columns = [state[x:x + 4] for x in range(0, 16, 4)]
        return ''.join(''.join([columns[0][x], columns[1][x], columns[2][x], columns[3][x]]) for x in range(4))


    def encryption(self, data, ifdecrypt, numrounds):
        state = self.StateMatrix(data)
        expanded_key = self.key_handler(self.initialkey, ifdecrypt)

        #preforming the initial round w[0,3]
        if ifdecrypt:
            state = self.AddRoundKey(re.findall('.' * 2, data), expanded_key[10])
        else: state = self.AddRoundKey(state, expanded_key[0])

        #round 1-10
        for i in range(numrounds):
            state = self.SubBytes(state, ifdecrypt)
            state = self.ShiftRows(state, ifdecrypt)
            if ifdecrypt:
                state = self.AddRoundKey(state, expanded_key[-(i + 2)])
            else:
                state = self.AddRoundKey(state, expanded_key[i+1])

        if ifdecrypt:
            return ''.join(state)
        else:
            return self.RevertStateMatrix(state)


    def SubBytes(self, state, isInv):
        # Transforms the State Matrix using  byte S-box
        if not isInv:
            return ['%02x' % self.sbox[int(state[x], 16)] for x in range(16)]
        elif isInv:
            return ['%02x' % self.rsbox[int(state[x], 16)] for x in range(16)]

    def ShiftRows(self, state, isInv):
        # Changes the State by cyclically shifting the last
        # three rows of the State by different offsets.
        offset = 0
        if isInv: state = re.findall('.' * 2, self.RevertStateMatrix(state))
        for x in range(0, 16, 4):
            state[x:x + 4] = state[x:x + 4][offset:] + state[x:x + 4][:offset]
            if not isInv:
                offset += 1
            elif isInv:
                offset -= 1
        if isInv: return self.StateMatrix(''.join(state))
        return state

    def AddRoundKey(self, state, key):
        #Round Key is added to the State using an XOR operation.

        return ['%02x' % (int(state[x], 16) ^ int(key[x], 16)) for x in range(16)]


    def key_handler(self, key, isInv):
        # Return the expanded key
        if not isInv: return self.ExpandKey(key)
        # Return the inverse expanded key
        if isInv: return [re.findall('.' * 2, self.RevertStateMatrix(x)) for x in self.ExpandKey(key)]


    def ExpandKey(self, key):
        #expands the key from w[0,3] to w[0,43]
        w = ['%08x' % int(x, 16) for x in re.findall('.' * 8, key)]

        i = 4
        while i < 44:
            temp = w[i - 1]
            if i % 4 == 0:
                temp = '%08x' % (self.SubWord(self.RotWord(temp)) ^ (self.rcon[i // 4] << 24))
            w.append('%08x' % (int(w[i - 4], 16) ^ int(temp, 16)))
            i += 1

        return [self.StateMatrix(''.join(w[x:x + 4])) for x in range(0, len(w), 4)]


    def RotWord(self,word):
        #rotates word for key expansion
        return int(word[2:] + word[0:2], 16)


    def SubWord(self, byte):
        #using sub box on a word for key expansion
        return ((self.sbox[(byte >> 24 & 0xff)] << 24) + (self.sbox[(byte >> 16 & 0xff)] << 16) +
                (self.sbox[(byte >> 8 & 0xff)] << 8) + self.sbox[byte & 0xff])


'''====================================================================================================='''



#100 ciphertexts from the give file
def partA100ciphers():
    print('=====================================================================================================')
    fileinput = open('AES-pair.txt', 'r')
    fileouta1 = open('out_a1.txt', 'w')
    Lines = fileinput.readlines()
    i = 0
    for line in Lines:
        i = i + 1
        tuple = line.split()

        #encrypts the data (tuple[1]) using the key (tuple[0])
        AES = aes(tuple[0])
        ciphertext = AES.encryption(tuple[1], False, 10)
        # hex -> base64
        b64 = b64encode(bytes.fromhex(ciphertext)).decode()
        print(ciphertext + ' , ' + b64)

        fileouta1.writelines('base64 ciphertext #' + str(i) + ' : ' +  b64+'\n')
    fileouta1.close()
    fileinput.close()


#avalanche affect
def partAavalanche():
    print('=====================================================================================================')
    key = 'fde8f7a9b86c3bff07c0d39d04605edd'
    AES = aes(key)
    stringerror = 'Hello everybody!'
    stringerrorhex = binascii.hexlify(stringerror.encode()).decode()
    string = 'hello everybody!'
    stringhex = binascii.hexlify(string.encode()).decode()
    fileouta2 = open('out_a2.txt', 'w')
    fileouta2.writelines('|    round num      |  amount of differing bits |\n')
    fileouta2.writelines('|                   |                           |\n')

    for i in range(11):
        ciphertexterror = AES.encryption(stringerrorhex, False, i)
        ciphertext = AES.encryption(stringhex, False, i)
        #calculates the amount of different bits
        binarydifference = bin((int(ciphertexterror, 16) ^ int(ciphertext, 16)))
        text = "|number of rounds " + str(i) + " | " + str(binarydifference.count('1')) + ' differing bits          |'
        print(ciphertexterror + ' , ' + ciphertext)
        print(text)
        fileouta2.writelines(text + '\n')

    fileouta2.close()

#encryption using the CFB operation mode
def CFBencrypt(IV, key, plaintext):
    AES = aes(key)
    shiftregister = IV
    temp = AES.encryption(shiftregister, False, 10)[0:16]
    ciphertext = []
    ciphertext.append(format((int(temp, 16) ^ int(plaintext[0], 16)), 'x').rjust(16, '0'))
    for i in range(1,len(plaintext)):
        shiftregister = shiftregister[16:32] + ciphertext[i-1]
        temp = AES.encryption(shiftregister, False, 10)[0:16]
        ciphertext.append(format((int(temp, 16) ^ int(plaintext[i], 16)), 'x').rjust(16, '0'))
    return ciphertext

#decryption using the CFB operation mod
def CFBdecrypt(IV, key, ciphertext):
    AES = aes(key)
    shiftregister = IV
    temp = AES.encryption(shiftregister, False, 10)[0:16]
    plaintext = []
    plaintext.append(format((int(temp, 16) ^ int(ciphertext[0], 16)), 'x').rjust(16, '0'))
    for i in range(1,len(ciphertext)):
        shiftregister = shiftregister[16:32] + ciphertext[i-1]
        temp = AES.encryption(shiftregister, False, 10)[0:16]
        plaintext.append(format((int(temp, 16) ^ int(ciphertext[i], 16)), 'x').rjust(16, '0'))
    return plaintext

#preforms partB for CFB operation mode with and without error
def partBCFB(fileoutb1, fileoutb2):
    print('=====================================================================================================')
    keystring = "IbrahimMuharibXY"
    keyhex = binascii.hexlify(keystring.encode()).decode()
    # IV = ''.join(random.choice('0123456789abcdef') for n in range(32)) #fully random IV
    IV = 'ef390b9a28e188f4c537dda241c845dd'
    messagestring = 'This Is The Sample Test For IbrahimMuharibXY Python PA!!'
    messagestring = messagestring.replace(' ', '')  # remove spaces
    messagehex = binascii.hexlify(messagestring.encode()).decode()
    blocksize = 16
    splitedmessage = [messagehex[i:i + blocksize] for i in range(0, len(messagehex), blocksize)]
    splitedmessage[len(splitedmessage) - 1] = splitedmessage[len(splitedmessage) - 1].ljust(16,'0')  # zero filling the last block
    print(splitedmessage)
    CFBencryption = CFBencrypt(IV, keyhex,splitedmessage)
    print(CFBencryption)
    CFBencryptionstring = ''.join(CFBencryption)
    # hex -> base64
    CFBencryptionb64 = b64encode(bytes.fromhex(CFBencryptionstring)).decode()
    #print(CFBencryptionstring + ' , ' + CFBencryptionb64)
    CFBdecryption = CFBdecrypt(IV, keyhex, CFBencryption)
    print(CFBdecryption)

    #outputing results to outb1 and outb2
    fileoutb1.writelines('IV for both modes is = ' + IV)
    fileoutb1.writelines('\nThe key for both modes is = ' + keyhex)
    fileoutb1.writelines('\nmessage in ASCII = ' + messagestring)
    fileoutb1.writelines('\nmessage converted into hex = ' + messagehex)
    fileoutb1.writelines('\n==================================================================================================================================================================================================')
    fileoutb1.writelines('\nciphertext "using mode CFB" = ' + CFBencryptionstring + ' , ' + CFBencryptionb64)

    fileoutb2.writelines('original meassge                         = ' + messagehex)
    fileoutb2.writelines('\n==================================================================================================================================================================================================')
    fileoutb2.writelines('\nusing mode CFB')
    fileoutb2.writelines('\noriginal encrypted message               = ' + ' , '.join(CFBencryption))
    CFBencryption[0] = format(int(CFBencryption[0], 16)>>1,'x') #adding an error
    fileoutb2.writelines('\nencrypted message after adding the error = ' + ' , '.join(CFBencryption))
    fileoutb2.writelines('\n\ndecryption of the orignal message        = ' + ' , '.join(CFBdecryption))
    CFBerrordecrypted = CFBdecrypt(IV, keyhex, CFBencryption)
    fileoutb2.writelines('\ndecryption of the message with error     = ' + ' , '.join(CFBerrordecrypted))
    fileoutb2.writelines('\n==================================================================================================================================================================================================')
    fileoutb2.writelines('\nresulting in the error propagating in the first 3 plaintext blocks,\nthe orignal block and 2 blocks after since it takes 2 shifts of the shift register to remove C1 from it')
    fileoutb2.writelines('\n==================================================================================================================================================================================================')


def OFB(IV, key, data):
    AES = aes(key)
    tempdata = IV
    encryptresults = []
    resultedtext = []

    for i in range(len(data)):
        tempdata = AES.encryption(tempdata, False, 10).ljust(32, '0')
        encryptresults.append(tempdata)
        resultedtext.append(format((int(data[i], 16) ^ int(encryptresults[i], 16)), 'x').rjust(32, '0'))
    return resultedtext


def partBOFB(fileoutb1, fileoutb2):
    print('=====================================================================================================')
    keystring = "IbrahimMuharibXY"
    keyhex = binascii.hexlify(keystring.encode()).decode()
    #IV = ''.join(random.choice('0123456789abcdef') for n in range(32)) #fully random IV
    IV = 'ef390b9a28e188f4c537dda241c845dd'
    messagestring = 'This Is The Sample Test For IbrahimMuharibXY Python PA!!'
    messagestring = messagestring.replace(' ', '') #remove spaces
    messagehex = binascii.hexlify(messagestring.encode()).decode()
    blocksize = 32
    splitedmessage = [messagehex[i:i + blocksize] for i in range(0, len(messagehex), blocksize)]
    splitedmessage[len(splitedmessage)-1] = splitedmessage[len(splitedmessage)-1].ljust(32, '0') #zero filling the last block
    print(splitedmessage)
    OFBencryption = OFB(IV, keyhex, splitedmessage)
    print(OFBencryption)
    #OFBencryption[0] = "ff" + OFBencryption[0][2:]
    #OFBencryption[0] = format(int(OFBencryption[0], 16)>>1,'x') #adding an error
    OFBdecryption = OFB(IV, keyhex, OFBencryption)
    print(OFBdecryption)
    OFBencryptionstring = ''.join(OFBencryption)
    # hex -> base64
    OFBencryptionb64 = b64encode(bytes.fromhex(OFBencryptionstring)).decode()
    #print(OFBencryptionstring + ' , ' + OFBencryptionb64)

    #outputing results to outb1 and outb2
    fileoutb1.writelines('\n==================================================================================================================================================================================================')

    fileoutb1.writelines('\nciphertext "using mode OFB" = ' + OFBencryptionstring + ' , ' + OFBencryptionb64)
    fileoutb1.writelines('\n==================================================================================================================================================================================================')

    fileoutb2.writelines('\nusing mode CFB')
    fileoutb2.writelines('\noriginal encrypted message               = ' + ' , '.join(OFBencryption))
    OFBencryption[0] = format(int(OFBencryption[0], 16) >> 1, 'x')  # adding an error
    fileoutb2.writelines('\nencrypted message after adding the error = ' + ' , '.join(OFBencryption))
    fileoutb2.writelines('\n\ndecryption of the orignal message        = ' + ' , '.join(OFBdecryption))
    OFBerrordecrypted = OFB(IV, keyhex, OFBencryption)
    fileoutb2.writelines('\ndecryption of the message with error     = ' + ' , '.join(OFBerrordecrypted))
    fileoutb2.writelines('\n==================================================================================================================================================================================================')
    fileoutb2.writelines('\nresulting in the error existing in only the first block,\nbecause in OFB only the encryption output propagates not the ciphertext itself')
    fileoutb2.writelines('\n==================================================================================================================================================================================================')



#calls both CFB and OFB for partB
def partB():
    file1 = open('out_b1.txt', 'w')
    file2 = open('out_b2.txt', 'w')


    partBCFB(file1, file2)
    partBOFB(file1, file2)

    file1.close()
    file2.close()

'''====================================================================================================='''

#calling the methods for different parts
#partA100ciphers()
#partAavalanche()
partB()
