# LightAES-OFB-CFB
An implementation of the light AES algorithm (AES without the mix column operation) using 128 bits key, and in OFB and CFB operational modes.

The implementation is split into 2 main parts, for the light AES itself and the operational modes.

Part A
In file main.py, we use the function encry p tion( data, if decrypt, num rounds) to implement
the light AES 128 encryption and decryption operations, this function uses the (SubBytes(),
ShiftRows(), AddRound Key()) to perform the steps of each round from 0 to 10 , we also use
the key_handler() to expand the ke y from 4 w ords into 44.

The functions PartA100ciphers() and PartAavalanche() are used to preform and fill out the
output text files out_a1. txt and out_a2.txt respectively
The output:
- A txt file named out_a1.txt with the results ciphertext in Base64 format.
- A txt file named out_a2.txt with the results of avalanche effect test.
- ------------------------------------------------------------------------------------------------------------------------
Part B
In file main.py, we use the function OFB(IV, key, data) to implement the encryption and
decryption operations in OFB mode we also use the function CFBencrypt(IV, key,
plaintext) and CFBdecrypt(IV, key, ciphertext) to implement the encryption and
decryption operations in CFB mode

The functions PartBCFB and PartBOFB are used to preform and fill out the output text
files out_b1. txt and out_b2.txt respectively
The output:
- A txt file named out_b1.txt with the selected IV, key, message and the generated ciphertexts for each mode.
- A txt file named out_b2.txt with the results of error propagation for each mode.
