# AEAD_CHACHA20_POLY1305

This is an implementation of AEAD_CHACHA20_POLY1305, following RFC8439 protocol. This project was made for a computer science course on cryptography, and should not be considered as secure. It was not designed to be robust against side-channel attacks.

## Installation

Run `make` command to build the files.

## Test and usage 

You can launch the program using the following command:
```bash
./chacha20 yourkey.key < input
```
The key must be in the format :
```
constant:iv:key:aad
```
with values in hexadecimal. Constant should 32 bits in length, iv 64 bits, key 256 bits, and aad should be at most 2^64 -1 octets. An example from RFC8439 test vector is provided for extra clarity. 

You can test the software using this command, and you should get the corresponding output:
```console
➜ ./chacha20 testvector.key < inputvector.txt
Cipher :
d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2 
a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6 
3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b 
1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36 
92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58 
fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc 
3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b 
61 16 
Tag :
1a e1 0b 59 4f 09 e2 6a 7e 90 2e cb d0 60 06 91
```
