TezCrypt
===========

TezCrypt is a python program used to encrypt or decrypt files and folders. It can be used in python or as a cmdline program.
TezCrypt support  python3.4+ and is compatible with windows and linux system.

# How to use

First we import the module:
```python
from tezcrypt import Encryptor
```
# Python
## Key
A password key is required to use this program.
Key must be 8 to 24 characters long 
- password are case sensitive. 
- Symbols and numbers are supported
- 8 to 24 characters long ( cmdline only)

## Initialize
```python
mykey = "secretkey"
crypt = Encryptor(key=mykey)
```

Once initialized,  method `encrypt()` or `decrypt()` can be called with parameters  'infile' , 'outfile',and  'alter'.
The `infile` argument is the name of the file you want to decrypt or encrypt. It must be called (required). The `outfile` argument is optional.It is the name of the file you want save the results. `alter` is also optional, alter argument decrypt or encrypt file name. There are 3 option to pass to alter: 'decrypt','encrypt', False. It is set to False by default.
#### Warning: If the outfile is Not supplied, the infile will be overwritten!
- infile   -  input file to encrypt or decrypt 
- outfile  -  output file to save the results 
- alter    -  encrypt or decrypt file name  

```python

from tezcrypt import Encryptor
mykey = "secretkey"
crypt = Encryptor(key=mykey)

#Example : 1
your_file = "important.txt"
crypt.encrypt(infile=your_file)
#infile will be overwritten

#Example : 2
your_file = "important.txt"
newfile = "important_encrypted.txt"
crypt.encrypt(infile=your_file, outfile=newfile)
#infile not overwritten,  newfile will be created

#Example : 3
your_file = "important.txt"
crypt.encrypt(infile=your_file ,alter='encrypt')
#result: infile --> 437CE4CEBDF566845E60A9C00FD926C4
#"important.txt" overwritten to filename "437CE4CEBDF566845E60A9C00FD926C4"

#Example : 4
your_file = 437CE4CEBDF566845E60A9C00FD926C4'
crypt.decrypt(infile=infile,alter='decrypt')
#result: 'important.txt'
# "filename "437CE4CEBDF566845E60A9C00FD926C4" is converted back to "important.txt"

```




# Cmdline

TezCrypt can also be used as a cmdline program.
For linux distribution, Use **tezcrypt** bash file instead of **tezcrypt.py**.

## cmdline argument 

```bash

usage: tezcrypt.py [-h] [-o OUTFILE] [-k KEY] [-f] [-a] (-e | -d) infile

positional arguments:
  infile                Input file

optional arguments:
  -h, --help            show this help message and exit
  -o OUTFILE, --outfile OUTFILE
                        Output file
  -k KEY, --key KEY     key for encryption and decryption
  -f, --folder          Full folder Encrypt/Decrypt
  -a, --alter           Encrypt/Decrypt file name
  -e, --encrypt         Encrypt file
  -d, --decrypt         Decrypt file

```

## cmdline usage 
```bash
#To encrypt (overwrite infile)
$ tezcrypt `infile.txt` -e  -k "mysecretkey"

#To decrypt (overwrite infile)
$ tezcrypt `infile.txt` -d  -k "mysecretkey"

#To encrypt to another file
$ tezcrypt `infile.txt` -e -o "newfile.txt" -k "mysecretkey"

#To decrypt to another file
$ tezcrypt `infile.txt` -d  -o "newfile.txt" -k "mysecretkey"

#To encrypt file and filename (overwrite infile)
$ tezcrypt `infile.txt` -e -a  -k "mysecretkey"

#To decrypt file and filename (overwrite infile, and convert filename back to original name)
$ tezcrypt `infile.txt` -d -a  -k "mysecretkey"

# If argument "-k" not passed,then user will be prompt to enter password




```

