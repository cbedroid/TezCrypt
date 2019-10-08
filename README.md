TezCrypt
===========

TezCrypt is a python program used to encrypt or decrypt files. It can be used in python or as a cmdline program.

TezCrypt support  python3.4+ and is compatible with windows and linux system.


# How to use

First we import the module:
```python
from tezcrypt import Encryptor
```
## Key
A password key is required to use this program.
Key must be 8 to 24 characters long 
- password are case sensitive. 
- Symbols and numbers are supported
- 8 to 24 characters long ( cmdline only)

# Python
```python
mykey = "secretkey"
crypt = Encryptor(key=mykey)
```
Once initialized,  method `encrypt()` or `decrypt()` can be called with parameters  'data' and 'outfile'. 
The `data` argument is the name of the file you want to decrypt or encrypt. It must be called (required). The `outfile` argument is optional.It is the name of the file you want save the results.
#### If the outfile is Not supplied, the infile will be overwritten!
- data - input file to encrypt or decrypt 
- outfile - output file to save the results 

```python
Infile = "important.txt"
crypt.encrypt(data=infile)
#infile will be overwritten

newfile = "important_encrypted.txt"
crypt.encrypt(data=infile, outfile=newfile)
#infile not overwritten,  newfile is created
```
# Cmdline
#### Optional,but Not recommended
 ##### <sup>Save an environment variable named "MYCRYPT=path_to_recovery_file" for password recovery. This is optional, it save all password to a file in case user forgets encryption or decryptio key.This is not recommended, because it can cause security risk if attacker find password.</sup>


TezCrypt can also be used as a cmdline program.
For linux distribution, it's best to save tezcrypt to /usr/bin/. Then add  a shebang line with your python executable path to the first line of "tezcrypt.py"

If you are adding a shebang line, then  change "tezcrypt.py" to "tezcrypt"
> change tezcrypt.py   -->   tezcrypt 

If using python 3, then  python3 will be your python executable. Add either one below to the first line of "tezcrypy"

> #!/usr/bin/env python 
#### Or 
>#/usr/bin/python3 
## cmdline argument 

```bash
 Usage: tezcrypt [-h] [-o OUTFILE] [-k KEY] (-e | -d) infile

positional arguments:
  infile                Input file to decrypt or encrypt 

optional arguments:
  -h, --help            show this help message and exit
  -o OUTFILE, --outfile OUTFILE
                        Output file to save the (en|de)crypted results 
  -k KEY, --key KEY     key for encryption and decryption
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

```

