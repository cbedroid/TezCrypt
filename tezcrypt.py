#!/data/data/com.termux/files/usr/bin/python3.7
__author__ = "Cornelius Brooks"
__created__ = "Oct 3, 2019"
__description__ = "File encryptor/decryptor"


import os
import sys
import blowfish
import subprocess as sp
import base64
import re
import argparse
from getpass import getpass
from functools import wraps
from platform import system

class EncryptorError(Exception):
    """ Catch all Encryption and Decryption errors"""
    pass

class Encryptor():
    """Encryptor is a file encryption program that 
    encrypt and decrypt files"""
    def __init__(self,key):
        key = str(key).strip()
        self._key=key
        #self._make_export()
        self._backup = os.environ.get("MYCRYPT")
        self.cipher = blowfish.Cipher(key.encode("ascii"))
            
    def _make_export(self):
        """ !!Important !!
        Optional ,but recommended
        Creates an environment varible: MYCRYPT
        MYCRYPT variable will be the pathname of Encryptor encyrption keys 
        incase of lost decryption key (recovery file)
        """
        # TODO:: Need fix setting environment variable from python
        #        This way not working
        is_recovery = os.environ.get("MYCRYPT")
        if not is_recovery or is_recovery != "not set":
            print("\n","-"*52)
            print("\t\t--- RECOVER KEY ---\n")
            print("This is a one time setup,incase you lose encryption key")
            print("-"*52)
            msg = "Do you want to setup a recovery file? : "
            recovery = input(msg).lower().strip()
            if recovery in ["yes","y"]:
                if system == "Windows":
                    file_path = "\\".join((os.environ.get("UserProfile"),".MYCRYPT"))
                    os.environ["MYCRYPT"] = file_path
                else:
                    file_path = "/".join((os.environ.get("PREFIX"),"etc/.MYCRYPT"))
                    command = "export MYCRYPT='%s'"%file_path
                    runner =sp.call(command,shell= True)
                    print("Runner:",runner)

                print("\nRecovery file now save as environment variable:")
                print(file_path)

            else:
                os.environ["MYCRYPT"] = "not set"


    def _write_output(self,data,outfile=None,mode='encrypt'):
        """Creates a output file """
        # If user did not enter an outfile, then save copy of infile
        # and rename out_file -> infile
        if not outfile:
            infile = self.infile
            outfile = infile
            print('\t-- Saving outfile as %s --'%outfile) 
        try: #testing file written correctly
            with open("___temp___","wb")  as nf:
                nf.write(data)
        except:
            print("\nError writing file")
            sys.exit()

        with open(outfile,"wb")  as nf:
            nf.write(data)
        os.remove("___temp___")
        print("Writing %s Done"%self._type)
    def handler(f):
        """ Read input file and return its data"""
        @wraps(f)
        def inner(self,infile,outfile=None):

            if not os.path.isfile(infile):
                print("File not found:",infile)
                sys.exit()

            self.infile = infile #capture infile name incase outfile is not supplied

            name_of_f = f.__name__
            mode = 'rb' if 'de' in name_of_f  else 'r'
            with open(infile,mode) as inf:
                try:
                    data = inf.read().strip()
                    self._test_strain = data
                except UnicodeDecodeError as e:
                    print('\t-- Seem like %s is already Encrypted'%self.infile)
                    sys.exit()
                return f(self,data,outfile)
        return inner

    @handler
    def encrypt(self,data,outfile,):
        """Encrypt files using blowfish algorithm
            params: data - input file name
                    outfile - file to save the encrypted data
        """
        try:
            self._type = 'Encryption'
            pad_size  = 8
            padding = pad_size - (len(data) % pad_size)
            padding = (chr(padding)*padding).encode('ascii')
            data = data.encode('utf-8') + padding

            data = b"".join(self.cipher.encrypt_ecb(data))
            self._write_output(data,outfile)
        except Exception as e:
            print("ERROR:",e)
        if self._backup and self._backup !="not set":
            with open(self._backup,"a") as k:
                stored = "%s --> %s\n"%(self.infile,self._key)
                k.write(stored)
                print("\nBack_UP:",self._backup)

    @handler
    def decrypt(self,data,outfile):
        """Decrypt files using blowfish algorithm.
            params: data - input file name
                    outfile - file to save the decrypted data
        """
        try:
            self._type = 'Decryption'
            data = b"".join(self.cipher.decrypt_ecb(data))
        except ValueError as e:
            print('\t-- Seem like %s is already Decrypted'%self.infile)
            sys.exit()
        try:
            pad_size =int(data[-1])
            #remove padding
            padding =  b"".join([chr(pad_size).encode("ascii")]*pad_size)

            computed = b"".join([chr(pad_size).encode("ascii")] * pad_size)
            if not data[-pad_size:] == padding:
                raise ValueError()
            data = data[:-pad_size]
            self._write_output(data,outfile,mode='decrypt')

        except ValueError as e:
            print('\n\t -- Invalid Decryption key --')
            sys.exit()


def _check_len(key):
    min_char = 8
    max_char = 24
    lop = len(key)

    if lop < min_char or lop > max_char:
        e_msg ="too short" if lop < min_char else "too long"
        print("\n-- Password is %s .. Try again --"%e_msg)
        return False
    return True

def _verify(key):
    verify = getpass("verify password: ").strip()
    if verify != key:
        print("\nPassword doesnt match.. Try again")
        return False
    return True


def perfect_pwd(key=None,need_verify=True):
    global max_retry
    nv = need_verify
    if max_retry <= 0:
        print("\nToo many Invalid password.. Goodbye")
        sys.exit(0)

    if not key:
        key = getpass("Enter password: ").strip()
        if any(key.lower()==x for x in ["q","quit"]):
            print("\nExiting...")
             
        if not key:
            print("-- You must enter password --")
            max_retry -= 1
            return perfect_pwd(key=None,need_verify=nv)

    if not _check_len(key):
        max_retry -= 1
        return perfect_pwd(key=None,need_verify=nv)
    if nv:
        if not _verify(key):
            max_retry -= 1
            return perfect_pwd(key=None,need_verify=nv)
        return key

    return key

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('infile',help='Input file',type=str)
    parser.add_argument('-o','--outfile',help='Output file',type=str,default=None)
    parser.add_argument('-k','--key',help='key for encryption and decryption',type=str)
    
    dore = parser.add_mutually_exclusive_group(required=True)
    dore.add_argument('-e',"--encrypt",help='Encrypt file',action='store_true')
    dore.add_argument('-d',"--decrypt",help='Decrypt file',action='store_true')
    args = parser.parse_args()
   
    if args:
        infile = args.infile
        encrypt = args.encrypt
        decrypt = args.decrypt
        outfile = args.outfile
        key = args.key

        if not encrypt and not decrypt:
            print("\nInvalid Mode")
            print('\t-- Please choose either decrypt or encrypt --')
            sys.exit(0)
        else:
            if not infile:
                print('\n\t-- Must specify an input file to begin --')
                print(parser.print_help())
                sys.exit(0)

            
            if decrypt:
                key = perfect_pwd(key,False)
                TezCrypt = Encryptor(key)
                print('\nDecrypting %s ....'%infile)
                TezCrypt.decrypt(infile,outfile)
            elif encrypt:
                key = perfect_pwd(key)
                TezCrypt = Encryptor(key)
                print('\nEncrypting %s ....'%infile)
                TezCrypt.encrypt(infile,outfile)
    else:
        print(parser.print_help())

if __name__ =='__main__':
    max_retry = 3
    main()
