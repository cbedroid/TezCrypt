__author__ = "Cornelius Brooks"
__created__ = "Oct 3, 2019"
__description__ = "File encryptor/decryptor"


import os
import sys
import re
import blowfish
import subprocess
import base64
import argparse
import shutil
from getpass import getpass
from glob import glob
from functools import wraps
from platform import system
from time import sleep

if system() == 'Windows':
    # getpass doesn't work properly on Windows
    # with getpass, so we will create our own bypass
    class Getpass():
        def getpass(self, msg='Password: '):
            return input(msg)
    getpass = Getpass.getpass


class EncryptorError(Exception):
    """ Catch all Encryption and Decryption errors"""
    pass


class Encryptor():
    """Encryptor is a file encryption program that 
        encrypt and decrypt files"""

    def __init__(self, key):
        key = str(key).strip()
        self._key = key
        self._backup = os.environ.get("MYCRYPT")
        self._cipher = blowfish.Cipher(key.encode("ascii"))

    @property
    def key(self):
        '''Encryption/Decryption key'''
        if hasattr(self, "_key"):
            return self._key


    @key.setter
    def key(self, key):
        '''Sets password key value
           @@params: key - plain text password 
        '''

        key = str(key).strip()
        print("Key:", key)
        self._key = key
        self._cipher = blowfish.Cipher(key.encode("ascii"))


    def _handler(f):
        """ Read input file and return its data"""
        @wraps(f)
        def inner(self, infile, outfile=None, alter=False):
            if not os.path.isfile(infile):
                print("File not found:", infile)
                return

            self.infile = infile  # capture infile name incase outfile is not supplied
            name_of_f = f.__name__
            mode = 'rb' if 'de' in name_of_f else 'r'
            try:
                with open(infile, mode) as inf:
                    data = inf.read()
                self._test_strain = data
            except UnicodeDecodeError as e:
                print('\t-- Seem like %s is already Encrypted' % infile)
                return
            return f(self, data, outfile, alter)
        return inner


    @_handler
    def encrypt(self, infile, outfile, alter):
        """Encrypt files using blowfish algorithm
            @@params: infile - input file name
            @@params: outfile - file to save the encrypted data
            @@params: alter - "decrypt" or "encrypt" file name (see alter_name())
       """
        data = self._encrypt(infile)
        self._write_output(data, outfile, mode=alter)


    def _encrypt(self, data, add_padding=True):
        if not data:
            return
        try:
            self._type = 'Encryption'
            pad_size = 8
            padding = pad_size - (len(data) % pad_size)
            padding = (chr(padding)*padding).encode('ascii')
            data = data.encode('utf-8')
            data = data + padding
            data = b"".join(self._cipher.encrypt_ecb(data))
        except Exception as e:
            print("ERROR:", e)

        if self._backup and self._backup != "not set":
            with open(self._backup, "a") as k:
                stored = "%s --> %s\n" % (self.infile, self._key)
                k.write(stored)
        return data


    @_handler
    def decrypt(self, infile, outfile, alter=False):
        """Decrypt files using blowfish algorithm.
            @@params: infile - input file name
            @@params: outfile - file to save the decrypted data
            @@params: alter - "decrypt" or "encrypt" file name (see alter_name())
       """
        data = self._decrypt(infile)
        self._write_output(data, outfile, mode=alter)


    def _decrypt(self, data, remove_padding=True):
        if not data:
            return
        try:
            self._type = 'Decryption'
            data = b"".join(self._cipher.decrypt_ecb(data))
        except ValueError as e:
            data = "".join(self._cipher.decrypt_ecb(data))
        except:
            print('\t-- Seem like %s is already Decrypted' % self.infile)
            return
        try:
            if remove_padding:
                pad_size = int(data[-1])
                # remove padding
                padding = b"".join([chr(pad_size).encode("ascii")]*pad_size)
                if not data[-pad_size:] == padding:
                    raise ValueError()
                data = data[:-pad_size]
        except ValueError as e:
            print('\n\t -- Invalid Decryption key --')
            return
        return data.decode('utf-8')


    def _write_output(self, data, outfile=None, mode=False):
        """Creates an output file to save results"""
        # If user did not enter an outfile, then save copy of infile
        # and rename out_file -> infile
        if not data:
            return
        if not outfile:
            outfile = self.infile
            print('\t-- Saving outfile as %s --' % outfile)
        try:  # testing file written correctly
            with open("___temp___", "w") as nf:
                nf.write(data)
                write_mode = "w"
        except:
            write_mode = "wb"

        with open(outfile, write_mode) as nf:
            nf.write(data)
        os.remove("___temp___")
        self.alter_name(outfile, mode)
        print("Writing %s Done" % self._type)


    def alter_name(self, name, mode=False):
        '''Encrypt or Decrypt file name '
           @@params:: name - input file to change name
           @@params:: mode - set mode to "decrypt" to decrypt file name 
                             set mode to "encrypt" to decrypt file name 
                             default: False  file name not changed
        '''
        self.infile = name
        if not mode or not isinstance(mode, str):
            return

        path, _name = os.path.split(name)
        try:
            if mode.lower().strip() == 'encrypt':
                result = base64.b16encode(self._encrypt(_name)).decode('ascii')
            else:
                result = self._decrypt(base64.b16decode(
                    _name.encode('ascii')))
        except Exception as e:
            print(e)
            return

        try:
            new_path = '/'.join((path, result)) if path else result
            shutil.copyfile(name, new_path)
            sleep(.5)
            os.remove(name)
            print('New file:', new_path)
            return result
        except Exception as e:
            print('Error scrambling file name', e)


def _check_len(key):
    min_char = 8
    max_char = 24
    lop = len(key)

    if lop < min_char or lop > max_char:
        e_msg = "too short" if lop < min_char else "too long"
        print("\n-- Password is %s .. Try again --" % e_msg)
        return False
    return True


def _verify(key):
    verify = getpass("verify password: ").strip()
    if verify != key:
        print("\nPassword doesnt match.. Try again")
        return False
    return True


def perfect_pwd(key=None, need_verify=True):
    global max_retry
    nv = need_verify
    if max_retry <= 0:
        print("\nToo many Invalid password.. Goodbye")
        sys.exit(0)

    if not key:
        key = getpass("Enter password: ").strip()
        if any(key.lower() == x for x in ["q", "quit"]):
            print("\nExiting...")

        if not key:
            print("-- You must enter password --")
            max_retry -= 1
            return perfect_pwd(key=None, need_verify=nv)

    if not _check_len(key):
        max_retry -= 1
        return perfect_pwd(key=None, need_verify=nv)
    if nv:
        if not _verify(key):
            max_retry -= 1
            return perfect_pwd(key=None, need_verify=nv)
        return key
    return key


def main():
    global getpass
    parser = argparse.ArgumentParser()
    parser.add_argument('infile', help='Input file', type=str)
    parser.add_argument('-o', '--outfile', help='Output file', default=None)
    parser.add_argument(
        '-k', '--key', help='key for encryption and decryption', type=str)
    parser.add_argument(
        '-f', '--folder', help='Full folder Encrypt/Decrypt', action='store_true')
    parser.add_argument(
        '-a', '--alter', help='Encrypt/Decrypt file name', action='store_true')

    dore = parser.add_mutually_exclusive_group(required=True)
    dore.add_argument('-e', "--encrypt", help='Encrypt file',
                      action='store_true')
    dore.add_argument('-d', "--decrypt", help='Decrypt file',
                      action='store_true')

    args = parser.parse_args()
    if args:
        infile = args.infile
        encrypt = args.encrypt
        decrypt = args.decrypt
        outfile = args.outfile
        folder = args.folder
        alter = args.alter
        key = args.key

        if not encrypt and not decrypt:
            print("\nInvalid Mode")
            print('\t-- Please choose either decrypt or encrypt --')
            sys.exit(0)

        if folder:
            dorf = infile
            # combine dirname and filename if folder option selected
            if isinstance(dorf, (list, tuple, set)):
                infile = dorf

            elif isinstance(infile, str):
                if os.path.isdir(dorf):
                    try:
                        infile = list(
                            filter(os.path.isfile, glob(dorf+'/*', recursive=True)))
                        if not infile:
                            print("\n -- No files found in directory: %s --" % dorf)
                            return
                    except:
                        raise EncryptorError('Invalid Directory: %s' % infile)

                elif os.path.isfile(dorf):
                    infile = [dorf]
                else:
                    msg = '\n\t-- Invalid file or folder: %s is not a folder --' % dorf
                    print(msg)
                    return
            else:
                print('\n\t-- Invalid file name: %s --' % dorf)
                return

        if infile:
            if not isinstance(infile, (list, tuple)):
                infile = [infile]
            if len(infile) != 1:
                outfile = None

            key = perfect_pwd(
                key, False) if decrypt else perfect_pwd(key, True)
            if alter:
                alter = 'decrypt' if decrypt else 'encrypt'
            else:
                alter = False

            TezCrypt = Encryptor(key)
            for x in infile:
                if decrypt:
                    print('\nDecrypting %s ....' % x)
                    TezCrypt.decrypt(x, outfile, alter)
                elif encrypt:
                    print('\nEncrypting %s ....' % x)
                    TezCrypt.encrypt(x, outfile, alter)
        else:
            print('\n\t-- Must specify an input file to begin --')
            print(parser.print_help())


if __name__ == '__main__':
    max_retry = 3
    main()
