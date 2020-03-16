#!/usr/local/bin/python3.8
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
import threading
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


class Error():
    '''Print warning and error message to user screen '''
    @staticmethod
    def display(msg,obj='  '):
        errors = { 'ENCRYPT': 'Seems like %s is already encrypted',
                   'DECRYPT': 'Seems like %s is arleady decrypted',
                   'NOFILE' : '%s file not found!',
                   'WRITING': 'Error while writing %s. Rolling back file ....',
                   'KEY'    : 'Invalid Key %s',
                   'ALTER'  : 'ERROR altering file name %s' , 
                   'PWD'    : 'Password is %s .. Try again --',
                   'NOMATCH': 'Password doesnt match.. Try again %s',
                   'ATTEMPTS':'Too many Invalid password.. Goodbye %s',
                   'NOPWD'  : ' You must enter password %s',
                   'FILE'  : 'No files found in directory: %s',
                   'FNAME' : 'Invalid file name: %s',
                   'DORF'  : 'Invalid file or folder: %s is not a folder --',
                   'MODE': 'Invalid Mode\nPlease choose either decrypt or encrypt %s',
                }
        error = errors.get(msg)
        if error:
            print('\n\t-- '+ error%obj +' -- ')


class Encryptor():
    """Encryptor is a file encryption program that 
        encrypt and decrypt files"""

    def __init__(self, key):
        key = str(key).strip()
        self._key = key
        self._mode = 'unknown'
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


    def _is_encrypted(self,raw_data):
        '''Test infile file and data type
            returns False if file not encrypted
            returns True if file is encrypted 
        '''
        # if base64.b64decode throw error then the file is not encrypt 
        try:
            base64.b64decode(raw_data)
        except base64.binascii.Error as e:
            if 'padding' in str(e): #padding error then the file is not encrypt
                return 0
            else:
                return -1
        else:
            return 1


    @staticmethod
    def read_file(file=None,mode='r'):
        ''' Read infile and return it data '''
        with open(file,mode) as r:
            return r.read()

    @staticmethod
    def _test_mode(file=None):
        ''' test the data type and return the IO mode type'''
        # we want to test 'rb' mode first since 'r' will not throw error 
        # for bytes or string
        if not file:
            raise FileNotFoundError('No File was entered')
        try:
            with open(file,'rb') as r:
                r.read()
            return 'rb'
        except:
           return 'r'
        
    def _encryptorType(self,caller):
        '''User Encyption Type: 
            return whether user is decrypting or encrypting 
            params: caller - function name (en|decrypting function name)
        '''
        if 'de' in caller:
            return False  #Encyptor.decrypt function called 
        else:
            return True   #Encyptor.encrypt function called 


        
    def _found_stamp(self,data):
        ''' This function check if file was encrypted or decrypted
             by checking the last three (3) bytes or string in infile
            -returns: False if file is not encrypted 
                      True if file is encrypted 
        '''
        stamps =['ENR','ENB',b'ENR',b'ENB']
        try:
            if any(x == data[-3:] for x in stamps):
                return True
        except Exception as e:
            pass


    def _handler(f):
        """ Read input file and determine the algorithm ro handle its data 
            return:  IO data from infile 
        """
        @wraps(f)
        def inner(self, infile, outfile=None, alter=False):
            name_of_f = f.__name__
            self._f = name_of_f
            if not os.path.isfile(infile):
                Error.display('NOFILE',infile)
                return
            try:
                self.infile = infile  # capture infile name incase outfile is not supplied
                mode = self._test_mode(infile) # get file mode
                data = self.read_file(infile,mode) # get data from file

                # check for encryption stamp , exit if stamp found
                if self._encryptorType(f.__name__):
                    if self._found_stamp(data):
                        Error.display('ENCRYPT',infile)
                        return 
                    # encypting we set the mode from read_file mode
                    self._stamp =  'ENR' if mode == 'r' else 'ENB'
                    self._mode  = 'wb'
                # strip stamp from decryption data 
                if not self._encryptorType(f.__name__):
                    if  self._found_stamp(data):
                        # decryption we get the mode from end of file  
                        self._stamp = data[-3:]
                        data = data[:-3]
                        self._mode = 'wb' if self._stamp == b'ENB' else 'w'
            except Exception as e:
                print('HANDLER',e)
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
        self._write_output(data, outfile, alter=alter)


    def _encrypt(self, data, add_padding=True):
        if not data:
            return
        try:
            self._type = 'Encryption'
            pad_size = 8
            padding = pad_size - (len(data) % pad_size)
            padding = (chr(padding)*padding).encode('ascii')
            try:
                data = data.encode('utf-8')
            except:
                pass
            data = data + padding
            data = b"".join(self._cipher.encrypt_ecb(data))
            data +=self._stamp.encode('ascii') # stamp the file 
        except Exception as e:
            pass

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
        self._write_output(data, outfile, alter=alter)

    def _decrypt(self, data, remove_padding=True):
        if not data:
            return
        try:
            self._type = 'Decryption'
            data = b"".join(self._cipher.decrypt_ecb(data))
        except Exception as e:
            try:
                data = ''.join(self._cipher.decrypt_ecb(data))
            except Exception as e:
                Error.display('DECRYPT',self.infile)
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
            Error.display('KEY')
            return

        if self._mode == 'wb': 
            return data 
        else:
            return data.decode('utf-8')


    def _write_output(self, data, outfile=None, alter=False):
        """Creates an output file to save IO data """
        # If user did not enter an outfile, then save copy of infile
        # and rename out_file -> infile
        temp = '___temp___'
        if not data:
            return

        if not outfile:
            outfile = self.infile # overwrite infile 
        if self._mode == 'unknown':
            try:  # testing file written correctly
                #   and returns the right IO mode to write file
                with open(temp,"w") as nf:
                    nf.write(data)
                    write_mode = "w"
            except Exception as e:
                write_mode = "wb"
            finally:
                os.remove(temp)
        else:
            write_mode = self._mode

        try: # Capture data and write to temp file
             # !! Writing to tempfile incase error occur
             # this way the corrupt data wont be overwrite infile
            with open(temp, write_mode) as nf:
                nf.write(data)
        except Exception as e:
            Error.display('WRITING',outfile)
        else:
            # if there is no error then, write to infile and remove tempfile
            shutil.copyfile(temp,outfile)
            sleep(.5)
            self.alter_name(outfile, alter)
            print("Writing %s Done" % self._type)
        finally:
            os.remove(temp)


    def alter_name(self, name, mode=False):
        '''Encrypt or Decrypt file name  '
           @@params:: name - input file to change name
           @@params:: mode - set mode to "decrypt" to decrypt file name 
                             set mode to "encrypt" to decrypt file name 
                             default: False  file name not changed
        '''
        self.infile = name
        if not mode or not isinstance(mode, str):
            print('\t-- Saving outfile as %s --' % name)
            return
        path, _name = os.path.split(name)
        try:
            if mode.lower().strip() == 'encrypt':
                result = base64.b16encode(self._encrypt(_name)).decode('ascii')
            else:
                result = self._decrypt(base64.b16decode(
                    _name)[:-3]).decode()
        except Exception as e:
            return

        try:
            new_path = '/'.join((path, result)) if path else result
            shutil.copyfile(name, new_path)
            sleep(.5)
            os.remove(name)
            print('\t-- Saving outfile as %s --' % result)
            return result
        except Exception as e:
            Error.display('ALTER',name)
            print(e)


def _check_len(key):
    min_char = 8
    max_char = 24
    lop = len(key)

    if lop < min_char or lop > max_char:
        e_msg = "too short" if lop < min_char else "too long"
        Error.display('PWD',e_msg)
        return False
    return True


def _verify(key):
    verify = getpass("verify password: ").strip()
    if verify != key:
        Error.display('NOMATCH')

        return False
    return True


def perfect_pwd(key=None, need_verify=True):
    global max_retry
    nv = need_verify
    if max_retry <= 0:
        Error.display('ATTEMPTS')
        sys.exit(0)

    if not key:
        key = getpass("Enter password: ").strip()
        if any(key.lower() == x for x in ["q", "quit"]):
            print("\nExiting...")

        if not key:
            Error.display('NOPWD')
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
            Error.display('MODE')
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
                            Error.display('FILE',infile)
                            return
                    except:
                        raise EncryptorError('Invalid Directory: %s' % infile)

                elif os.path.isfile(dorf):
                    infile = [dorf]
                else:
                    Error.display('DORF',dorf)
                    return
            else:
                Error.display('FNAME')
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
                    t = threading.Thread(target=TezCrypt.decrypt,
                            args=(x, outfile, alter,),
                            )
                elif encrypt:
                    print('\nEncrypting %s ....' % x)
                    t = threading.Thread(target=TezCrypt.encrypt,
                            args=(x, outfile, alter),
                            )
        else:
            print('\n\t-- Must specify an input file to begin --')
            print(parser.print_help())


if __name__ == '__main__':
    max_retry = 3
    main()
