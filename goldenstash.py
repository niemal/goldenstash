#!/usr/bin/env python3
'''
goldenstash - A CLI credentials safe

Originally written by niemal
Ported to Python 3 by linuxtinkerer
Join us @ irc://irc.hydra.ws/#default

DISCLAIMER:
The cryptography in this program is hand-rolled. While the
cipher (Twofish) and mode of operation (CBC) are both secure,
and industry standards are abided by in this application,
under no circumstances should you use this program in
situations that can or could result in damages to you. This
program is purely made for academic purposes, and is meant
as a "toy program". You should really use another program,
like KeePass, GPG, or Veracrypt. You have been warned.

Licensed AGPLv3 or Later.
'''
VERSION = '0.0.2'

# To whomever reads this:
# This program is written with a command line-centric focus.
# It is mean to be easy to use from the command line. If you
# make a GUI of this program, you are doing the users of
# this and your program a disservice.
# Also, you are literally worse than Comcast.

# TODO: Improve file structure
# TODO: Support other file formats?
# TODO: Add checksum to file
# TODO: Fix up command parsing structure [in progress]
# TODO: Daemonize?
# TODO: Other stuff
# TODO: Load stuff from the configuration file
# TODO: Parse different entries as some type of object or something so
# we can do more with them (eg search /all/ entries or delete entries)
# TODO: Use a config file (~/.goldenstash.conf)

# NOTE: The --obfus flag to change the number of obfuscation layers
# has been changed. Maybe we can add this again in the future?
# NOTE: The --encryptfile flag was removed because I thought it served
# no purpose.
# NOTE: Maybe password generation should be added?
# NOTE: The cryptography in here is hand-rolled. While it uses industry
# best-practices, your life should /NOT/ depend on this program.

try:
    from twofish import Twofish
except:
    from sys import exit
    print('It looks like you don\'t have the `twofish` Python module installed.')
    print('Try running the following command to install it:')
    print('    sudo pip3 install twofish')
    exit(-1)

import sys, os, getpass
import operator
import array
import codecs
import argparse
from subprocess import Popen, PIPE, STDOUT
#import base64  # used for debugging


# Global vars
allowed = ' @0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-:!^%&*()_.#'
obfuscation_layers = 20 # The more possibilities of layers, the bigger the file.
padding = 0


# Constants - These SHOULD NOT change
ASCII_START_BLOCK = '---------------'
ASCII_END_BLOCK =   '------END------'
ASCII_0END_BLOCK =  b'------0END------'
#CONFIG_PATH = os.path.expanduser('~/.goldenstash')
PASS_PROMPT = 'Please enter your encryption key: '

CONFIG = {
    'IV': "POWQEOSADJQ9234SZ",
    'database': "~/.database.gs",
    'filename': "default",
}


def rand(minimum: int, maximum: int) -> int:
    '''
    Generate random number between min and max and return
    it as an integer ordinal.

    The implementation of this method uses os.urandom, which
    is good enough for cryptographic use. However, on the off
    chance that we get crappy entropy, then it's only used
    for padding in the file. There should be no big deal,
    but it is an attack vector. /dev/urandom on Linux and
    the BSDs is secure enough anyways.

    minimum - The lower bound of acceptable numbers to return
    maximum - The lower bound of acceptable numbers to return

    Returns a random number minimum <= n <= maximum
    '''
    # TODO: Is it quicker to a modulo operation for this? It
    # is possible that a modulo operation biases the values of
    # this to lower values.
    numb = ord(os.urandom(1))
    while numb > maximum or numb < minimum:
        numb = ord(os.urandom(1))
    return numb


def padup(data: bytes) -> bytes:
    '''
    Pads data to 16 bytes in length.
    This is a utility function for Twofish
    '''
    # Make sure we're bytes, just in case
    if type(data) == str:
        data = data.encode('utf-8')

    if data == b"":
        while len(data) != 16:
            data += allowed[rand(0, len(allowed)-1)].encode('utf-8')
        return data
    elif len(data) < 16: # Padding up.
        global padding
        padding = 0
        #print('data is a {}'.format(type(data)))
        while len(data) != 16:
            data += allowed[rand(0, len(allowed)-1)].encode('utf-8')
            padding += 1
        return data


def byte_hexxor(a: bytes, b: bytes) -> bytes:
    '''
    Hex two byte strings.

    a - A string of bytes
    b - Another string of bytes

    Returns the result of a^b
    '''
    if len(a) != len(b):
        print('error in hexxing a and b')
        print('a: {}|EOL'.format(a))
        print('b: {}|EOL'.format(b))

    result_list = []
    for x, y in zip(a, b):
        # str(unichr()) converts back to string
        res = operator.xor(x, y)
        #print('result: {}'.format(res))
        result_list.append(res)
    #return b''.join(result_list)
    r = array.array('B', result_list).tostring()
    #print(codecs.getencoder('hex')(r)[0])
    #print(len(r))
    return r


def CBC_encrypt(IV_str: str, key_str: str, data_str: str) -> str:
    '''
    Encrypt data CBC using the IV, key and the actual data

    IV - Initialization Value (aka the salt/nonce) (what type?)
    key - the key (what type?)
    data - the data (what type?)
    '''
    print('[*] Encrypting database...')

    IV = IV_str.encode('utf-8')
    key = key_str.encode('utf-8')
    data = data_str.encode('utf-8')
    
    if len(IV) > 16:
        while len(IV) != 16:
            IV = IV[1:]
    if len(IV) < 16:
        while len(IV) != 16:
            for i in IV:
                IV += i
                if len(IV) == 16:
                    break
    if len(key) > 32:
        while len(key) != 32:
            key = key[1:]
    cipher = Twofish(key)
    rounds = int(float(len(data))/16)
    #print("[+] Initiating encryption process..")

    buf = b''
    block = data[:16]
    data = data[16:]
    if len(block) != 16:
        block = padup(block)
    #print('block: {}\niv: {}'.format(len(block), len(IV)))
    # hexxed is type(bytes)
    hexxed = byte_hexxor(block, IV)
    #print('hexxed: {}\nlen: {}'.format(hexxed, len(hexxed)))
    # block is type(bytes)
    block = cipher.encrypt(hexxed)

    buf += block

    for round in range(0, rounds-1):
        data_chunk_bytes = data[:16]
        hexxed = byte_hexxor(data_chunk_bytes, block)
        #print(type(hexxed))
        #print(len(hexxed))
        block = cipher.encrypt(hexxed)
        #print('data: {}'.format(base64.b64encode(hexxed)))
        #print('block : {}'.format(base64.b64encode(block)))
        buf += block
        data = data[16:]
        #print(type(data))
        
        if len(data) < 16: # Padding up the last block.
            data = padup(data)  # data is bytes
            block = cipher.encrypt(byte_hexxor(data, block))
            buf += block
            break
    
    # Obfuscation for the 0END signature.
    #print("buf " + str(base64.b64encode(buf)))
    #print(data)
    data = ASCII_0END_BLOCK[:]  # Make a copy of the block
    block = cipher.encrypt(byte_hexxor(data, block))
    buf += block
    #print('buf: ', end='')
    #print(base64.b64encode(buf))
    #print('=======================')
    for i in range(rand(1,obfuscation_layers)):
        if rand(1, 3301) % 2 == 0:
            data = ASCII_0END_BLOCK[:]
        else:
            data = padup("")
        block = cipher.encrypt(byte_hexxor(data, block))
        buf += block
        
    
    if padding != 0:
        buf = b"PADDING = " + str(padding).encode('utf-8') + b"\n" + buf
    print('[*] Database encrypted.')
    return buf


def CBC_decrypt(IV_str, key_str, data): 
    '''
    Decrypt a Twofish-CBC encrypted file.

    IV - Initalization Vector (aka nonce)
    key - The key used to decrypt the file (type str)
    data - the file to be decrypted (type str)
    '''
    print('[*] Decrypting database...')

    IV = IV_str.encode('utf-8')
    key = key_str.encode('utf-8')

    assert type(data) == bytes

    if len(IV) > 16:
        #while len(IV) != 16:
        #    IV = IV[1:]
        IV = IV[len(IV)-16:]
    elif len(IV) < 16:  # TODO: How to do this better?
        copy = IV[:]
        while len(IV) != 16:
            for i in copy:
                IV += i
                if len(IV) == 16:
                    break

    assert len(IV) == 16
    
    # keysize is limited to 32 bytes as per libtwofish, the libary
    # that pytwofish is based off of
    if len(key) > 32:
        while len(key) != 32:
            key = key[1:]

    #print(len(key))
    cipher = Twofish(key)

    padlen = 0
    if b'PADDING' in data:
        data = data.replace(b'PADDING = ', b'')
        padlen = int(data[:data.find(b'\n')])
        data = data[data.find(b'\n')+1:]


    # number or rounds is equal the the number of 16-byte blocks
    rounds = len(data) // 16
    #print('padding length: {}'.format(padlen))
    #print('data length: {}'.format(len(data)))
    #print('[+] Initiating decryption process..')

    buf = b''

    old_block = data[:16]
    #print('old block: {}'.format(len(old_block)))
    data = data[16:]
    #print('old_block len: {}'.format(len(old_block)))
    hexxed = byte_hexxor(cipher.decrypt(old_block), IV)
    new_block = byte_hexxor(cipher.decrypt(old_block), IV)
    buf += new_block

    assert type(new_block) == bytes and type(old_block) == bytes

    for rnd in range(rounds-1):
        new_block = data[:16]
        data = data[16:]
        #print('old: {}\nnew: {}'.format(base64.b64encode(old_block), base64.b64encode(new_block)))
        #print('='*5)
        buf += byte_hexxor(cipher.decrypt(new_block), old_block)
        old_block = new_block[:]

    # strip obfuscation
    end_block_index = buf.find(ASCII_0END_BLOCK)  # USE find() here, rfind() breaks sutff
    if end_block_index != -1:
        buf = buf[:end_block_index]

    # strip padding
    if padlen != 0:
        buf = buf[:len(buf)-padlen]

    print('[*] Database decrypted.')
    return buf


def print_header():
    print('Running Goldenstash {}'.format(VERSION))
    print()


def main():
    parser = argparse.ArgumentParser(prog='Goldenstache')
    parser.add_argument('-v', '--version', action='version',
            version='Goldenstash {}'.format(VERSION))

    subparsers = parser.add_subparsers(help='Goldenstash commands')

    search_parser = subparsers.add_parser('search', aliases=('s',),
            help='search the password database')
    #search_parser.add_argument('--all', action='store_true', default=True,
    #        help='View all matches in the database. (Default: True)')
    search_parser.add_argument('term', nargs=1,
            help='Term to search for')
    search_parser.set_defaults(func=querydb)

    add_creds_parser = subparsers.add_parser('add', help='add credentials to the database')
    add_creds_parser.add_argument('title', help='Title of account')
    add_creds_parser.add_argument('user', help='Username of account to add')
    add_creds_parser.add_argument('password', help='Password of account to add')
    add_creds_parser.set_defaults(func=addCreds)

    # NOTE: Maybe it's easier to make `clipboard`, `file`, and `stdout` 
    # into separate commands?
    export_parser = subparsers.add_parser('export', aliases=('e',),
            help='Export the database to plaintext')
    export_parser.add_argument('target', choices=['clipboard', 'file', 'stdout'],
            help='How to export the database.')
    export_parser.add_argument('--path', default=None, nargs='?', required=False,
            help='Where to save the exported file. Only required for `stdout` target option.')
    export_parser.set_defaults(func=exportdb)

    # TODO: Implement delete function
    #delete_parser = subparsers.add_parser('delete', aliases('d',),
    #        help='Delete accounts from the database')

    args = parser.parse_args()
    
    if 'func' not in args:
        parser.print_usage()
    elif 'func' in args:
        args.func(args)
    return


def querydb(args):
    '''
    Query database by entry title
    '''
    print_header()
    title = args.term[0]
    IV = CONFIG['IV']
    key = getpass.getpass(PASS_PROMPT)

    database = os.path.expanduser(CONFIG['database'])
    database = os.path.abspath(database)

    if not os.path.exists(database):
        print('Database does not exist!')
        print(database)
        return

    try:
        index = -1
        with open(database, 'rb') as f:
            db = f.read()
            data = CBC_decrypt(IV, key, db)  # data is in bytes

            # convert the title to bytes so we can search the decrypted data
            title = title.encode('utf-8')
            index = data.find(title)

            #print('data: {}\n{}'.format(data, '='*30))

        if index == -1:
            print("[-] Unable to find the specified title.")
            #print(data)
            return
        else:
            start = data[:index].rfind(b'Title')
            # stop is start plus the index of the end block because
            # otherwise it would be the index of the slice, not the actual entry
            stop = start + data[start:].find(ASCII_END_BLOCK.encode('utf-8'))
            result = data[start:stop].strip()

            # convert to str for pretty printing
            result = result.decode('utf-8')
            print('{}\n{}\n{}'.format(ASCII_START_BLOCK, result, ASCII_END_BLOCK))
            return
    except IOError:
        print("[-] No database was found, you may create one with --addcreds.")
        return


def addCreds(args):
    '''
    Add credentials to database
    '''
    print_header()
    title = args.title
    user = args.user
    password = args.password

    IV = CONFIG['IV']
    key = getpass.getpass(PASS_PROMPT)

    database = os.path.expanduser(CONFIG['database'])
    database = os.path.abspath(database)

    if title == "default":
        print("[-] You need to specify a title (--title).")
        return
    if user == "default":
        print("[-] You need to specify a username (--user).")
        return
    if password == "default":
        print("[-] You need to specify a password (--pass).")
        return
    try:
        with open(database, "rb") as f:
            file_db = f.read()
            data = CBC_decrypt(IV, key, file_db)
            #print('decrypted:\n{}\n==================='.format(data))
            shadow_data = data.replace(b"\n", b"")
            #print(type(shadow_data))
            for i in shadow_data:
                c = chr(i)
                if c not in allowed:
                    #print(data)
                    #print(i)
                    print('{} is not allowed, aborting!'.format(c))
                    print("[-] The key you provided seems to be invalid. Aborting.")
                    return
        entry = '\n{}\nTitle: {}\nUsername: {}\nPassword: {}\n{}'.format(ASCII_START_BLOCK, title, user, password, ASCII_END_BLOCK)
        data += entry.encode('utf-8')

        # data needs to be a string for CBC_encrypt
        data = data.decode('utf-8')

        with open(database, "wb") as f:
            f.write(CBC_encrypt(IV, key, data))
        print("[+] Credentials added.")
        return
    except FileNotFoundError:
        print('[+] Database was not found, creating it now.\n'
              '[!] DO NOT forget your key or else the data cannot be queried nor retrieved.')
        with open(database, "ab+") as f:
            data = '\n{}\nTitle: {}\nUsername: {}\nPassword: {}\n{}'.format(ASCII_START_BLOCK, title, user, password, ASCII_END_BLOCK)
            #data = "\n---------------\nTitle: " + title + "\nUsername: " + user + "\nPassword: " + password + "\n------END------"
            enc_bytes = CBC_encrypt(IV, key, data)

            f.write(enc_bytes)
            print('[+] Credentials added.')
            print('[+] Your database is located at {}'.format(database))
            return


def exportdb(args):
    '''
    Export database to one of three formats
    '''
    print_header()

    target = str(args.target).lower()
    key = getpass.getpass(PASS_PROMPT)
    IV = CONFIG['IV']

    database = os.path.expanduser(CONFIG['database'])
    database = os.path.abspath(database)

    with open(database, 'rb') as f:
        data_bytes = f.read()
    cleartext_bytes = CBC_decrypt(IV, key, data_bytes)

    if target == 'clipboard':
        # TODO: Check if xclip is actually installed
        # xclip must be installed for this to work
        paste_command = 'cat - | xclip -selection clipboard -in'
        pipe = Popen(paste_command, shell=True, stdin=PIPE)

        # End of Transmission escape code (^D)
        # ASCII: 04
        eot = b'\x04'

        output = pipe.communicate(cleartext_bytes + eot)
        print('[+] Database copied to clipboard.')
    elif target == 'stdout':
        print(cleartext_bytes.decode('utf-8'))
    elif target == 'file':
        if 'path' not in args:
            print('[!] You must specify a path to save the exported file.')
            return
        path = args.path

        # Bugfix for expanding path
        if '~' in path:
            path = os.path.expanduser(path)
        path = os.path.abspath(path)

        if os.path.exists(path):
            print()
            print('[!] WARNING! File exists: {}'.format(path))
            response = input('Overwrite file? [y/N] ')

            if response.lower().strip() != 'y':
                print('[!] Quitting. File not written.')
                return
        try:
            os.remove(path)
            with open(path, "wb") as f:
                f.write(cleartext_bytes)
                print('[+] File was exported successfully.')
                print('Exported file is: {}.'.format(path))
                return
        except IOError:
            print('[-] Unable to find the specified file for decryption.')
            return


if __name__ == "__main__":
    main()
