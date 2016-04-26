# File: mangling_attack.py
# Author: Brandon Hammel
# Class: CS 177, Spring 2016
# Assignment: Homework 3, Task 3

# Performs a username mangling attack when supplied with a password
# file containing the salts and hashes of passwords.

import argparse
import crypt
import itertools
import sys


def cmp_pass(crypt_pass, word, salt, user):
    crypt_word = crypt.crypt(word, salt)
    if (crypt_word == crypt_pass):
        print("[+] Found Password for " + user + ": " + word)
    return


def test_pass(crypt_pass, user):
    salt = ''
    if '$' in crypt_pass:
        # Hashed using $1$ (MD5), $5$ (SHA-256), or $6$ (SHA-512).
        # Salt is everything up to last '$'.
        index = crypt_pass.rfind('$')
        salt = crypt_pass[0:index + 1]
    else:
        # Hashed using traditional DES. First two characters are salt.
        salt = crypt_pass[0:2]
    # Try reversed username
    cmp_pass(crypt_pass, user[::-1], salt, user)
    # Add 's' to username
    cmp_pass(crypt_pass, user + 's', salt, user)
    # Add combinations of digits to end of username
    for num in itertools.product('0123456789', repeat=4):
        cmp_pass(crypt_pass, user + ''.join(num), salt, user)
    # Try all possible capitalizations of username
    lower_user = user.lower()
    for p in itertools.product(*[(0, 1)] * len(lower_user)):
        cmp_pass(crypt_pass, ''.join(c.upper() if t else c for t, c in izip(p, lower_user)), salt, user)
    return


def main():
    parser = argparse.ArgumentParser(description='Username mangling attack.',
                                     prog='mangling_attack')
    parser.add_argument('-f', '--file',
                        required=True,
                        help='specify password file')
    args = parser.parse_args()
    pass_file = open(args.file, 'r')
    for line in pass_file.readlines():
        if ':' in line:
            user = line.split(':')[0]
            crypt_pass = line.split(':')[1].strip()
            print("[*] Cracking password for: " + user)
            test_pass(crypt_pass, user)
    return


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
