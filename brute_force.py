# File: brute_force.py
# Author: Brandon Hammel
# Class: CS 177, Spring 2016
# Assignment: Homework 3, Task 3

# Performs a basic brute-force search attack when supplied with a
# password file containing the salts and hashes of passwords, and
# the length to be brute-forced.

import argparse
import crypt
import itertools
import sys


def cmp_pass(crypt_pass, word, salt, user):
    crypt_word = crypt.crypt(word, salt)
    if (crypt_word == crypt_pass):
        print("[+] Found Password for " + user + ": " + word)
    return


def test_pass(crypt_pass, user, length):
    salt = ''
    if '$' in crypt_pass:
        # Hashed using $1$ (MD5), $5$ (SHA-256), or $6$ (SHA-512).
        # Salt is everything up to last '$'.
        index = crypt_pass.rfind('$')
        salt = crypt_pass[0:index + 1]
    else:
        # Hashed using traditional DES. First two characters are salt.
        salt = crypt_pass[0:2]
    for word in itertools.product('abcdefghijklmnopqrstuvwxyz0123456789', repeat=length):
        cmp_pass(crypt_pass, ''.join(word), salt, user)
    return


def main():
    parser = argparse.ArgumentParser(description='Brute-force search attack.',
                                     prog='brute_force')
    parser.add_argument('-f', '--file',
                        required=True,
                        help='specify password file')
    parser.add_argument('-l', '--length',
                        type=int, required=True,
                        help='specify length of password')
    args = parser.parse_args()
    pass_file = open(args.file, 'r')
    for line in pass_file.readlines():
        if ':' in line:
            user = line.split(':')[0]
            crypt_pass = line.split(':')[1].strip()
            print("[*] Cracking password for: " + user)
            test_pass(crypt_pass, user, args.length)
    return


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
