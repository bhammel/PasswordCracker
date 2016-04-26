# File: dictionary_attack.py
# Author: Brandon Hammel
# Class: CS 177, Spring 2016
# Assignment: Homework 3, Task 3

# Performs a basic brute-force dictionary attack when supplied with
# a password file containing the salts and hashes of passwords, and
# a dictionary file. An optional flag can be used to apply leet
# speak rules to each word in the dictionary file.

import argparse
import crypt
import sys


def cmp_pass(crypt_pass, word, salt, user):
    crypt_word = crypt.crypt(word, salt)
    if (crypt_word == crypt_pass):
        print("[+] Found Password for " + user + ": " + word)
    return


def test_pass(crypt_pass, dname, user, use_leet):
    dict_file = open(dname, 'r')
    salt = ''
    if '$' in crypt_pass:
        # Hashed using $1$ (MD5), $5$ (SHA-256), or $6$ (SHA-512).
        # Salt is everything up to last '$'.
        index = crypt_pass.rfind('$')
        salt = crypt_pass[0:index + 1]
    else:
        # Hashed using traditional DES. First two characters are salt.
        salt = crypt_pass[0:2]
    for word in dict_file.readlines():
        word = word.strip()
        if use_leet:
            word = word.replace('a', '4').replace('e', '3').replace('l', '1').replace('o', '0').replace('t', '7')
        # Only check words of length 6 or higher.
        if (len(word) < 6):
            continue
        cmp_pass(crypt_pass, word, salt, user)
    return


def main():
    parser = argparse.ArgumentParser(description='Brute-force dictionary attack.',
                                     prog='dictionary_attack')
    parser.add_argument('-f', '--file',
                        required=True,
                        help='specify password file')
    parser.add_argument('-d', '--dict',
                        required=True,
                        help='specify dictionary file')
    parser.add_argument('-l', '--leet',
                        required=False, action='store_true',
                        help='use leet speak rules')
    args = parser.parse_args()
    pass_file = open(args.file, 'r')
    for line in pass_file.readlines():
        if ':' in line:
            user = line.split(':')[0]
            crypt_pass = line.split(':')[1].strip()
            print("[*] Cracking password for: " + user)
            test_pass(crypt_pass, args.dict, user, args.leet)
    return


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
