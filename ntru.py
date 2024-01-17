#!/usr/bin/env python3
"""NTRU v0.1

Usage:
  ntru.py [options] enc PUB_KEY_FILE [FILE]
  ntru.py [options] dec PRIV_KEY_FILE [FILE]
  ntru.py (-h | --help)
  ntru.py --version

Options:
  -b, --block        Interpret input/output as block stream.
  -i, --poly-input   Interpret input as polynomial represented by integer array.
  -o, --poly-output  Interpret output as polynomial represented by integer array.
  -h, --help         Show this screen.
  --version          Show version.
  -d, --debug        Debug mode.
  -v, --verbose      Verbose mode.
"""

from docopt import docopt
from ntru.ntrucipher import NtruCipher
from ntru.mathutils import random_poly
from sympy.abc import x
from sympy import ZZ, Poly
from padding.padding import *
import numpy as np
import sys
import logging
import math
import base64

log = logging.getLogger("ntru")

debug = False
verbose = False

# Embedded Keys (Replace with actual key values)
EMBEDDED_PRIVATE_KEY = {
    "N": 167,  # Replace with actual value
    "p": 3,    # Replace with actual value
    "q": 128,  # Replace with actual value
    "f": [0, -1, -1, -1, -1, 0, 0, 0, -1, 1, 0, 1, -1, -1, 0, -1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1,
          1, -1, 0, -1, 1, -1, -1, -1, 0, 1, 1, 1, -1, 0, 0, -1, 1, 1, 1, -1, 1, 0, 1, 0, -1, 0, 1, -1, 0, -1, -1,
          -1, -1, 0, 0, -1, -1, -1, -1, 1, 0, 0, 1, 0, 1, -1, -1, -1, 0, 1, -1, -1, 0, 1, -1, 1, 1, 1, 1, 1, 0, 1,
          1, 0, -1, 0, 1, 0, 0, -1, -1, -1, 0, 1, 0, -1, 0, 0, 0, -1, -1, 1, 1, 0, -1, 1, -1, 1, 1, -1, 1, 1, 0, 1,
          1, 1, 1, -1, -1, 0, -1, 0, 0, 0, -1, 0, 1, -1, 1, 1, 1, -1, 1, 0, 0, 0, 1, 0, 1, 0, -1, -1, 1, -1, -1,
          0, 1, 1, 0, -1, 0, 0, -1],  # Replace with actual array
    "f_p": [1, 0, 1, 1, -1, 0, 1, -1, -1, -1, -1, 0, 0, -1, 0, -1, 0, -1, 0, 0, -1, 0, -1, 1, 0, -1, 0, -1, -1, 1,
            -1, 0, 0, 0, 0, -1, 1, 1, 1, 1, 0, 0, -1, 1, 1, 0, 0, -1, 0, 1, 1, 1, 0, -1, 0, -1, 1, 1, 0, 0, -1, -1, 0,
            1, 0, 1, 1, -1, 1, 1, 1, 0, 0, 0, 1, 0, 1, -1, -1, 1, 0, 0, 0, 1, 1, 1, -1, 0, -1, -1, 0, 1, -1, -1, -1,
            -1, 0, 1, 0, 0, 1, 1, -1, 1, 1, 1, 0, 1, 1, 0, 0, -1, 0, 1, -1, -1, 0, 0, 0, 0, -1, -1, -1, -1, -1, 0,
            1, 1, 1, 0, 1, 1, 0, -1, 0, -1, 0, 1, 1, 0, -1, -1, 1, 0, -1, -1, 1, -1, -1, 0, 0, 0, 0, -1, -1, -1, -1,
            0, -1, -1, 1, 0, 1, 1, -1, 0, -1]  # Replace with actual array
}

EMBEDDED_PUBLIC_KEY = {
    "N": 167,  # Replace with actual value
    "p": 3,    # Replace with actual value
    "q": 128,  # Replace with actual value
    "h": [-23, 57, -25, 62, 36, 64, -4, -22, -62, -46, -50, 40, -33, 62, 39, 34, -50, 51, -28, -43, -58,
          14, 42, -38, -15, -1, -56, -20, -50, -41, -22, -9, 18, -15, -56, -22, 19, 33, -8, -8, -23,
          -37, 60, -50, 30, -31, -30, 15, 54, -15, 50, -19, -42, 0, 9, 14, -17, -7, -17, -59, -32, -28,
          -16, 55, 21, 40, -60, -9, -50, 12, 57, 64, -31, 58, 2, 26, -53, -33, -29, 5, -12, 20, -49, -40,
          20, 32, -21, 30, 9, 8, 16, -41, -30, -10, 57, 57, 11, -22, -11, -20, -53, -16, -42, 11, 13,
          -20, 18, -4, 64, 55, -52, -10, 39, 32, 45, 54, -51, 26, -29, 57, 0, -9, -8, 7, -62, 13, -37, 51,
          36, 53, 56, 6, -24, -10, -21, -5, 38, 8, 36, 61, -3, 53, -18, 0, 48, 34, -53, 10, 52, -19, -48,
          61, -31, -18, 61, 38, -63, 11, 10, 44, -9, -41, -1, -36, 30, 1, 35]  # Replace with actual array
}

def encrypt(input_arr, bin_output=False, block=False):    
    # Use embedded public key
    pub_key = EMBEDDED_PUBLIC_KEY
    ntru = NtruCipher(int(pub_key['N']), int(pub_key['p']), int(pub_key['q']))
    ntru.h_poly = Poly(pub_key['h'].astype(np.int)[::-1], x).set_domain(ZZ)
    if not block:
        if ntru.N < len(input_arr):
            raise Exception("Input is too large for current N")
        output = (ntru.encrypt(Poly(input_arr[::-1], x).set_domain(ZZ),
                               random_poly(ntru.N, int(math.sqrt(ntru.q)))).all_coeffs()[::-1])
    else:
        input_arr = padding_encode(input_arr, ntru.N)
        input_arr = input_arr.reshape((-1, ntru.N))
        output = np.array([])
        block_count = input_arr.shape[0]
        for i, b in enumerate(input_arr, start=1):
            log.info("Processing block {} out of {}".format(i, block_count))
            next_output = (ntru.encrypt(Poly(b[::-1], x).set_domain(ZZ),
                                        random_poly(ntru.N, int(math.sqrt(ntru.q)))).all_coeffs()[::-1])
            if len(next_output) < ntru.N:
                next_output = np.pad(next_output, (0, ntru.N - len(next_output)), 'constant')
            output = np.concatenate((output, next_output))

    if bin_output:
        k = int(math.log2(ntru.q))
        output = [[0 if c == '0' else 1 for c in np.binary_repr(n, width=k)] for n in output]
    return np.array(output).flatten()

def decrypt(input_arr, bin_input=False, block=False):
    # Use embedded private key
    priv_key = EMBEDDED_PRIVATE_KEY
    ntru = NtruCipher(int(priv_key['N']), int(priv_key['p']), int(priv_key['q']))
    ntru.f_poly = Poly(priv_key['f'].astype(np.int)[::-1], x).set_domain(ZZ)
    ntru.f_p_poly = Poly(priv_key['f_p'].astype(np.int)[::-1], x).set_domain(ZZ)

    if bin_input:
        k = int(math.log2(ntru.q))
        pad = k - len(input_arr) % k
        if pad == k:
            pad = 0
        input_arr = np.array([int("".join(n.astype(str)), 2) for n in
                              np.pad(np.array(input_arr), (0, pad), 'constant').reshape((-1, k))])
    if not block:
        if ntru.N < len(input_arr):
            raise Exception("Input is too large for current N")
        log.info("POLYNOMIAL DEGREE: {}".format(max(0, len(input_arr) - 1)))
        return ntru.decrypt(Poly(input_arr[::-1], x).set_domain(ZZ)).all_coeffs()[::-1]

    input_arr = input_arr.reshape((-1, ntru.N))
    output = np.array([])
    block_count = input_arr.shape[0]
    for i, b in enumerate(input_arr, start=1):
        log.info("Processing block {} out of {}".format(i, block_count))
        next_output = ntru.decrypt(Poly(b[::-1], x).set_domain(ZZ)).all_coeffs()[::-1]
        if len(next_output) < ntru.N:
            next_output = np.pad(next_output, (0, ntru.N - len(next_output)), 'constant')
        output = np.concatenate((output, next_output))
    return padding_decode(output, ntru.N)

def main():
    args = docopt(__doc__, version='NTRU v0.1')
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG if args['--debug'] else logging.INFO if args['--verbose'] else logging.WARN)
    root.addHandler(ch)

    log.debug(args)
    poly_input = bool(args['--poly-input'])
    poly_output = bool(args['--poly-output'])
    block = bool(args['--block'])

    input_data = None
    if args['FILE'] is None or args['FILE'] == '-':
        input_data = sys.stdin.read() if poly_input else sys.stdin.buffer.read()
    else:
        with open(args['FILE'], 'rb') as file:
            input_data = file.read()

    if not poly_input:
        try:
            input_data = base64.b64decode(input_data)
        except Exception as e:
            log.error(f"Error decoding Base64 data: {e}")
            sys.exit(1)

    if poly_input:
        input_arr = np.array(eval(input_data))
    else:
        input_arr = np.unpackbits(np.frombuffer(input_data, dtype=np.uint8))
    input_arr = np.trim_zeros(input_arr, 'b')

    # Initialize output variable
    output = None

    # Perform encryption or decryption
    if args['enc']:
        output = encrypt(args['PUB_KEY_FILE'], input_arr, bin_output=not poly_output, block=block)
    elif args['dec']:
        output = decrypt(args['PRIV_KEY_FILE'], input_arr, bin_input=not poly_input, block=block)

    # Handle output
    if output is not None:
        if poly_output:
            print(list(output.astype(np.int)))
        else:
            output_data = np.packbits(np.array(output).astype(np.int)).tobytes()
            output_data_base64 = base64.b64encode(output_data)
            sys.stdout.buffer.write(output_data_base64)
    else:
        log.error("No output generated from NTRU operation.")

if __name__ == '__main__':
    main()
