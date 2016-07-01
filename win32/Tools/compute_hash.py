#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
if sys.version_info.major < 3: print("[-] You need Python 3."); sys.exit(255)

#############################################################################
# Code.                                                                     #
#############################################################################

def ROR(x, n):
    mask = (2**n) - 1
    mask_bits = x & mask
    return (x >> n) | (mask_bits << (32 - n))

def compute_hash(name):
    hash = 0
    for i in name:
        hash = ROR(hash, 0xd)
        hash += ord(i)

    return hash


#############################################################################
# Main.                                                                     #
#############################################################################

def Usage(argv):
    print("Usage: {0}".format(argv))
    sys.exit(255)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        Usage(sys.argv[0])

    print("{0}: 0x{1:08x}".format(sys.argv[1], compute_hash(sys.argv[1])))

    sys.exit(0)
