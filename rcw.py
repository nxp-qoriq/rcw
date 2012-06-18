#!/usr/bin/python

# rcw.py -- compiles an RCW source file into an PBL/RCW binary

# Copyright 2011 Freescale Semiconductor, Inc.
# Author: Timur Tabi <timur@freescale.com>

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#     * Neither the name of Freescale Semiconductor nor the
#     names of its contributors may be used to endorse or promote products
#     derived from this software without specific prior written permission.

# This software is provided by Freescale Semiconductor "as is" and any
# express or implied warranties, including, but not limited to, the implied
# warranties of merchantability and fitness for a particular purpose are
# disclaimed. In no event shall Freescale Semiconductor be liable for any
# direct, indirect, incidental, special, exemplary, or consequential damages
# (including, but not limited to, procurement of substitute goods or services;
# loss of use, data, or profits; or business interruption) however caused and
# on any theory of liability, whether in contract, strict liability, or tort
# (including negligence or otherwise) arising in any way out of the use of
# this software, even if advised of the possibility of such damage.

# This program compiles an RCW "source file" into a binary image, with or
# without a PBL header.  The syntax of the source file is very simple.  These
# are the only constructs supported:
#
# 1. A bit field definition.  Bit fields are defined in the format XXX[b:e],
# where XXX is the name of the field (only letters, numbers, and an underscore
# are allowed), 'b' is the starting bit position, and 'e' is the ending bit
# position.
#
# 2. A value assigned to a bit field.  Assignments are defined in the format
# XXX=v, where XXX is the name of the field (which must have been previously
# defined), and 'v' is the numeric value assigned to that field.
#
# 3. A variable, which begins with a % symbol.  Any variable can by created, and
# it can be assigned any string.  However, specific variables have pre-defined
# meanings.  Variables are used to define parts of the RCW or PBL that cannot
# be defined by a symbol assignment.
#
# Comments are marked with the pipe symbol "|".  All whitespace is removed
# before the file is parsed.
#
# This program is provided as an informal tool for evaluation purposes only.
# It is not supported.  Please contact the author directly with any questions.

import os
import re
import sys
import struct
import binascii
import itertools
import subprocess

from optparse import OptionParser, OptionGroup

class ordered_dict(dict):
    def __init__(self, *args, **kwargs):
        dict.__init__(self, *args, **kwargs)
        self._order = self.keys()

    def __setitem__(self, key, value):
        dict.__setitem__(self, key, value)
        if key in self._order:
            self._order.remove(key)
        self._order.append(key)

    def __delitem__(self, key):
        dict.__delitem__(self, key)
        self._order.remove(key)

    def order(self):
        return self._order[:]

    def ordered_items(self):
        return [(key,self[key]) for key in self._order]

# Python's binascii.crc32() function uses a different algorithm to calculate
# the CRC, so we need to do it manually.  The polynomial value is 0x04c11db7.
# Python integers can be larger than 32 bits, so we have to "& 0xffffffff"
# to keep the value within a 32-bit range.  The CRC algorithm depends on this.
# Otherwise, some calculations may overflow.
def crc32(data):
    # Calculate the CRC table
    table = []
    for i in range(256):
        mask = i << 24
        for j in range(8):
            if mask & 0x80000000:
                mask = (mask << 1) ^ 0x04c11db7;
            else:
                mask <<= 1;
        table.append(mask & 0xffffffff)

    crc = 0xffffffff
    for i in data:
        crc = (crc << 8) ^ table[(crc >> 24) ^ ord(i)]
        crc = crc & 0xffffffff

    return crc

def command_line():
    global options, args

    parser = OptionParser(usage='usage: %prog [options]',
        description='This script reads an RCW source file and generates an '
            'RCW bin file.')

    parser.add_option('-i', dest='input', help='input filename.  '
        'Defaults to stdin if not specified')

    parser.add_option('-o', dest='output', help='output filename.  '
        'Defaults to stdout if not specified')

    parser.add_option('--no-pbl', dest='pbl',
        help='do not generate the PBL preamble and end-command',
        action='store_false', default=True)

    parser.add_option('-r', dest='reverse', help='generate a source file from a binary.  '
        'Must also specify --rcw.  --pbl option is ignored.', action='store_true', default=False)

    parser.add_option('-I', dest='include', help='include path.  '
        'Can be specified multiple times', action="append")

    parser.add_option('--rcw', dest='rcw', help='RCW defintion filename.  '
        'Used only if -r is specified.')

    (options, args) = parser.parse_args()

    if options.input:
        options.input = os.path.expanduser(options.input)
    else:
        options.input = '/dev/stdin'

    if options.output:
        options.output = os.path.expanduser(options.output)
    else:
        options.output = '/dev/stdout'

    if options.reverse and not options.rcw:
        print "Error: -r option requires --rcw"
        sys.exit(1)

def check_for_overlap(name, begin, end):
    global symbols

    if name in symbols:
        print 'Error: Duplicate bitfield definition for', name
        return

    # Iterate over the list of symbols that have already been defined
    for n, [b, e] in symbols.iteritems():
        # check if either 'begin' or 'end' is inside an bitfield range
        if (b <= begin <= e) or (b <= end <= e):
            print 'Error: Bitfield', name, 'overlaps with', n

def parse_source_file(source):
    global symbols
    global assignments
    global vars

    symbols = ordered_dict()

    for l in source:
        l = ''.join(l.split()) # Remove all whitespace

        if not len(l):  # Skip blank or comment-only lines
            continue

        # Is it an identifier?  %var=value
        m = re.search(r'%([a-zA-Z]+)=(.+)', l)
        if m:
            identifier, value = m.groups()
            vars[identifier] = value
            continue

        # Is it a single field definition?  NAME[position]
        m = re.search(r'([A-Z0-9_]+)\[([0-9a-zA-Z]+)]', l)
        if m:
            name, position = m.groups()
            position = int(position, 0)
            check_for_overlap(name, position, position)

            symbols[name] = [position, position]
            continue

        # Is it a ranged field definition?  NAME[begin:end]
        m = re.search(r'([A-Z0-9_]+)\[([0-9a-zA-Z]+):([0-9a-zA-Z]+)\]', l)
        if m:
            (name, begin, end) = m.groups()
            begin = int(begin, 0)
            end = int(end, 0)
            check_for_overlap(name, begin, end)
            symbols[name] = [begin, end]
            continue

        # Is it a field assignment? NAME=value
        m = re.search(r'([A-Z0-9_]+)=([0-9a-zA-Z]+)', l)
        if m:
            (name, value) = m.groups()
            value = int(value, 0)
            if not name in symbols:
                print 'Error: Unknown bitfield', name
            else:
                if name in assignments:
                    print 'Error: Duplicate assignement for bitfield', name
                assignments[name] = value
            continue

# Run the C preprocessor on the given source code.  This allows you to include
# C macros and #include statements in the source file.
def read_source_file(filename):
    global options

    i = ['-I', '.']     # Always look in the current directory
    if options.include:
        for x in options.include:
            i.extend(['-I', x])
    p = subprocess.Popen(['gcc', '-E', '-x', 'c', '-P'] + i + [filename],
        shell=False, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ret = p.communicate()
    if p.returncode != 0:
        print ret[1],
        return None

    return ret[0].splitlines()

# Check for specific variables
def check_vars():
    global vars
    global options

    if not 'size' in vars:
        print 'Error: "%size" variable must be specified'
        sys.exit(1)

    if options.pbl:
        # If we want the PBL header/footer, the vars for those must be defined
        if not vars['sysaddr']:
            print 'Error: PBL format requires %sysaddr to be defined'
            sys.exit(1)

def create_binary():
    global symbols
    global assignments
    global vars
    global options

    # Create the RCW data.  We encode it into 'bits' as a giant (2^size)-bit number
    size = int(vars['size'], 0)
    bits = 0L

    for n, v in assignments.iteritems():
        # n = name of symbol
        # v = value to assign
        b, e = symbols[n]   # First bit and last bit
        s = 1 + e - b       # number of bits in field

        # Make sure it's not too large
        if v >= (1 << s):
            print 'Error: Value', v, 'is too large for field', n
            continue

        # Set the bits.  We assume that bits [b:e] are already zero.  They can be
        # non-zero only if we have overlapping bitfield definitions, which we
        # already report as an error.
        bits += v << ((size - 1) - e)

    # Generate the binary.  First, apply the preamble, if requested
    binary = ''
    if options.pbl:
        length_byte = (((size / 8) & 63) << 1) | 1
        binary = binascii.unhexlify('aa55aa55') + chr(length_byte) + binascii.unhexlify(vars['sysaddr'])

    # Then convert 'bits' into an array of bytes
    for i in range(size - 8, -1, -8):
        binary += chr(bits >> i & 0xff)

    # Add the end-command
    if options.pbl:
        binary += binascii.unhexlify('08138040')

        # Calculate and add the CRC
        crc = crc32(binary) & 0xffffffff
        binary += struct.pack('>L', crc)

    return binary

# Create a source file from a binary and
def create_source():
    global symbols
    global vars
    global options

    f = open(options.input, 'rb')
    binary = f.read()
    f.close()

    size = int(vars['size'], 0)

    # If the binary is larger than the RCW, then we assume that it has a
    # preamble and an end-command, so remove them.  This is bit hackish,
    # but it'll work for now.
    if len(binary) > (size / 8):
        preamble = binary[0:8]

        # Convert the binary into a large integer
        rcw = binary[8:8 + (size / 8)]
        bits = int(binascii.hexlify(rcw), 16)
    else:
        bits = int(binascii.hexlify(binary), 16)

    # Loop over all the known symbols
    source = ''
    for n, [b, e] in symbols.ordered_items():
        s = 1 + e - b       # number of bits in field

        mask = ((1 << s) - 1)
        v = (bits >> ((size - 1) - e)) & mask
        if v:
            source += "%s=%u\n" % (n, v)

    return source

if (sys.version_info < (2,6)) or (sys.version_info >= (3,0)):
    print 'Only Python versions 2.6 or 2.7 are supported.'
    sys.exit(1)

# Make all 'print' statements output to stderr instead of stdout
sys.stdout = sys.stderr

command_line()

symbols = {}
assignments = {}
vars = {}

if options.reverse:
    source = read_source_file(options.rcw)
    if not source:
        sys.exit(1)
    parse_source_file(source)

    f = open(options.output, 'w')
    f.write(create_source())
    f.close()
else:
    source = read_source_file(options.input)
    if not source:
        sys.exit(1)
    parse_source_file(source)
    check_vars()

    # Write it all to the output file
    f = open(options.output, 'wb')
    f.write(create_binary())
    f.close()
