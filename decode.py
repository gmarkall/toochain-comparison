#!/usr/bin/env python3

# Copyright (C) 2016 Embecosm Limited
# Contributor Graham Markall <graham.markall@embecosm.com>

# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation; either version 3 of the License, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.

# You should have received a copy of the GNU General Public License along
# with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys

opcode = int(sys.argv[1], 16)
binary = format(opcode, '032b')
maj_op = opcode >> 27 & 31
min_op = opcode >> 16 & 63
src1 = (opcode >> 24 & 7) + (opcode >> 9 & 56)
src2 = (opcode >> 6 & 63)
dst = (opcode & 63)
f = (opcode >> 15 & 1)
p = (opcode >> 22 & 3)

print("Opcode       is 0x%X\n" % opcode)
print("Binary       is %s\n" % binary)
print("Major opcode is 0x%X\n" % maj_op)
print("Minor opcode is 0x%X\n" % min_op)
print("SRC1         is 0x%X, %s\n" % (src1, src1))
print("SRC2         is 0x%X, %s\n" % (src2, src2))
print("DST          is 0x%x, %s\n" % (dst, dst))
print("Flags        is %s\n" % f)
print("P            is %s\n" % p)
