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

class RegisterArgument(object):
    def __init__(self, name):
        if name[0] != 'r' and name != 'ilink1' and name != 'ilink2':
            raise ValueError('Bad register name %s' % s)
        self._name = name

    def __repr__(self):
        return 'RegisterArgument(%s)' % self._name

    def __str__(self):
        return self._name

    def __eq__(self, other):
        try:
            return self._name == other._name
        except AttributeError:
            return False

    @property
    def name(self):
        return self._name

class ImmediateArgument(object):
    def __init__(self, value):
        self._value = value

    def __repr__(self):
        return 'ImmediateArgument(%s)' % self._value

    def __str__(self):
        return '%s' % self._value

    def __eq__(self, other):
        try:
            return self._value == other._value
        except AttributeError:
            return False

    @property
    def value(self):
        return self._value

class IndirectArgument(object):
    def __init__(self, arg):
        self._arg = parse_arg(arg)

    def __repr__(self):
        return 'IndirectArgument(%s)' % repr(self._arg)

    def __str__(self):
        return '[%s]' % self._arg

    def __eq__(self, other):
        try:
            return self._arg == other._arg
        except AttributeError:
            return False

class AsmInstr(object):
    def __init__(self, s):
        parts = s.split()
        nparts = len(parts)

        # Parse address of instruction
        self._addr = int(parts[0][:-1], 16)

        # Next comes the hex encoding of the instruction. This is either 2, 4,
        # or 8 sets of hex digits. After the hex digits there are then either
        # one or two more fields, the mnemonic and its arguments. Working out
        # which is which is a little fiddly especially considering the
        # differences between the old and new output formats - however, for a
        # given number of parts there is only one possible combination so we can
        # use a mapping to determine which field is which.
        #
        # nfields_to_type_indices is a mapping that given the number of parts,
        # provides the indices of each of those parts in tuple form:
        #
        # (hex_indices, mnemonic_index, arg_index)
        #
        # * Multiple hex indices are stored as a tuple
        # * mnemonic_index is always a positive integer
        # * If there are no arguments, arg_index is -1
        #
        nfields_to_type_indices = {
            # Two hex fields, one mnemonic, and no arguments
            4: ((1, 2), 3, -1),
            # Two hex fields, one mnemonic, and some arguments
            5: ((1, 2,), 3, 4),
            # There must be four hex fields, one mnemonic, and no arguments
            6: ((1, 2, 3, 4), 5, -1),
            # There must be four hex fields, one mnemonic, and some arguments
            7: ((1, 2, 3, 4), 5, 6),
            # There must be eight hex fields, one mnemonic, and no arguments
            10: ((1, 2, 3, 4, 5, 6, 7, 8), 9, -1),
            # There must be eight hex fields, one mnemonic, and some arguments
            11: ((1, 2, 3, 4, 5, 6, 7, 8), 9, 10)
        }

        try:
            hex_indices, mnemonic_index, arg_index = \
                nfields_to_type_indices[nparts]
        except KeyError:
            raise ValueError("Can't parse assembly line with %s parts" % nparts)

        # Parse hex encoding of instruction. Done by concatenating all hex
        # digits. We check that a token is hex by trying to parse it as hex.
        hexdigits = ''
        for i in hex_indices:
            try:
                current_token = parts[i]
                int(current_token, 16)
                hexdigits += current_token
            except ValueError:
                # Those were not hex digits!
                raise ValueError("Unexpected non-hex digit %s. Perhaps "
                    "nfields_to_type indices is incorrect?" % current_token)
        self._encoding = hexdigits

        # Next is the mnemonic
        self._mnemonic = parts[mnemonic_index]

        # Then the arguments. If none, use an empty arg list
        if arg_index == -1:
            self._args = []
        else:
            self._args = parse_args(parts[arg_index])

    def __str__(self):
        return '%s %s %s' % (self._addr, self._encoding, self.assembly)

    def __eq__(self, other):
        try:
            return (self._addr == other._addr
                and self._encoding == other._encoding
                and self._mnemonic == other._mnemonic
                and self._args == other._args)
        except AttributeError:
            return False

    @property
    def addr(self):
        return self._addr

    @property
    def encoding(self):
        return self._encoding

    @property
    def mnemonic(self):
        return self._mnemonic

    @property
    def args(self):
        return self._args

    @property
    def assembly(self):
        '''
        Return a representation of the instruction as written in assembly
        language, without the address or encoding.
        '''
        if self._args:
            return '%s %s' % (self._mnemonic,
                ','.join([ str(arg) for arg in self._args]))
        else:
            return self._mnemonic

class Relocation(object):
    '''
    Represents a relocation. There are some differences between the old and new
    relocation formats. In order to make it easy to compare old and new
    relocations, we normalise them to the new format when constructing a
    Relocation object from an old assembly dump.
    '''
    def __init__(self, s):
        parts = s.split()
        nparts = len(parts)
        if nparts != 3:
            raise ValueError("Can't handle relocation with %s parts" % nparts)


        # Parse relocation type - only relocations to 0x57f0000 + 16-bit offset
        # supported for now.
        ty = parts[1]
        if ty == 'R_ARC_NPS_CMEM16':
            old = False
        elif ty == 'R_ARC_16_CCM':
            old = True
        else:
            raise ValueError("Unsupported relocation type %s" % ty)

        # Always use the new name for the relocation type
        self._type = 'R_ARC_NPS_CMEM16'

        # Parse address of instruction
        addr = int(parts[0][:-1], 16)
        if old:
            # The old toolchain targets the exact bytes to patch up with the
            # address - the new toolchain targets the beginning of the
            # instruction, two bytes prior. So fix up by subtracting 2 from old
            # offsets.
            addr -=2
        self._addr = addr

        self._symbol = parts[2]

    def __eq__(self, other):
        try:
            return (self._addr == other._addr and
                self._type == other._type and self._symbol == other._symbol)
        except AttributeError:
            return False

    def __str__(self):
        return '%s: %s %s' % (self._addr, self._type, self._symbol)

def same_addr_and_encoding(a, b):
    '''
    Check whether two instructions have the same address and encoding.
    '''
    return a.addr == b.addr and a.encoding == b.encoding

# Ad-hoc rules about instructions that are equivalent but decode to different
# mnemonics or registers names, etc.
def semantic_equivalent(a, b):
    # Things with different addresses or encodings are not semantically
    # equivalent so no point going any further.
    if not same_addr_and_encoding(a, b):
        return False

    # Test 1: nop is the same as mov 0, 0
    if ((a.assembly == 'nop' or b.assembly == 'nop') and
            (a.assembly == 'mov 0,0' or b.assembly == 'mov 0,0')):
        return True

    # Test 2: r30 is ilink2 (Level 2 interrupt link register)
    if (a.mnemonic == b.mnemonic):
        same_registers = True
        for arg_a, arg_b in zip(a.args, b.args):
            # No need to check arguments that are the same
            if arg_a == arg_b:
                continue

            # If the arguments are not register arguments, then this check
            # doesn't apply, and they're not semantically equivalent
            if not (isinstance(arg_a, RegisterArgument) and
                    isinstance(arg_b, RegisterArgument)):
                same_registers = False
                # No point looking further if we've already determined they're
                # dissimilar arguments
                break

            # Finally, we can check if one register is r30 and the other ilink2
            name_a = arg_a.name
            name_b = arg_b.name
            if not ((name_a == 'r30' or name_b == 'r30') and
                    (name_a == 'ilink2' or name_b == 'ilink2')):
                same_registers = False

        # If we got through the whole register list without finding an
        # unexpected discrepancy then the instructions are equivalent.
        if same_registers:
            return True

    # Test 3: signed vs. unsigned immediates, e.g. -1 in one disassembled output
    # and 4294967295 in another. This test checks for exactly that case since
    # it appears in the output - generalising further will require some work to
    # ensure that the size of immediates in particular instructions is correctly
    # accounted for.
    if (a.mnemonic == b.mnemonic):
        same_immediates = True
        for arg_a, arg_b in zip(a.args, b.args):
            # No need to check arguments that are the same
            if arg_a == arg_b:
                continue

            # If the arguments are not immediate arguments, then this check
            # doesn't apply, and they're not semantically equivalent
            if not (isinstance(arg_a, ImmediateArgument) and
                    isinstance(arg_b, ImmediateArgument)):
                same_immediates = False

            # Finally check if one value is -1 and the other 4294967295
            value_a = arg_a.value
            value_b = arg_b.value
            if not ((value_a == -1 or value_b == -1) and
                    (value_a == 4294967295 or value_b == 4294967295)):
                same_immediates = False

        # If we got through all arguments without finding an unexpected
        # discrepancy then the instructions are equivalent
        if same_immediates:
            return True

    # No semantic equivalence found - give up, they're different instructions.
    return False


def parse_args(argtoken):
    # Arguments are a comma-separated string
    arglist = []
    args = argtoken.split(',')

    for arg in args:
        arglist.append(parse_arg(arg))

    return arglist

def parse_arg(arg):
    # The format of arguments differs between the old and new assemblers, so
    # we put them into a canonical form.

    if arg[0] == 'r' or arg[0] == 'i':
        # Register argument (rN, ilinkN, etc.)
        canonicalised = RegisterArgument(arg)
    elif arg[0:2] == '0x':
        # Hex argument
        try:
            canonicalised = ImmediateArgument(int(arg, 16))
        except ValueError:
            raise ValueError('Invalid hex argument %s' % arg)
    elif arg[0] == '[' and arg[-1] == ']':
        canonicalised = IndirectArgument(arg[1:-1])
    else:
        # Assume argument is a decimal and attempt to parse it
        try:
            canonicalised = ImmediateArgument(int(arg))
        except ValueError:
            raise ValueError('Invalid decimal argument %s' % arg)

    return canonicalised

def parse_dump(dump):
    lines = dump.split('\n')

    # Check there is disassembly of only one section
    disassemblies = []
    for i, line in enumerate(lines):
       if 'Disassembly' in line:
           disassemblies.append((i, line))
    if len(disassemblies) != 1:
        raise RuntimeError("Got %s disassembled sections - expected 1"
            % len(disassemblies))

    # Compute the line number of the first line of disassembled code
    first_dis_line = disassemblies[0][0] + 3
    dis_string = disassemblies[0][1]

    # Check the disassembly is of the text section
    if not 'Disassembly of section .text:' in dis_string:
        raise RuntimeError("Expecting disassembly of text section. Got: %s"
            % dis_string)

    # Parse the disassembly
    parsed = []
    for line in lines[first_dis_line:]:
        # Only parse non-empty lines
        if line.strip() == '':
            continue

        if 'R_ARC_NPS_CMEM16' in line or 'R_ARC_16_CCM' in line:
            p = Relocation(line)
        else:
            p = AsmInstr(line)
        parsed.append(p)

    return parsed

def main():
    parser = make_parser()
    args = parser.parse_args()
    basenames = args.basename

    good_total = 0
    sem_equiv_total = 0
    bad_total = 0

    for basename in basenames:
        print("Comparing %s\n" % basename)

        with open('%s.oldeb.dump' % basename) as f:
            old_dump = f.read()
        with open('%s.neweb.dump' % basename) as f:
            new_dump = f.read()

        good, sem_equiv, bad = compare(old_dump, new_dump, verbose=args.verbose)
        good_total += good
        sem_equiv_total += sem_equiv
        bad_total += bad

        print(" - Good: %s" % good)
        print(" - Same encoding, semantically equivalent disassembly: %s"
            % sem_equiv)
        print(" - Bad: %s\n" % bad)

    print("Summary:\n")
    print("Total Good: %s" % good_total)
    print("Total Same encoding, semantically equivalent disassembly: %s"
        % sem_equiv_total)
    print("Total Bad: %s" % bad_total)

    if bad_total > 0:
        return 1
    else:
        return 0

def compare(old_dump, new_dump, *, verbose=False):
    old_repr = parse_dump(old_dump)
    new_repr = parse_dump(new_dump)
    good = 0
    sem_equiv = 0
    bad = 0
    for old, new in zip(old_repr, new_repr):
        if old == new:
            if verbose:
                print("GOOD:")
                print("| \- Old: %s" % old)
                print("\--- New: %s\n" % new)
            good += 1
        elif semantic_equivalent(old, new):
            print("SEMANTIC EQUIVALENT:")
            print("| \- Old: %s" % old)
            print("\--- New: %s\n" % new)
            sem_equiv += 1
        else:
            print("BAD:")
            print("| \- Old: %s" % old)
            print("\--- New: %s\n" % new)
            bad += 1

    return good, sem_equiv, bad

def make_parser():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('basename', nargs='+',
        help='Base name of files to compare')
    parser.add_argument('-v', '--verbose', help='verbose output',
        action='store_true')
    return parser


if __name__ == '__main__':
    import sys
    sys.exit(main())
