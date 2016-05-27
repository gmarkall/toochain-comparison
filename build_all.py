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

from subprocess import Popen
from warnings import warn
import os

TOPDIR = os.path.abspath(os.path.dirname(__file__))

toolchains = [ 'oldeb', 'neweb' ]
sources = [ 'nps400-%s' % i for i in range(8) ]


toolchain_paths = {
    'oldel': '/home/graham/work/ezchip/devel/install/usr/bin',
    'oldeb': '/home/graham/work/ezchip/devel/install/usr/bin',
    'newel': '/home/graham/work/projects/mellanox/install-el/bin',
    'neweb': '/home/graham/work/projects/mellanox/install-eb/bin',
}


toolchain_prefix = {
    'oldel': 'arceb-mellanox-linux-uclibc',
    'oldeb': 'arceb-mellanox-linux-uclibc',
    'newel': 'arc-elf',
    'neweb': 'arceb-elf',
}


toolchain_args = {
    'oldel': ['-EL'],
    'oldeb': [],
    'newel': ['-mcpu=nps400'],
    'neweb': ['-mcpu=nps400'],
}


def make_env(toolchain):
    e = os.environ.copy()
    e['PATH'] = '%s:%s' % (toolchain_paths[toolchain], os.environ['PATH'])
    return e

error = False

for t in toolchains:
    env = make_env(t)

    for s in sources:
        # Assemble everything
        args = [
            '%s-as' % toolchain_prefix[t],
            '-o', 'out/%s.%s.o' % (s, t),
            'src/%s.s' % s
        ]
        args += toolchain_args[t]
        print("Invoking: %s" % " ".join(args))
        proc = Popen(args, env=env, cwd=TOPDIR)
        retcode = proc.wait()
        if retcode != 0:
            warn("Assembling %s with %s failed with retcode %s"
                % (s, t, retcode))
            error = True

        # Disassemble everything
        args = [
            '%s-objdump' % toolchain_prefix[t],
            '-dr',
            'out/%s.%s.o' % (s, t)
        ]
        print("Invoking: %s" % " ".join(args))
        with open('out/%s.%s.dump' % (s, t), 'w') as f:
            proc = Popen(args, env=env, cwd=TOPDIR, stdout=f)
            retcode = proc.wait()
            if retcode != 0:
                warn("Disassembling %s with %s failed with retcode %s"
                    % (s, t, retcode))
                error = True

if error:
    raise RuntimeError("Not all processes executed successfully.")
