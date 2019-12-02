#!/usr/bin/env python3

import os
import os.path
import re
import argparse


os.environ['BN_DISABLE_USER_PLUGINS'] = '1'
import binaryninja as bn

# pip3 install git+https://github.com/sprout42/python-magic
# - module that uses libmagic to identify file types
import magic

import yaml


if __name__ == '__main__':
    def hexint_presenter(dumper, data):
        return dumper.represent_int(hex(data))
    yaml.add_representer(int, hexint_presenter)

    parser = argparse.ArgumentParser()
    parser.add_argument('path', help='Path to find binaries in')
    parser.add_argument('output', help='Output file to save results in')
    parser.add_argument('-u', '--update-analysis', action='store_true',
            help='Update analysis of existing dbs')
    args = parser.parse_args()

    bin_file_types = re.compile(r'^(?:Mach-O 64-bit)|(?:ELF)|(?:PE32)')

    strings = {}
    m = magic.Magic()
    for dirname, _, filelist in os.walk(args.path):
        for filename in filelist:
            binfile = os.path.join(dirname, filename)
            if filename is not None:
                filetype = m.from_file(binfile)
                if bin_file_types.match(filetype):
                    dbfile = os.path.join(dirname, filename + '.bndb')
                    if os.path.isfile(dbfile):
                        print('Re-Opening {}'.format(dbfile))
                        bv = bn.binaryview.BinaryViewType.get_view_of_file(dbfile,
                                update_analysis=args.update_analysis)
                        bv.save_auto_snapshot()
                    else:
                        print('Analyzing {}'.format(binfile))
                        bv = bn.binaryview.BinaryViewType.get_view_of_file(binfile, update_analysis=True)
                        bv.create_database(dbfile)
                    strings[binfile] = {s.start: s.value for s in bv.get_strings()}

    with open(args.output, 'w') as f:
        f.write(yaml.dump(strings))
