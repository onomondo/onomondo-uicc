# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

import os
import re

def to_c_array(path='files', out_path='ss_static_files.c', mode='bin'):
    # walk the files directory and get a list of all files and subdirectories
    s = f'#include "ss_static_files_{mode}.h"\n'
    data_type = 'uint8_t' if mode == 'bin' else 'char'

    files, directories = get_dirs_and_files(path)

    s += 'const ss_dir_t ss_dirs_arr[] = {\n'
    ds = []
    for d in directories:
        if d == '':
            continue
        ds.append( f'{{.name = "{d}"}}')
    s += ', \n'.join(ds) + '\n};\n'

    for f in files:
        c_f_name = (f).replace("/", "_").replace(".", "_")
        s += f"static const {data_type} {c_f_name}[] = "
        with open(path + f, 'r') as file:
            data = file.read()
            # get it in chunks of 2
            if mode == 'bin':
                data = re.findall('..', data)
                data = ','.join([f'0x{byte}' for byte in data])
                s += f'{{{data}}};\n'
            else:
                s += f'"{data}";\n'

    s += 'const ss_file_t ss_files_arr[] = {\n'
    fs = []
    for f in files:
        c_f_name = (f).replace("/", "_").replace(".", "_")
        with open(path + f, 'r') as file:
            data = file.read()
            data_len = len(data)
            if mode == 'bin':
                fs.append(f'{{.name = "{f}", .data = {c_f_name}, .size = sizeof({c_f_name})}}')
            else:
                fs.append(f'{{.name = "{f}", .data = {c_f_name}, .size = {data_len}}}')

    s += ', \n'.join(fs) + '\n};\n'

    s += f'const uint32_t ss_files_len = {len(files)};\n'
    s += f'const uint32_t ss_dirs_len = {len(directories)};\n'
    s += f'const ss_file_t *ss_files = ss_files_arr;\n'
    s += f'const ss_dir_t *ss_dirs = ss_dirs_arr;\n'

    with open(out_path, 'w') as file:
        file.write(s)

def get_dirs_and_files(path):
    files = []
    directories = []

    for root, d_names, f_names in os.walk(path):
        current_dir = root.split('files')[-1]
        directories.append(current_dir)
        for file in f_names:
            files.append(current_dir+'/'+file)

    print(directories)
    directories.sort()
    files.sort()

    return files, directories
to_c_array('../files', 'ss_static_files_bin.c', 'bin')
to_c_array('../files', 'ss_static_files_hex.c', 'hex')

