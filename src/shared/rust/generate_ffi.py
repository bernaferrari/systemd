#!/usr/bin/env python3
"""
Generate FFI wrapper blocks for shared/ Rust stub files.

Reads each .rs stub, extracts SOURCE_C_FILE and EXPORTED_SYMBOLS,
runs ctags on the C source to get function signatures, and produces
a proper FFI shadow module.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

# Type mapping: C type → Rust FFI type
C_TO_RUST = {
    'void': None,  # special: return void → no return
    'int': 'c_int',
    'unsigned int': 'c_uint',
    'unsigned': 'c_uint',
    'long': 'c_long',
    'unsigned long': 'c_ulong',
    'long long': 'c_longlong',
    'unsigned long long': 'c_ulonglong',
    'size_t': 'usize',
    'ssize_t': 'isize',
    'pid_t': 'pid_t',
    'uid_t': 'uid_t',
    'gid_t': 'gid_t',
    'mode_t': 'mode_t',
    'dev_t': 'dev_t',
    'ino_t': 'ino_t',
    'nlink_t': 'nlink_t',
    'off_t': 'off_t',
    'blksize_t': 'blksize_t',
    'blkcnt_t': 'blkcnt_t',
    'bool': 'bool',
    '_Bool': 'bool',
    'float': 'f32',
    'double': 'f64',
    'char': 'c_char',
    'uint8_t': 'u8',
    'uint16_t': 'u16',
    'uint32_t': 'u32',
    'uint64_t': 'u64',
    'int8_t': 'i8',
    'int16_t': 'i16',
    'int32_t': 'i32',
    'int64_t': 'i64',
    'usec_t': 'u64',
    'nsec_t': 'u64',
    'sd_id128_t': 'sd_id128_t',
}

# Types that need *mut prefix (pointers)
POINTER_TYPES = {
    'char': '*mut c_char',
    'void': '*mut c_void',
    'int': '*mut c_int',
    'unsigned int': '*mut c_uint',
    'unsigned': '*mut c_uint',
    'long': '*mut c_long',
    'size_t': '*mut usize',
    'ssize_t': '*mut isize',
    'pid_t': '*mut pid_t',
    'uid_t': '*mut uid_t',
    'gid_t': '*mut gid_t',
    'mode_t': '*mut mode_t',
    'dev_t': '*mut dev_t',
    'ino_t': '*mut ino_t',
    'off_t': '*mut off_t',
    'bool': '*mut bool',
    '_Bool': '*mut bool',
    'float': '*mut f32',
    'double': '*mut f64',
    'uint8_t': '*mut u8',
    'uint16_t': '*mut u16',
    'uint32_t': '*mut u32',
    'uint64_t': '*mut u64',
    'int8_t': '*mut i8',
    'int16_t': '*mut i16',
    'int32_t': '*mut i32',
    'int64_t': '*mut i64',
    'usec_t': '*mut u64',
    'sd_id128_t': '*mut sd_id128_t',
}

# Types that are pointers to const
CONST_POINTER_TYPES = {
    'char': '*const c_char',
    'void': '*const c_void',
    'int': '*const c_int',
    'unsigned int': '*const c_uint',
    'unsigned': '*const c_uint',
    'size_t': '*const usize',
    'uint8_t': '*const u8',
    'uint32_t': '*const u32',
    'uint64_t': '*const u64',
    'int32_t': '*const i32',
    'int64_t': '*const i64',
}

# Known struct types → *mut c_void for opaque pointers
STRUCT_POINTER_TYPES = {
    'sd_bus': '*mut c_void',
    'sd_bus_message': '*mut c_void',
    'sd_bus_error': '*mut c_void',
    'sd_event': '*mut c_void',
    'sd_device': '*mut c_void',
    'sd_hwdb': '*mut c_void',
    'sd_id128_t': '*mut sd_id128_t',
    'sd_netlink': '*mut c_void',
    'sd_journal': '*mut c_void',
    'sd_login_monitor': '*mut c_void',
    'Hashmap': '*mut c_void',
    'Set': '*mut c_void',
    'OrderedHashmap': '*mut c_void',
    'PamModule': '*mut c_void',
    'PamData': '*mut c_void',
    'strv': '*mut c_void',
    'acl_t': '*mut c_void',
    'acl_entry_t': '*mut c_void',
    'sd_bus_slot': '*mut c_void',
    'sd_bus_track': '*mut c_void',
    'sd_bus_creds': '*mut c_void',
    'sd_bus_container': '*mut c_void',
    'sd_bus_message_handler_t': '*mut c_void',
    'sd_dhcp_client': '*mut c_void',
    'sd_dhcp_server': '*mut c_void',
    'sd_dhcp6_client': '*mut c_void',
    'sd_lldp': '*mut c_void',
    'sd_lldp_neighbor': '*mut c_void',
    'sd_ipv4ll': '*mut c_void',
    'sd_ipv4acd': '*mut c_void',
    'sd_ndisc': '*mut c_void',
    'sd_pae': '*mut c_void',
    'sd_radv': '*mut c_void',
    'Partition': '*mut c_void',
    'FdSet': '*mut c_void',
    'JsonVariant': '*mut c_void',
    'UdevRules': '*mut c_void',
    'UdevListEntry': '*mut c_void',
    'UdevDevice': '*mut c_void',
    'UdevMonitor': '*mut c_void',
    'UdevEnumerate': '*mut c_void',
    'Varlink': '*mut c_void',
    'VarlinkServer': '*mut c_void',
    'VarlinkConnection': '*mut c_void',
    'struct stat': '*mut c_void',
    'struct pollfd': '*mut c_void',
    'struct sigaction': '*mut c_void',
    'struct iovec': '*mut c_void',
    'struct timeval': '*mut c_void',
    'struct timespec': '*mut c_void',
    'struct tm': '*mut c_void',
    'struct ucred': '*mut c_void',
    'struct ifconf': '*mut c_void',
    'struct ifreq': '*mut c_void',
    'struct ifinfomsg': '*mut c_void',
    'struct nlmsghdr': '*mut c_void',
    'struct rtattr': '*mut c_void',
    'struct ndmsg': '*mut c_void',
    'struct ether_addr': '*mut c_void',
    'struct fdisk_context': '*mut c_void',
    'struct fdisk_table': '*mut c_void',
    'struct fdisk_partition': '*mut c_void',
    'struct fdisk_iter': '*mut c_void',
    'struct archive': '*mut c_void',
    'struct archive_entry': '*mut c_void',
    'struct termios': '*mut c_void',
    'struct winsize': '*mut c_void',
    'ElfW_Ehdr': '*mut c_void',
    'ElfW_Phdr': '*mut c_void',
    'FILE': '*mut c_void',
    'DIR': '*mut c_void',
    'regex_t': '*mut c_void',
    'Elf32_Ehdr': '*mut c_void',
    'Elf64_Ehdr': '*mut c_void',
    'Elf32_Phdr': '*mut c_void',
    'Elf64_Phdr': '*mut c_void',
}

# Const struct pointer types
CONST_STRUCT_POINTER_TYPES = {
    'sd_bus': '*const c_void',
    'sd_bus_message': '*const c_void',
    'sd_bus_error': '*const c_void',
    'sd_event': '*const c_void',
    'sd_device': '*const c_void',
    'sd_hwdb': '*const c_void',
    'sd_id128_t': '*const sd_id128_t',
    'sd_netlink': '*const c_void',
    'sd_journal': '*const c_void',
    'sd_bus_slot': '*const c_void',
    'sd_bus_creds': '*const c_void',
    'Set': '*const c_void',
    'Hashmap': '*const c_void',
    'JsonVariant': '*const c_void',
    'struct stat': '*const c_void',
    'struct iovec': '*const c_void',
    'struct ifreq': '*const c_void',
    'struct ether_addr': '*const c_void',
    'struct archive_entry': '*const c_void',
    'UdevDevice': '*const c_void',
    'UdevListEntry': '*const c_void',
    'Varlink': '*const c_void',
}

# Types that we just keep as c_int for simplicity
SIMPLE_INT_TYPES = {
    'int',
    'unsigned int',
    'unsigned',
    'long',
    'unsigned long',
    'pid_t',
    'uid_t',
    'gid_t',
    'mode_t',
    'dev_t',
    'ino_t',
    'off_t',
    'blksize_t',
    'blkcnt_t',
    'size_t',
    'ssize_t',
    'int8_t',
    'int16_t',
    'int32_t',
    'int64_t',
    'uint8_t',
    'uint16_t',
    'uint32_t',
    'uint64_t',
    'bool',
    '_Bool',
    'float',
    'double',
}

# Enum-like types (usually int behind the scenes)
ENUM_TYPES = {
    'ImportType',
    'ImportVerify',
    'ImageClass',
    'ExtensionType',
    'InstallChangeType',
    'EscapeAction',
    'BPFProgramType',
    'NetDevKind',
    'BusTransport',
    'ResolveParameter',
    'VarlinkMethod',
    'ManagerObject',
    'NetdevType',
}

C_TYPE_ALIASES = {
    'uid_t': 'c_uint',
    'gid_t': 'c_uint',
    'pid_t': 'c_int',
    'dev_t': 'u64',
    'mode_t': 'u32',
    'off_t': 'i64',
    'ino_t': 'u64',
    'blksize_t': 'i32',
    'blkcnt_t': 'i64',
    'nlink_t': 'u64',
    'usec_t': 'u64',
    'nsec_t': 'u64',
    'sd_id128_t': '[u8; 16]',
}


def parse_c_type(param_str: str) -> tuple[str, str, bool]:
    """
    Parse a C parameter string like "const char *path" or "int fd" or "Set *uids"
    Returns (name, rust_type, is_const_ptr)
    """
    param_str = param_str.strip()
    if not param_str:
        return ('', '*mut c_void', False)

    # Handle array parameters like "char *argv[]" → *mut *mut c_char
    is_array = param_str.endswith('[]')
    if is_array:
        param_str = param_str[:-2].strip()

    # Check for function pointer: e.g. "sd_bus_message_handler_t callback"
    # These are just opaque pointers
    is_function_ptr = False
    for fn_type in [
        'sd_bus_message_handler_t',
        'HashmapIterateFunc',
        'cleanup_callback_t',
        'const_cleanup_callback_t',
        'foreach_process_callback_t',
    ]:
        if fn_type in param_str:
            is_function_ptr = True
            break

    # Handle const qualifier
    is_const = 'const ' in param_str or param_str.startswith('const ')
    clean = param_str.replace('const ', '').strip()
    # Normalize multiple spaces
    clean = re.sub(r'\s+', ' ', clean)

    # Handle ** (double pointer)
    if '**' in clean or ' * *' in clean:
        # Extract the base type and name
        clean = clean.replace('**', '').replace(' * *', '').strip()
        parts = clean.rsplit(None, 1)
        if len(parts) == 2:
            base_type, name = parts
        else:
            base_type = clean
            name = 'arg'
        return (name, '*mut *mut c_void', False)

    # Handle pointer: "char *name" or "struct stat *buf"
    if '*' in clean:
        # Remove all * from the string for type extraction
        base = clean.replace('*', '').strip()
        parts = base.rsplit(None, 1)
        if len(parts) == 2:
            base_type, name = parts
        else:
            base_type = base
            name = 'arg'

        if is_function_ptr:
            return (name, '*mut c_void', False)

        # Check struct pointers
        if is_const:
            if base_type in CONST_STRUCT_POINTER_TYPES:
                return (name, CONST_STRUCT_POINTER_TYPES[base_type], True)
            elif base_type in STRUCT_POINTER_TYPES:
                return (name, STRUCT_POINTER_TYPES[base_type], True)
            elif base_type in CONST_POINTER_TYPES:
                return (name, CONST_POINTER_TYPES[base_type], True)
            else:
                return (name, '*const c_void', True)
        else:
            if base_type in STRUCT_POINTER_TYPES:
                return (name, STRUCT_POINTER_TYPES[base_type], False)
            elif base_type in POINTER_TYPES:
                return (name, POINTER_TYPES[base_type], False)
            else:
                return (name, '*mut c_void', False)

    # Handle simple types: "int fd", "size_t len"
    parts = clean.rsplit(None, 1)
    if len(parts) == 2:
        type_str, name = parts
    elif len(parts) == 1:
        type_str = parts[0]
        name = 'arg'
    else:
        return ('arg', 'c_int', False)

    # Map type
    if type_str in C_TO_RUST:
        rust_type = C_TO_RUST[type_str]
        if rust_type is None:
            return (name, 'c_void', False)
        return (name, rust_type, False)
    elif type_str in ENUM_TYPES:
        return (name, 'c_int', False)
    else:
        # Unknown type, default to c_int for integers, c_void for structs
        if type_str.startswith('struct ') or type_str[0].isupper():
            return (name, 'c_void', False)
        return (name, 'c_int', False)


def parse_return_type(ret_str: str) -> str:
    """Parse C return type to Rust FFI type."""
    ret_str = ret_str.strip()
    if not ret_str or ret_str == 'void':
        return ''

    # Remove const, static, inline
    ret_str = ret_str.replace('const ', '').replace('static ', '').replace('inline ', '').strip()

    if ret_str in C_TO_RUST:
        v = C_TO_RUST[ret_str]
        if v is None:
            return ''
        return v
    elif ret_str in ENUM_TYPES:
        return 'c_int'
    elif ret_str.startswith('struct ') or ret_str[0].isupper():
        return 'c_int'  # structs returned by value → just c_int placeholder
    else:
        return 'c_int'


def get_functions_from_ctags(c_file: str, exported_symbols: list[str]) -> list[dict]:
    """Run ctags on a C file and extract function signatures."""
    if not os.path.exists(c_file):
        return []

    try:
        result = subprocess.run(
            ['ctags', '--fields=+S+t', '--output-format=json', c_file],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

    functions = []
    exported_set = set(exported_symbols)

    for line in result.stdout.strip().split('\n'):
        if not line:
            continue
        try:
            tag = json.loads(line)
        except json.JSONDecodeError:
            continue

        if tag.get('kind') != 'function':
            continue

        name = tag.get('name', '')
        # Skip static/internal functions that are not in exported symbols
        # and skip functions starting with underscore
        if name.startswith('_'):
            continue

        # If we have exported symbols, prefer those
        if exported_symbols and name not in exported_set:
            continue

        signature = tag.get('signature', '')
        line_num = tag.get('line', 0)
        typeref = tag.get('typeref', '')

        params = []
        ret_type = 'int'

        if typeref.startswith('typename:'):
            ret_type = typeref[len('typename:') :].strip()

        if signature:
            sig = signature.strip()
            paren_idx = sig.find('(')
            if paren_idx >= 0:
                params_part = sig[paren_idx + 1 : sig.rfind(')')].strip()

                # Parse parameters
                if params_part and params_part != 'void':
                    # Split by comma, being careful with function pointers
                    raw_params = []
                    depth = 0
                    current = ''
                    for ch in params_part:
                        if ch == '(':
                            depth += 1
                            current += ch
                        elif ch == ')':
                            depth -= 1
                            current += ch
                        elif ch == ',' and depth == 0:
                            raw_params.append(current.strip())
                            current = ''
                        else:
                            current += ch
                    if current.strip():
                        raw_params.append(current.strip())

                    for p in raw_params:
                        p = p.strip()
                        if p == 'void' or p == '...':
                            continue
                        pname, ptype, is_const = parse_c_type(p)
                        if pname:
                            params.append((pname, ptype))
                        else:
                            params.append((f'arg{len(params)}', ptype))
        else:
            # No signature from ctags - try to extract from the source
            params = []

        functions.append(
            {
                'name': name,
                'return_type': ret_type,
                'params': params,
                'line': line_num,
            }
        )

    # Sort: exported symbols first, then others
    if exported_symbols:
        functions.sort(
            key=lambda f: (
                0 if f['name'] in exported_set else 1,
                exported_symbols.index(f['name']) if f['name'] in exported_symbols else 999,
            )
        )

    return functions


def determine_needed_imports(functions: list[dict]) -> set[str]:
    """Determine which std::ffi types are needed."""
    imports = set()
    imports.add('c_int')  # default for return types

    for func in functions:
        for _, ptype in func['params']:
            if 'c_char' in ptype:
                imports.add('c_char')
            if 'c_void' in ptype:
                imports.add('c_void')
            if 'c_uint' in ptype:
                imports.add('c_uint')
            if 'c_int' in ptype:
                imports.add('c_int')
            if 'c_long' in ptype:
                imports.add('c_long')
            if 'c_ulong' in ptype:
                imports.add('c_ulong')

        ret = parse_return_type(func['return_type'])
        if 'c_uint' in ret:
            imports.add('c_uint')
        if 'c_void' in ret:
            imports.add('c_void')

    # Always include these minimal imports
    if not any('c_char' in i for i in imports):
        imports.discard('c_char')
    if not any('c_void' in i for i in imports):
        imports.discard('c_void')
    if not any('c_uint' in i for i in imports):
        imports.discard('c_uint')

    return imports


def generate_ffi_file(rs_file: str, c_file: str, exported_symbols: list[str], source_c_path: str) -> str:
    """Generate the FFI wrapper file content."""
    functions = get_functions_from_ctags(c_file, exported_symbols)
    needed_imports = determine_needed_imports(functions)

    # Determine the include path for the C source relative to the Rust file
    # The Rust file is at src/shared/rust/foo.rs
    # The C file is at src/shared/bar.c
    # So the relative include path from the Rust dir is ../bar.c
    c_basename = os.path.basename(c_file)
    include_path = f'../{c_basename}'

    lines = []
    lines.append('// SPDX-License-Identifier: LGPL-2.1-or-later')
    lines.append('//')
    lines.append(f'// PORT-SYNC: {source_c_path}')
    lines.append('//')
    lines.append('// FFI shadow module.')
    lines.append('')

    # Imports
    if functions:
        ffi_imports = []
        for imp in sorted(needed_imports):
            ffi_imports.append(imp)
        if ffi_imports:
            lines.append(f'use std::ffi::{{{", ".join(ffi_imports)}}};')
    lines.append('')

    if functions:
        used_custom = set()
        for func in functions:
            for _, ptype in func['params']:
                if ptype in C_TYPE_ALIASES:
                    used_custom.add(ptype)
            ret = parse_return_type(func['return_type'])
            if ret in C_TYPE_ALIASES:
                used_custom.add(ret)

        for ct in sorted(used_custom):
            lines.append(f'pub type {ct} = {C_TYPE_ALIASES[ct]};')
        if used_custom:
            lines.append('')

    # Source constants
    lines.append(f'pub const SOURCE_PATH: &str = "{source_c_path}";')
    lines.append(f'pub const SOURCE_TEXT: &str = include_str!("{include_path}");')
    lines.append('')

    # Keep exported symbols for reference
    if exported_symbols:
        symbols_str = ', '.join(f'"{s}"' for s in exported_symbols)
        lines.append(f'pub const EXPORTED_SYMBOLS: &[&str] = &[{symbols_str}];')
        lines.append('')

    # FFI extern block
    if functions:
        lines.append('unsafe extern "C" {')
        for func in functions:
            ret_type = parse_return_type(func['return_type'])
            params_str = ', '.join(f'{pname}: {ptype}' for pname, ptype in func['params'])
            if ret_type:
                lines.append(f'    fn {func["name"]}({params_str}) -> {ret_type};')
            else:
                lines.append(f'    fn {func["name"]}({params_str});')
        lines.append('}')
        lines.append('')

        # FFI wrapper functions
        for func in functions:
            ret_type = parse_return_type(func['return_type'])
            params_str = ', '.join(f'{pname}: {ptype}' for pname, ptype in func['params'])
            wrapper_name = f'rs_{func["name"]}'
            if ret_type:
                lines.append(f'#[no_mangle]')
                lines.append(f'pub unsafe extern "C" fn {wrapper_name}({params_str}) -> {ret_type} {{')
                args = ', '.join(pname for pname, _ in func['params'])
                lines.append(f'    {func["name"]}({args})')
                lines.append('}')
            else:
                lines.append(f'#[no_mangle]')
                lines.append(f'pub unsafe extern "C" fn {wrapper_name}({params_str}) {{')
                args = ', '.join(pname for pname, _ in func['params'])
                lines.append(f'    {func["name"]}({args});')
                lines.append('}')
            lines.append('')

    # Source lines helper
    lines.append('pub fn source_lines() -> usize { SOURCE_TEXT.lines().count() }')
    lines.append('')

    # Tests
    lines.append('#[cfg(test)]')
    lines.append('mod tests {')
    lines.append('    use super::*;')
    lines.append('')
    lines.append('    #[test]')
    lines.append('    fn source_is_embedded() { assert!(!super::SOURCE_TEXT.is_empty()); }')
    lines.append('}')
    lines.append('')

    return '\n'.join(lines)


def extract_metadata(rs_file: str) -> tuple[str, list[str]]:
    """Extract SOURCE_C_FILE and EXPORTED_SYMBOLS from an existing stub file."""
    source_c_file = ''
    exported_symbols = []

    with open(rs_file, 'r') as f:
        content = f.read()

    # Extract SOURCE_C_FILE
    m = re.search(r'pub const SOURCE_C_FILE:\s*&str\s*=\s*"([^"]+)"', content)
    if m:
        source_c_file = m.group(1)

    # Extract EXPORTED_SYMBOLS
    m = re.search(r'pub const EXPORTED_SYMBOLS:\s*&\[&str\]\s*=\s*\[([^\]]*)\]', content)
    if m:
        symbols_str = m.group(1)
        exported_symbols = re.findall(r'"([^"]+)"', symbols_str)

    return source_c_file, exported_symbols


def main():
    rust_dir = Path('src/shared/rust')
    root_dir = Path('.')

    # Find all target files
    target_files = []
    for rs_file in sorted(rust_dir.glob('*.rs')):
        name = rs_file.name
        if name in ('lib.rs', 'tests.rs', 'ffi.rs', 'generate_ffi.py'):
            continue

        # Check line count
        line_count = len(rs_file.read_text().splitlines())
        if line_count >= 200:
            continue

        # Check if already has FFI
        content = rs_file.read_text()
        if 'unsafe extern "C"' in content:
            continue

        target_files.append(rs_file)

    print(f'Found {len(target_files)} target files to process')

    success = 0
    skipped = 0
    errors = 0

    for rs_file in target_files:
        source_c_file, exported_symbols = extract_metadata(str(rs_file))

        if not source_c_file:
            print(f'  SKIP {rs_file.name}: no SOURCE_C_FILE found')
            skipped += 1
            continue

        c_file_path = root_dir / source_c_file
        if not c_file_path.exists():
            print(f'  SKIP {rs_file.name}: C source {source_c_file} not found')
            skipped += 1
            continue

        try:
            new_content = generate_ffi_file(str(rs_file), str(c_file_path), exported_symbols, source_c_file)
            rs_file.write_text(new_content)
            func_count = len(get_functions_from_ctags(str(c_file_path), exported_symbols))
            print(f'  OK {rs_file.name}: {func_count} functions from {source_c_file}')
            success += 1
        except Exception as e:
            print(f'  ERROR {rs_file.name}: {e}')
            errors += 1

    print(f'\nDone: {success} succeeded, {skipped} skipped, {errors} errors')


if __name__ == '__main__':
    main()
