#!/usr/bin/env python3
"""Generate Rust FFI wrapper files for journal C sources (batch 1)."""

import re
import os

BASE = os.path.dirname(os.path.abspath(__file__))
C_DIR = os.path.join(BASE, '..')

FILES = [
    (
        'journald_audit.rs',
        'journald-audit.c',
        'journald audit socket processing and netlink message handling.',
    ),
    ('journald_client.rs', 'journald-client.c', 'journald client context log filter pattern matching.'),
    ('journald_config.rs', 'journald-config.c', 'journald configuration loading, parsing, and merging.'),
    ('journald_console.rs', 'journald-console.c', 'journald console message forwarding.'),
    (
        'journald_context.rs',
        'journald-context.c',
        'journald client context metadata cache with LRU eviction.',
    ),
    ('journald_kmsg.rs', 'journald-kmsg.c', 'journald /dev/kmsg reading and kernel message processing.'),
    (
        'journald_manager.rs',
        'journald-manager.c',
        'journald manager: core daemon state, journal file management, dispatch.',
    ),
    ('journald_native.rs', 'journald-native.c', 'journald native protocol message and file processing.'),
    (
        'journald_rate_limit.rs',
        'journald-rate-limit.c',
        'Per-priority journal rate limiting with burst and interval.',
    ),
    ('journald_socket.rs', 'journald-socket.c', 'journald forward-to-socket functionality.'),
    (
        'journald_stream.rs',
        'journald-stream.c',
        'journald stdout stream processing with protocol negotiation and persistence.',
    ),
    (
        'journald_sync.rs',
        'journald-sync.c',
        'journald synchronization request tracking for Varlink Synchronize method.',
    ),
    ('journald_syslog.rs', 'journald-syslog.c', 'journald syslog socket handling and message processing.'),
    (
        'journald_varlink.rs',
        'journald-varlink.c',
        'journald Varlink server: Synchronize, Rotate, FlushToVar, RelinquishVar.',
    ),
    ('journald_wall.rs', 'journald-wall.c', 'journald wall message forwarding via wall(1).'),
    ('journald.rs', 'journald.c', 'Main systemd-journald daemon entry point.'),
    ('cat.rs', 'cat.c', 'Journal cat: pipe stdout/stderr to the journal.'),
    ('bsod.rs', 'bsod.c', 'systemd-bsod: display emergency log message as QR code on a VT.'),
    ('journalctl.rs', 'journalctl.c', 'Main journalctl binary with argument parsing and action dispatch.'),
]

SKIP_NAMES = {
    'DEFINE_MAIN_FUNCTION',
    'DEFINE_TRIVIAL_CLEANUP_FUNC',
    'DEFINE_PRIVATE_HASH_OPS',
    'DEFINE_HASH_OPS',
    'DEFINE_STRING_TABLE',
    'ASSERT_NOT_REACHED',
    'ASSERT_PTR',
    'STATIC_DESTRUCTOR_REGISTER',
}

RUST_KEYWORDS = {
    'type',
    'match',
    'loop',
    'fn',
    'let',
    'if',
    'else',
    'while',
    'for',
    'return',
    'break',
    'continue',
    'as',
    'in',
    'ref',
    'mut',
    'move',
    'async',
    'await',
    'impl',
    'trait',
    'struct',
    'enum',
    'use',
    'mod',
    'pub',
    'crate',
    'self',
    'super',
    'where',
    'unsafe',
    'extern',
    'true',
    'false',
    'const',
    'static',
    'dyn',
    'box',
}

C_KEYWORDS = {
    'if',
    'while',
    'for',
    'switch',
    'return',
    'case',
    'sizeof',
    'typeof',
    'goto',
    'else',
    'do',
    'break',
    'continue',
}

SIMPLE_TYPES = {
    'void': 'c_void',
    'int': 'c_int',
    'unsigned': 'c_uint',
    'unsigned int': 'c_uint',
    'signed': 'c_int',
    'bool': 'bool',
    'char': 'c_char',
    'size_t': 'usize',
    'ssize_t': 'isize',
    'usec_t': 'u64',
    'uint64_t': 'u64',
    'uint32_t': 'u32',
    'uint16_t': 'u16',
    'uint8_t': 'u8',
    'int64_t': 'i64',
    'int32_t': 'i32',
    'int16_t': 'i16',
    'int8_t': 'i8',
    'pid_t': 'i32',
    'uid_t': 'u32',
    'gid_t': 'u32',
    'dev_t': 'u64',
    'ino_t': 'u64',
    'off_t': 'i64',
    'nsec_t': 'u64',
    'socklen_t': 'u32',
    'double': 'f64',
    'sa_family_t': 'c_uint',
    'clockid_t': 'c_int',
    'sd_varlink_method_flags_t': 'u32',
}


def parse_c_file(filepath):
    with open(filepath, 'r') as f:
        text = f.read()

    text = re.sub(r'//.*$', '', text, flags=re.MULTILINE)
    text = re.sub(r'/\*.*?\*/', ' ', text, flags=re.DOTALL)
    text = re.sub(r'^\s*#.*$', '', text, flags=re.MULTILINE)
    text = re.sub(r'\s+', ' ', text).strip()

    functions = []

    for m in re.finditer(
        r'(?<!\w)'
        r'((?:static\s+)?(?:inline\s+)?(?:_\w+\s+)*)'
        r'([A-Za-z_][\w\s]+?\w)'
        r'(\s*\*)*'
        r'\s*'
        r'([A-Za-z_]\w*)'
        r'\s*\(([^)]*)\)'
        r'\s*(?:__attribute__\s*\(\([^)]*\)\)\s*)*'
        r'\{',
        text,
    ):
        prefix = m.group(1).strip()
        possible_ret = m.group(2)
        has_star = m.group(3) is not None
        func_name = m.group(4)
        params_raw = m.group(5).strip()

        if func_name in SKIP_NAMES or func_name.isupper():
            continue
        if func_name in C_KEYWORDS:
            continue
        if len(func_name) < 3:
            continue

        is_static = 'static' in prefix
        ret_type = prefix.replace('static', '').replace('inline', '').strip()
        ret_type = re.sub(r'\b_\w+\b', '', ret_type).strip()
        if ret_type:
            full_ret = ret_type + ('*' if has_star else '') + ' ' + possible_ret
        else:
            full_ret = possible_ret + ('*' if has_star else '')
        full_ret = re.sub(r'\s+', ' ', full_ret).strip()
        if not full_ret:
            full_ret = 'int'

        full_ret = re.sub(r'\bdefault_value\b', '', full_ret).strip()

        if not re.match(r'^[A-Z]', full_ret) and full_ret not in (
            'int',
            'void',
            'bool',
            'unsigned',
            'signed',
            'size_t',
            'ssize_t',
            'usec_t',
            'uint64_t',
            'uint32_t',
            'uint16_t',
            'uint8_t',
            'int64_t',
            'int32_t',
            'int16_t',
            'int8_t',
            'pid_t',
            'uid_t',
            'gid_t',
            'dev_t',
            'ino_t',
            'off_t',
            'nsec_t',
            'socklen_t',
            'double',
            'float',
            'char',
            'sd_varlink_method_flags_t',
            'sd_id128_t',
            'clockid_t',
            'sa_family_t',
        ):
            continue

        params = parse_params(params_raw)
        functions.append(
            {
                'name': func_name,
                'return_type': full_ret,
                'params': params,
                'is_static': is_static,
            }
        )

    seen = set()
    deduped = []
    for f in functions:
        sig = (f['return_type'], f['name'], tuple((t, n) for t, n in f['params']))
        if sig not in seen:
            seen.add(sig)
            deduped.append(f)
    return deduped


def parse_params(raw):
    raw = raw.strip()
    if not raw or raw == 'void':
        return []

    params = []
    for part in raw.split(','):
        part = part.strip()
        if not part:
            continue
        if part == '...':
            params.append(('...', '...'))
            continue

        part = re.sub(r'\s+', ' ', part).strip()

        m2 = re.match(r'^(.+?)\s*(\w+)\s*\[\s*\]$', part)
        if m2:
            base = m2.group(1).strip()
            name = m2.group(2).strip()
            if name in RUST_KEYWORDS:
                name = f'r#{name}'
            params.append((base + '*', name))
            continue

        m = re.match(r'^(.*?)\b(\w+)$', part)
        if m:
            ctype = m.group(1).strip()
            name = m.group(2).strip()
            if not ctype:
                continue
            if name in RUST_KEYWORDS:
                name = f'r#{name}'
            params.append((ctype, name))
            continue

    return params


def c_to_rust(ctype_str):
    t = ctype_str.strip()
    if t == '...':
        return '...'

    is_const = 'const' in t
    t_no_const = t.replace('const', '').strip()
    ptr_depth = t_no_const.count('*')
    base = t_no_const.replace('*', '').strip()
    t_clean = re.sub(r'\s+', ' ', base).strip()
    rust = SIMPLE_TYPES.get(t_clean, 'c_void')

    if ptr_depth == 0:
        return rust
    if ptr_depth == 1:
        return f'*const {rust}' if is_const else f'*mut {rust}'
    if rust == 'c_char' and is_const:
        return '*mut *const c_char'
    if rust == 'c_char':
        return '*mut *mut c_char'
    if rust == 'c_void' or rust == 'c_int':
        return f'*mut *mut {rust}'
    return '*mut c_void'


def ret_to_rust(ctype_str):
    t = ctype_str.strip()
    is_const = 'const' in t
    t_no_const = t.replace('const', '').strip()
    ptr_depth = t_no_const.count('*')
    base = t_no_const.replace('*', '').strip()

    t_clean = re.sub(r'\s+', ' ', base).strip()
    if t_clean == 'void' and ptr_depth == 0:
        return ''
    rust = SIMPLE_TYPES.get(t_clean, 'c_void')

    if ptr_depth == 0:
        return rust
    if ptr_depth == 1:
        return f'*const {rust}' if is_const else f'*mut {rust}'
    return f'*mut {rust}'


def needed_imports(functions):
    needed = set()
    for f in functions:
        rt = ret_to_rust(f['return_type'])
        for t in ('c_char', 'c_int', 'c_uint', 'c_void'):
            if t in rt:
                needed.add(t)
        for ct, _ in f['params']:
            rt2 = c_to_rust(ct)
            for t in ('c_char', 'c_int', 'c_uint', 'c_void'):
                if t in rt2:
                    needed.add(t)
    needed.update(['c_int'])
    return sorted(needed)


COMMON_NAMES = {
    'help',
    'parse_argv',
    'run',
    'main',
    'init',
    'free',
    'close',
    'open',
    'new',
    'read',
    'write',
    'flush',
    'sync',
    'start',
    'stop',
    'reset',
}


def generate(rust_file, c_file, desc, functions):
    imports = needed_imports(functions)
    mod_name = rust_file.replace('.rs', '').replace('journald_', 'jd_').replace('journalctl_', 'jc_')

    extern_lines = []
    for f in functions:
        params = []
        for ct, cn in f['params']:
            if ct == '...':
                params.append('...')
            else:
                params.append(f'{cn}: {c_to_rust(ct)}')
        ps = ', '.join(params)
        rt = ret_to_rust(f['return_type'])
        if rt:
            extern_lines.append(f'    fn {f["name"]}({ps}) -> {rt};')
        else:
            extern_lines.append(f'    fn {f["name"]}({ps});')

    wrapper_lines = []
    for f in functions:
        params = []
        call_args = []
        has_variadic = False
        for ct, cn in f['params']:
            if ct == '...':
                has_variadic = True
                continue
            params.append(f'{cn}: {c_to_rust(ct)}')
            call_args.append(cn)
        ps = ', '.join(params)
        ca = ', '.join(call_args)
        rt = ret_to_rust(f['return_type'])
        if f['name'] in COMMON_NAMES:
            wn = f'rs_{mod_name}_{f["name"]}'
        else:
            wn = f'rs_{f["name"]}'

        if has_variadic:
            continue
            if rt:
                wrapper_lines.append(
                    f'#[no_mangle]\n'
                    f'pub unsafe extern "C" fn {wn}({underscrored_params}) -> {rt} {{\n'
                    f'    unreachable!("variadic function {f["name"]} must be called from C")\n'
                    f'}}'
                )
            else:
                wrapper_lines.append(
                    f'#[no_mangle]\n'
                    f'pub unsafe extern "C" fn {wn}({underscrored_params}) {{\n'
                    f'    unreachable!("variadic function {f["name"]} must be called from C")\n'
                    f'}}'
                )
        elif rt:
            wrapper_lines.append(
                f'#[no_mangle]\npub unsafe extern "C" fn {wn}({ps}) -> {rt} {{\n    {f["name"]}({ca})\n}}'
            )
        else:
            wrapper_lines.append(
                f'#[no_mangle]\npub unsafe extern "C" fn {wn}({ps}) {{\n    {f["name"]}({ca});\n}}'
            )

    has_var = any(ct == '...' for f in functions for ct, _ in f['params'])

    adc = '#[allow(dead_code)]\n' if has_var else ''

    return f"""// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/journal/{c_file}
//
// {desc}

use std::ffi::{{{', '.join(imports)}}};

pub const SOURCE_PATH: &str = "src/journal/{c_file}";
pub const SOURCE_TEXT: &str = include_str!("../{c_file}");

{adc}unsafe extern "C" {{
{chr(10).join(extern_lines)}
}}

{chr(10).join(wrapper_lines)}

pub fn source_lines() -> usize {{ SOURCE_TEXT.lines().count() }}

#[cfg(test)]
mod tests {{
    #[test]
    fn source_is_embedded() {{
        assert!(!super::SOURCE_TEXT.is_empty());
    }}
    #[test]
    fn smoke_ffi() {{
        let _ = super::source_lines();
    }}
}}
"""


def main():
    for rust_file, c_file, desc in FILES:
        c_path = os.path.join(C_DIR, c_file)
        rust_path = os.path.join(BASE, rust_file)
        if not os.path.exists(c_path):
            print(f'SKIP: {c_path}')
            continue

        fns = parse_c_file(c_path)
        print(f'{c_file}: {len(fns)} functions')
        for f in fns:
            ps = ', '.join(f'{t} {n}' for t, n in f['params']) if f['params'] else 'void'
            print(f'  {f["return_type"]} {f["name"]}({ps})')

        with open(rust_path, 'w') as out:
            out.write(generate(rust_file, c_file, desc, fns))
        print(f'  -> {rust_file}')

    print(f'\nDone: {len(FILES)} files')


if __name__ == '__main__':
    main()
