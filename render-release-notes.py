#!/usr/bin/env python3
"""Render versioned release text with separate source/compiler provenance."""
from pathlib import Path
import argparse
import hashlib
import re


def render(root, source):
    version = (root / 'VERSION').read_text().strip()
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version):
        raise ValueError('Invalid release version')
    if not re.fullmatch(r'[a-f0-9]{40}', source):
        raise ValueError('Exact source commit required')
    sections = []
    notes = []
    for language in ('en', 'ru'):
        path = root / 'docs/releases' / f'v{version}.{language}.md'
        if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 65536:
            raise ValueError('Bounded source release notes required')
        raw = path.read_bytes()
        sections.append(raw.decode().strip())
        notes.append(f'- Notes `{path.relative_to(root)}` SHA-256: `{hashlib.sha256(raw).hexdigest()}`')
    pin = root / '.github/core-dns-compiler.json'
    provenance = '\n'.join(['## Provenance', '', f'- Source commit: `{source}`',
        f'- Compiler pin SHA-256: `{hashlib.sha256(pin.read_bytes()).hexdigest()}`', *notes])
    return '\n\n---\n\n'.join([*sections, provenance]) + '\n'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(render(Path(__file__).resolve().parent, args.source))
