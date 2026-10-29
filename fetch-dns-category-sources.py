#!/usr/bin/env python3
"""Fetch only immutable purpose-specific input pins, verifying every digest."""
import argparse
import hashlib
import importlib.util
from pathlib import Path
import re
import tempfile
import urllib.request

spec = importlib.util.spec_from_file_location('converter', Path(__file__).with_name('build-dns-categories.py'))
converter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(converter)
REPOSITORIES = {'https://github.com/AdguardTeam/AdguardFilters', 'https://github.com/easylist/easylist',
                'https://github.com/hagezi/dns-blocklists'}


def fetch_specs(spec_directory, output):
    selected = {}
    for file in sorted(spec_directory.glob('*.json')):
        value = converter.strict_json(file.read_text())
        for source in value['sources']:
            if source['repo'] not in REPOSITORIES or re.fullmatch('[0-9a-f]{40}', source['commit']) is None:
                raise ValueError('source must use a supported immutable public repository')
            if re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,63}', source['id']) is None:
                raise ValueError('source identity')
            for row in source['inputs']:
                identity = source['id'], row['path']
                request = source['repo'], source['commit'], row['sha256']
                if identity in selected and selected[identity] != request:
                    raise ValueError('conflicting source pin')
                selected[identity] = request
    for (source_id, relative), (repo, commit, digest) in sorted(selected.items()):
        target = converter.beneath(output / source_id, relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_file() and hashlib.sha256(target.read_bytes()).hexdigest() == digest:
            continue
        repository_path = repo.removeprefix('https://github.com/')
        url = f'https://raw.githubusercontent.com/{repository_path}/{commit}/{relative}'
        request = urllib.request.Request(url, headers={'User-Agent': 'FoxHole-DNS-pinned-builder'})
        with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as file:
            temporary = Path(file.name)
        try:
            hashed = hashlib.sha256()
            total = 0
            with urllib.request.urlopen(request, timeout=30) as response, temporary.open('wb') as file:
                for chunk in iter(lambda: response.read(65536), b''):
                    total += len(chunk)
                    if total > converter.MAX_INPUT_BYTES:
                        raise ValueError('pinned source is too large')
                    file.write(chunk)
                    hashed.update(chunk)
            if total == 0 or hashed.hexdigest() != digest:
                raise ValueError('pinned source hash mismatch')
            temporary.replace(target)
        finally:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--spec-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    fetch_specs(args.spec_dir, args.output)


if __name__ == '__main__':
    main()
