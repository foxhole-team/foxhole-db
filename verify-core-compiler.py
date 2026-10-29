#!/usr/bin/env python3
"""Admit only a pinned Core release compiler using the existing owner signer."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys


def pin_document(path):
    pin = json.loads(path.read_bytes())
    keys = {'schema', 'sourceCommit', 'producerCommit', 'handoffCommit', 'handoffSha256',
            'archiveSha256', 'archiveBytes', 'compilerSha256'}
    if set(pin) != keys or pin['schema'] != 1:
        raise ValueError('invalid compiler pin schema')
    for key in ('sourceCommit', 'producerCommit', 'handoffCommit'):
        if not isinstance(pin[key], str) or not re.fullmatch('[0-9a-f]{40}', pin[key]):
            raise ValueError('compiler source/producer/handoff pin is unbound')
    for key in ('handoffSha256', 'archiveSha256', 'compilerSha256'):
        if not isinstance(pin[key], str) or not re.fullmatch('[0-9a-f]{64}', pin[key]):
            raise ValueError('compiler hash pin is unbound')
    if type(pin['archiveBytes']) is not int or not 0 < pin['archiveBytes'] <= 512 * 1024**2:
        raise ValueError('compiler archive size pin is unbound')
    return pin


def load_verifier(core):
    spec = importlib.util.spec_from_file_location('pinned_core_lab_verifier', core/'scripts/verify-lab-release.py')
    module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def bind_pin(pin, handoff, compiler_key):
    if handoff['source_commit'] != pin['sourceCommit'] or handoff['producer_commit'] != pin['producerCommit'] or handoff['archive_sha256'] != pin['archiveSha256'] or handoff['archive_bytes'] != pin['archiveBytes']:
        raise ValueError('compiler source/producer/archive pin differs from signed handoff')
    if handoff['files'].get(compiler_key, {}).get('sha256') != pin['compilerSha256']:
        raise ValueError('compiler payload hash differs from pin')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('mode', choices=('pin', 'describe', 'verify'))
    p.add_argument('--pin', type=Path, required=True)
    p.add_argument('--core', type=Path)
    p.add_argument('--archive', type=Path)
    p.add_argument('--output', type=Path)
    a = p.parse_args();pin = pin_document(a.pin)
    if a.mode == 'pin':
        print(json.dumps(pin, sort_keys=True));return
    if a.core is None:
        raise ValueError('exact Core source checkout required')
    a.core = a.core.resolve()
    if a.archive is not None:
        a.archive = a.archive.resolve()
    if a.output is not None:
        a.output = a.output.resolve()
    verifier = load_verifier(a.core)
    required = (a.core/'scripts/lab-release-required-scope.json').read_bytes()
    handoff = verifier.select(verifier.signed_handoff(a.core, pin['sourceCommit'], pin['handoffCommit'], pin['handoffSha256']), a.core, pin['sourceCommit'], required)
    bind_pin(pin, handoff, verifier.COMPILER)
    if a.mode == 'verify':
        if a.archive is None or a.output is None:
            raise ValueError('archive and new output required')
        subprocess.run([sys.executable, str(a.core/'scripts/verify-lab-release.py'), 'verify', '--source', pin['sourceCommit'], '--handoff-commit', pin['handoffCommit'], '--handoff-sha256', pin['handoffSha256'], '--archive', str(a.archive), '--output', str(a.output)], cwd=a.core, check=True, timeout=120)
        compiler = a.output/verifier.COMPILER
        if not compiler.is_file() or not compiler.stat().st_mode & 0o111 or hashlib.sha256(compiler.read_bytes()).hexdigest() != pin['compilerSha256']:
            raise ValueError('verified executable compiler is missing')
    print(json.dumps(handoff, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        sys.exit('Pinned Core compiler admission failed: ' + str(error))
