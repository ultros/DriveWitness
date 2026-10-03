"""Regenerate the public cross-language fixture using the retained Python engine.
The fixture private key is deterministic test data, NEVER a production signing key.
"""
import base64
import hashlib
import json
import sqlite3
import sys
import tempfile
from pathlib import Path

repo = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo / 'legacy' / 'python'))
sys.path.insert(0, str(repo))
from dw.evidence import init_db, compress, roots, canonical_json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

with tempfile.TemporaryDirectory(prefix='DriveWitness-fixture-') as temp:
    db = init_db(Path(temp) / 'fixture.db')
    db.execute("INSERT INTO dw_scans(id,schema_version,status) VALUES(1,2,'COMPLETED')")
    paths = ['C:/café/😀.txt', 'C:/café/\ue000.txt', 'C:/zero', 'C:/gone', 'C:/error']
    rows = []
    for i, path in enumerate(paths):
        row = [1, path, compress(path), '0011223344556677', f'{i:032x}', i,
               1700000000123456700, 1700000000234567800, 1700000000345678900, 32,
               hashlib.sha256(('b3' + path).encode()).digest(), hashlib.sha256(path.encode()).digest(),
               None, 'FULL_DUAL_HASH', ['ADDED', 'UNCHANGED', 'MODIFIED', 'DELETED', 'ERROR'][i],
               1, 'RECALCULATED', None if i != 4 else 'ACCESS_DENIED', None if i != 4 else 'Permission café', 1, 1, 1,
               compress('2023-11-14T22:13:20.123456+00:00'), compress('2023-11-14T22:13:20.234567+00:00'),
               compress('2023-11-14T22:13:20.345678+00:00'), compress('scan-time')]
        db.execute('INSERT INTO dw_files VALUES(' + ','.join('?' for _ in row) + ')', row)
        rows.append([{'base64': base64.b64encode(x).decode()} if isinstance(x, bytes) else x for x in row])
    db.commit()
    calculated = roots(db, 1)
    manifest = {**calculated, 'scan_id': 1, 'sample': 'café 😀 <&>', 'float': 1.0, 'scope': {'roots': paths}}
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    fixture = {'rows': rows, 'roots': calculated, 'manifest': manifest,
               'canonical': canonical_json(manifest).decode(), 'signature': base64.b64encode(key.sign(canonical_json(manifest))).decode(),
               'public_key': base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode(),
               'encrypted_pem': key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(b'test-only')).decode()}
    db.close()
target = repo / 'tests' / 'DriveWitness.Tests' / 'Fixtures' / 'python-v2.json'
target.parent.mkdir(parents=True, exist_ok=True)
target.write_text(json.dumps(fixture, ensure_ascii=True, indent=2), encoding='utf-8')
print(target)
