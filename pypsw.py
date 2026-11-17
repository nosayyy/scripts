#!/usr/bin/env python3

"""
     pypsw - minimal password manager
    ==================================

    One python file, stdlib only. Stores
    "name: password" pairs in one encrypted
    file. Crypto: scrypt (KDF) + SHA256-CTR
    (cipher) + HMAC-SHA256 (MAC, encrypt-then-MAC).
    No custom primitives.

    License: MIT
    
"""

import os, sys, json, hashlib, hmac, getpass, secrets, struct
from pathlib import Path

class Vault:
    PATH = Path(os.environ.get('PYPSW_VAULT', Path.home() / '.local/share/pypsw/vault.db'))
    N, R, P, SALT, NONCE, MAC = 1 << 15, 8, 1, 16, 16, 32

    def __init__(self, pw: str):
        self.pw = pw
        self.db = self._read() if self.PATH.exists() else None

    def _key(self, salt: bytes) -> bytes:
        return hashlib.scrypt(self.pw.encode(), salt=salt, n=self.N, r=self.R, p=self.P, dklen=32, maxmem=128 << 20)

    @staticmethod
    def _xor(key: bytes, nonce: bytes, data: bytes) -> bytes:
        out = bytearray(len(data))
        for i in range(0, len(data), 32):
            blk = hashlib.sha256(key + nonce + struct.pack('<Q', i // 32)).digest()
            for j, (b, k) in enumerate(zip(data[i:i + 32], blk)):
                out[i + j] = b ^ k
        return bytes(out)

    def _encrypt(self, plain: bytes) -> bytes:
        salt, nonce = secrets.token_bytes(self.SALT), secrets.token_bytes(self.NONCE)
        key = self._key(salt)
        head = salt + nonce + self._xor(key, nonce, plain)
        return head + hmac.new(key, head, hashlib.sha256).digest()

    def _decrypt(self, blob: bytes) -> bytes:
        if len(blob) < self.SALT + self.NONCE + self.MAC:
            raise ValueError('File is corrupted')
        salt = blob[:self.SALT]
        nonce = blob[self.SALT:self.SALT + self.NONCE]
        ct, mac = blob[self.SALT + self.NONCE:-self.MAC], blob[-self.MAC:]
        key = self._key(salt)
        if not hmac.compare_digest(mac, hmac.new(key, blob[:-self.MAC], hashlib.sha256).digest()):
            raise ValueError('incorrect password or file is corrupted')
        return self._xor(key, nonce, ct)
      
    def _read(self) -> dict:
        return json.loads(self._decrypt(self.PATH.read_bytes()))

    def save(self, db: dict) -> None:
        self.PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.PATH.with_suffix('.tmp')
        tmp.write_bytes(self._encrypt(json.dumps(db).encode()))
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.PATH)
        self.db = db

    def add(self, name: str) -> None:
        if name in self.db:
            sys.exit(f'{name!r} already exists')
        val = getpass.getpass('password (null = generate): ')
        if not val:
            val = secrets.token_urlsafe(16)
            print(f'gen: {val}')
        self.db[name] = val
        self.save(self.db)
        print(f'added {name!r}')

    def get(self, name: str) -> None:
        if name not in self.db:
            sys.exit(f'{name!r} not found')
        print(self.db[name])

    def rm(self, name: str) -> None:
        if name not in self.db:
            sys.exit(f'{name!r} not found')
        if input(f'delete {name!r}? [y/N] ').lower() == 'y':
            del self.db[name]
            self.save(self.db)
            print('deleted')


def ask(prompt='master: ', confirm=False) -> str:
    pw = getpass.getpass(prompt)
    if not pw:
        sys.exit('an empty password is not allowed')
    if confirm and pw != getpass.getpass('confirm: '):
        sys.exit('passwords dont match)
    return pw


def main():
    args = sys.argv[1:]
    if not args:
        print('usage: pypsw {init|add|get|ls|rm|passwd} [args]')
        return
    cmd, rest = args[0], args[1:]

    if cmd == 'init':
        if Vault.PATH.exists():
            sys.exit(f'already exists: {Vault.PATH}')
        Vault(ask('new master: ', confirm=True)).save({})
        print(f'created: {Vault.PATH}')
        return
        
    if cmd == 'passwd':
        v = Vault(ask())
        v.pw = ask('new master: ', confirm=True)
        v.save(v.db)
        print('replaced')
        return

    v = Vault(ask())
    if cmd == 'add' and rest:      v.add(rest[0])
    elif cmd == 'get' and rest:    v.get(rest[0])
    elif cmd == 'ls':              [print(n) for n in sorted(v.db)]
    elif cmd == 'rm' and rest:     v.rm(rest[0])
    else:                          sys.exit(f'unknown: {cmd} {rest}')


if __name__ == '__main__':
    main()
