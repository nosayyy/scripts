#!/usr/bin/env python3



import os, sys, json, hashlib, hmac, getpass, secrets, struct
from pathlib import Path

class Vault:
    PATH = Path(os.environ.get('PYPSW_VAULT',
                Path.home() / '.local/share/pypsw/vault.db'))
    N, R, P, SALT, NONCE, MAC = 1 << 15, 8, 1, 16, 16, 32

    def __init__(self, pw: str):
        self.pw = pw
        self.db = self._read() if self.PATH.exists() else None

    
    def _key(self, salt: bytes) -> bytes:
        return hashlib.scrypt(self.pw.encode(), salt=salt, n=self.N, r=self.R,
                              p=self.P, dklen=32, maxmem=128 << 20)

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
            raise ValueError('файл повреждён')
        salt = blob[:self.SALT]
        nonce = blob[self.SALT:self.SALT + self.NONCE]
        ct, mac = blob[self.SALT + self.NONCE:-self.MAC], blob[-self.MAC:]
        key = self._key(salt)
        if not hmac.compare_digest(mac, hmac.new(key, blob[:-self.MAC],
                                                 hashlib.sha256).digest()):
            raise ValueError('неверный пароль или файл повреждён')
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
            sys.exit(f'{name!r} уже есть')
        val = getpass.getpass('пароль (пусто = сгенерировать): ')
        if not val:
            val = secrets.token_urlsafe(16)
            print(f'сгенерировано: {val}')
        self.db[name] = val
        self.save(self.db)
        print(f'добавлено {name!r}')

    def get(self, name: str) -> None:
        if name not in self.db:
            sys.exit(f'{name!r} не найдено')
        print(self.db[name])

    def rm(self, name: str) -> None:
        if name not in self.db:
            sys.exit(f'{name!r} не найдено')
        if input(f'удалить {name!r}? [y/N] ').lower() == 'y':
            del self.db[name]
            self.save(self.db)
            print('удалено')


def ask(prompt='master: ', confirm=False) -> str:
    pw = getpass.getpass(prompt)
    if not pw:
        sys.exit('пустой пароль недопустим')
    if confirm and pw != getpass.getpass('confirm: '):
        sys.exit('пароли не совпадают')
    return pw


def main():
    args = sys.argv[1:]
    if not args:
        print('usage: pypsw {init|add|get|ls|rm|passwd} [args]')
        return
    cmd, rest = args[0], args[1:]

    if cmd == 'init':
        if Vault.PATH.exists():
            sys.exit(f'уже есть: {Vault.PATH}')
        Vault(ask('новый мастер: ', confirm=True)).save({})
        print(f'создано: {Vault.PATH}')
        return
    if cmd == 'passwd':
        v = Vault(ask())
        v.pw = ask('новый мастер: ', confirm=True)
        v.save(v.db)
        print('сменён')
        return

    v = Vault(ask())
    if cmd == 'add' and rest:      v.add(rest[0])
    elif cmd == 'get' and rest:    v.get(rest[0])
    elif cmd == 'ls':              [print(n) for n in sorted(v.db)]
    elif cmd == 'rm' and rest:     v.rm(rest[0])
    else:                          sys.exit(f'неизвестно: {cmd} {rest}')


if __name__ == '__main__':
    main()
