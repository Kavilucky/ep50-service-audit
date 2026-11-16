#!/usr/bin/env python3
"""Расшифровка фото из журнала описи (AES-256-GCM) и сверка SHA-256.

Нужен пакет cryptography (pip install cryptography). Ключ берётся из ARCHIVE_KEY_HEX (файл .env), в командную строку не пишется.
Достаньте данные записи из базы (подставьте номер записи):
  docker compose exec -T postgres psql -U serviceaudit -d serviceaudit -At -c "SELECT encode(enc_iv,'hex'), encode(enc_tag,'hex'), encode(photo_enc,'hex'), image_sha256 FROM hardware_audit_log WHERE id = 1" > record.txt
Запуск:
  ARCHIVE_KEY_HEX=<ключ из .env> python decrypt_photo.py record.txt photo.jpg
Скрипт расшифрует файл, посчитает SHA-256 и сравнит с image_sha256 из журнала.
"""
import hashlib
import os
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    key_hex = os.environ.get("ARCHIVE_KEY_HEX", "")
    if len(key_hex) != 64:
        print("ARCHIVE_KEY_HEX должен быть 64 символа hex")
        return 2
    line = open(sys.argv[1], encoding="utf-8").read().strip().split("|")
    iv, tag, enc, sha = bytes.fromhex(line[0]), bytes.fromhex(line[1]), bytes.fromhex(line[2]), line[3].strip()
    plain = AESGCM(bytes.fromhex(key_hex)).decrypt(iv, enc + tag, None)
    got = hashlib.sha256(plain).hexdigest()
    open(sys.argv[2], "wb").write(plain)
    print("SHA-256 совпал с журналом" if got == sha else f"ВНИМАНИЕ: SHA-256 не совпал: {got} против {sha}")
    return 0 if got == sha else 1


if __name__ == "__main__":
    sys.exit(main())
