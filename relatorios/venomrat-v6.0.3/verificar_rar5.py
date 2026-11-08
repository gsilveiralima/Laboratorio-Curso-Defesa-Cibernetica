#!/usr/bin/env python3
"""Verificação defensiva e somente leitura de cabeçalhos de arquivos RAR 5.

Não descompacta arquivos, não executa amostras e não acessa rede.
A senha é pedida interativamente e não é gravada no relatório.

Dependência: python -m pip install rarfile
Uso: python verificar_rar5.py '/caminho/para/arquivo.rar'
"""
from __future__ import annotations

import argparse
from collections import Counter
from getpass import getpass
import hashlib
import hmac
from pathlib import Path
import sys

try:
    import rarfile
except ImportError:
    sys.exit("Dependência ausente. Instale com: python -m pip install rarfile")


def sha256_file(path: Path) -> str:
    dig = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            dig.update(chunk)
    return dig.hexdigest()


def verify_rar5_password(info: rarfile.RarInfo, password: bytes, cache: dict) -> str:
    """Verifica somente o campo de checagem do cabeçalho RAR 5.

    Resultado positivo NÃO garante integridade do conteúdo descompactado.
    """
    encryption = getattr(info, 'file_encryption', None)
    if not encryption:
        return 'indeterminada'
    algorithm, flags, kdf_count, salt, _iv, check = encryption
    if algorithm != 0 or not flags & 1 or not check or len(check) != 12:
        return 'indeterminada'
    if not 0 <= kdf_count <= 24:
        return 'indeterminada'
    if not hmac.compare_digest(hashlib.sha256(check[:8]).digest()[:4], check[8:]):
        return 'checagem_corrompida'

    key = (salt, kdf_count)
    if key not in cache:
        kdf_iterations = (1 << kdf_count) + 32
        material = hashlib.pbkdf2_hmac('sha256', password, salt, kdf_iterations, dklen=32)
        cache[key] = bytes(material[i] ^ material[i + 8] ^ material[i + 16] ^ material[i + 24]
                           for i in range(8))
    return 'correta_no_cabecalho' if hmac.compare_digest(cache[key], check[:8]) else 'incorreta'


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('arquivo', type=Path, help='Caminho do arquivo RAR 5')
    args = parser.parse_args()
    if not args.arquivo.is_file():
        parser.error('O caminho informado não é um arquivo válido.')

    password = getpass('Senha RAR (não será exibida): ').encode('utf-8')
    if not password:
        print('Senha vazia; análise encerrada.', file=sys.stderr)
        return 2

    try:
        with rarfile.RarFile(args.arquivo) as archive:
            entries = archive.infolist()
            files = [e for e in entries if not e.isdir()]
            counts = Counter()
            cache: dict = {}
            for entry in files:
                counts[verify_rar5_password(entry, password, cache)] += 1
            digest = sha256_file(args.arquivo)
            print('Formato: RAR 5 (estrutura parseada pela biblioteca rarfile)')
            print(f'SHA-256 do pacote: {digest}')
            print(f'Entradas: {len(entries)} | Arquivos: {len(files)} | Pastas: {len(entries)-len(files)}')
            print(f'Tamanho do RAR: {args.arquivo.stat().st_size:,} bytes')
            print(f'Tamanho descompactado informado pelos cabeçalhos: {sum(e.file_size for e in files):,} bytes')
            print('Verificação criptográfica dos cabeçalhos:')
            for outcome, num in sorted(counts.items()):
                print(f'  {outcome}: {num}')
            print('NOTA: sem extração, execução, rede ou verificação do payload descompactado.')
            return 0 if counts['correta_no_cabecalho'] == len(files) else 1
    except (OSError, rarfile.Error) as exc:
        print(f'Falha ao ler os metadados do RAR: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
