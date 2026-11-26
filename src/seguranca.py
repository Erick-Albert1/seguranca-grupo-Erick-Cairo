#!/usr/bin/env python3
"""seguranca - Ferramenta CLI de integridade (SHA-256) e assinatura digital (Ed25519).

Uso:
    python src/seguranca.py keygen chave_privada.pem chave_publica.pem
    python src/seguranca.py hash documento.txt
    python src/seguranca.py check documento.txt HASH_REFERENCIA
    python src/seguranca.py sign documento.txt chave_privada.pem assinatura.sig
    python src/seguranca.py verify documento.txt chave_publica.pem assinatura.sig

Codigos de saida:
    0 -> sucesso (hash correspondente / assinatura valida / operacao concluida)
    1 -> verificacao falhou (hash divergente / assinatura invalida)
    2 -> erro de uso ou de execucao (arquivo inexistente, chave incompativel etc.)
"""
import argparse
import hashlib
import os
import re
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

EXIT_OK = 0
EXIT_INVALIDO = 1
EXIT_ERRO = 2

TAMANHO_ASSINATURA = 64
REGEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ErroFerramenta(Exception):
    """Erro tratavel, exibido ao usuario com mensagem compreensivel."""


# --------------------------------------------------------------------------
# Funcoes auxiliares de E/S
# --------------------------------------------------------------------------
def ler_bytes(caminho, descricao="arquivo"):
    """Le um arquivo em modo binario, sem qualquer transformacao."""
    if not os.path.exists(caminho):
        raise ErroFerramenta(f"{descricao} nao encontrado: '{caminho}'")
    if os.path.isdir(caminho):
        raise ErroFerramenta(f"'{caminho}' e um diretorio, nao um {descricao}")
    try:
        with open(caminho, "rb") as f:
            return f.read()
    except OSError as e:
        raise ErroFerramenta(f"nao foi possivel ler '{caminho}': {e.strerror}")


def escrever_bytes(caminho, dados, privado=False):
    """Grava bytes em arquivo. Chaves privadas recebem permissao 0600 (POSIX)."""
    pasta = os.path.dirname(os.path.abspath(caminho))
    if not os.path.isdir(pasta):
        raise ErroFerramenta(f"diretorio de destino inexistente: '{pasta}'")
    try:
        fd = os.open(caminho, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600 if privado else 0o644)
        with os.fdopen(fd, "wb") as f:
            f.write(dados)
    except OSError as e:
        raise ErroFerramenta(f"nao foi possivel gravar '{caminho}': {e.strerror}")


# --------------------------------------------------------------------------
# Nucleo criptografico
# --------------------------------------------------------------------------
def sha256_arquivo(caminho):
    """Retorna o SHA-256 do arquivo (64 hex minusculos), lendo em blocos."""
    if not os.path.exists(caminho):
        raise ErroFerramenta(f"arquivo nao encontrado: '{caminho}'")
    if os.path.isdir(caminho):
        raise ErroFerramenta(f"'{caminho}' e um diretorio, nao um arquivo")
    h = hashlib.sha256()
    try:
        with open(caminho, "rb") as f:
            for bloco in iter(lambda: f.read(1024 * 1024), b""):
                h.update(bloco)
    except OSError as e:
        raise ErroFerramenta(f"nao foi possivel ler '{caminho}': {e.strerror}")
    return h.hexdigest()


def gerar_par_chaves():
    """Gera par Ed25519 e retorna (privada_pem_pkcs8, publica_pem_spki)."""
    privada = Ed25519PrivateKey.generate()
    pem_priv = privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pem_pub = privada.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem_priv, pem_pub


def carregar_chave_privada(caminho):
    pem = ler_bytes(caminho, "chave privada")
    try:
        chave = serialization.load_pem_private_key(pem, password=None)
    except (ValueError, TypeError) as e:
        raise ErroFerramenta(f"'{caminho}' nao e uma chave privada PEM (PKCS#8) valida: {e}")
    if not isinstance(chave, Ed25519PrivateKey):
        raise ErroFerramenta(f"chave incompativel: '{caminho}' nao e uma chave Ed25519")
    return chave


def carregar_chave_publica(caminho):
    pem = ler_bytes(caminho, "chave publica")
    try:
        chave = serialization.load_pem_public_key(pem)
    except (ValueError, TypeError) as e:
        raise ErroFerramenta(f"'{caminho}' nao e uma chave publica PEM (SubjectPublicKeyInfo) valida: {e}")
    if not isinstance(chave, Ed25519PublicKey):
        raise ErroFerramenta(f"chave incompativel: '{caminho}' nao e uma chave Ed25519")
    return chave


# --------------------------------------------------------------------------
# Comandos
# --------------------------------------------------------------------------
def cmd_keygen(args):
    if os.path.abspath(args.chave_privada) == os.path.abspath(args.chave_publica):
        raise ErroFerramenta("os caminhos das chaves privada e publica devem ser diferentes")
    for destino in (args.chave_privada, args.chave_publica):
        if os.path.exists(destino) and not args.force:
            raise ErroFerramenta(f"'{destino}' ja existe; use --force para sobrescrever")
    pem_priv, pem_pub = gerar_par_chaves()
    escrever_bytes(args.chave_privada, pem_priv, privado=True)
    escrever_bytes(args.chave_publica, pem_pub)
    print(f"Chave privada gravada em: {args.chave_privada}")
    print(f"Chave publica gravada em: {args.chave_publica}")
    print("ATENCAO: mantenha a chave privada em sigilo.")
    return EXIT_OK


def cmd_hash(args):
    print(sha256_arquivo(args.arquivo))
    return EXIT_OK


def cmd_check(args):
    referencia = args.hash_referencia.strip().lower()
    if not REGEX_SHA256.match(referencia):
        raise ErroFerramenta("hash de referencia invalido: deve ter 64 caracteres hexadecimais")
    calculado = sha256_arquivo(args.arquivo)
    if calculado == referencia:
        print("HASH VALIDO: o hash do arquivo corresponde a referencia.")
        print(f"SHA-256: {calculado}")
        return EXIT_OK
    print("HASH DIVERGENTE: o hash do arquivo NAO corresponde a referencia.")
    print(f"Calculado:  {calculado}")
    print(f"Referencia: {referencia}")
    return EXIT_INVALIDO


def cmd_sign(args):
    dados = ler_bytes(args.arquivo, "arquivo")
    chave = carregar_chave_privada(args.chave_privada)
    # Ed25519 aplicado diretamente aos bytes originais (sem pre-hash)
    assinatura = chave.sign(dados)
    escrever_bytes(args.assinatura, assinatura)
    print(f"Assinatura ({len(assinatura)} bytes) gravada em: {args.assinatura}")
    return EXIT_OK


def cmd_verify(args):
    dados = ler_bytes(args.arquivo, "arquivo")
    chave = carregar_chave_publica(args.chave_publica)
    assinatura = ler_bytes(args.assinatura, "arquivo de assinatura")
    if len(assinatura) != TAMANHO_ASSINATURA:
        print(
            f"ASSINATURA INVALIDA: o arquivo de assinatura tem {len(assinatura)} bytes "
            f"(esperado: {TAMANHO_ASSINATURA})."
        )
        return EXIT_INVALIDO
    try:
        chave.verify(assinatura, dados)
    except InvalidSignature:
        print("ASSINATURA INVALIDA: arquivo adulterado, chave incorreta ou assinatura corrompida.")
        return EXIT_INVALIDO
    print("ASSINATURA VALIDA: o arquivo e autentico e nao foi alterado.")
    return EXIT_OK


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        print(f"Erro: {message}", file=sys.stderr)
        sys.exit(EXIT_ERRO)


def montar_parser():
    p = _Parser(prog="seguranca", description="Hash SHA-256 e assinatura digital Ed25519.")
    sub = p.add_subparsers(dest="comando", required=True, parser_class=_Parser)

    s = sub.add_parser("keygen", help="gera par de chaves Ed25519 (PEM)")
    s.add_argument("chave_privada")
    s.add_argument("chave_publica")
    s.add_argument("--force", action="store_true", help="sobrescreve arquivos existentes")
    s.set_defaults(func=cmd_keygen)

    s = sub.add_parser("hash", help="calcula o SHA-256 de um arquivo")
    s.add_argument("arquivo")
    s.set_defaults(func=cmd_hash)

    s = sub.add_parser("check", help="compara o SHA-256 do arquivo com uma referencia")
    s.add_argument("arquivo")
    s.add_argument("hash_referencia")
    s.set_defaults(func=cmd_check)

    s = sub.add_parser("sign", help="assina um arquivo com a chave privada")
    s.add_argument("arquivo")
    s.add_argument("chave_privada")
    s.add_argument("assinatura")
    s.set_defaults(func=cmd_sign)

    s = sub.add_parser("verify", help="verifica a assinatura de um arquivo")
    s.add_argument("arquivo")
    s.add_argument("chave_publica")
    s.add_argument("assinatura")
    s.set_defaults(func=cmd_verify)
    return p


def main(argv=None):
    args = montar_parser().parse_args(argv)
    try:
        return args.func(args)
    except ErroFerramenta as e:
        print(f"Erro: {e}", file=sys.stderr)
        return EXIT_ERRO


if __name__ == "__main__":
    sys.exit(main())
