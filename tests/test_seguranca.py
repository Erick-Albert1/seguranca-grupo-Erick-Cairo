"""Testes automatizados (TI01-TI06 + tratamento de erros).

Execucao (a partir da raiz do repositorio):
    python -m unittest discover -s tests -v
Usa apenas a biblioteca padrao + 'cryptography'. Todos os dados sao ficticios.
"""
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(RAIZ, "src", "seguranca.py")


def rd(caminho):
    with open(caminho, "rb") as f:
        return f.read()


def wr(caminho, dados):
    with open(caminho, "wb") as f:
        f.write(dados)


def run(*args):
    return subprocess.run(
        [sys.executable, CLI, *map(str, args)], capture_output=True, text=True
    )


class BaseTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.d = self._tmp.name
        self.doc = self.p("documento.txt")
        with open(self.doc, "wb") as f:
            f.write("Certificado FICTICIO - Fulano de Tal\n".encode("utf-8") + b"\x00\xff bytes\r\n")
        self.priv, self.pub, self.sig = self.p("priv.pem"), self.p("pub.pem"), self.p("a.sig")

    def tearDown(self):
        self._tmp.cleanup()

    def p(self, nome):
        return os.path.join(self.d, nome)

    def hash_ref(self, caminho):
        with open(caminho, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    def keygen(self, priv=None, pub=None):
        r = run("keygen", priv or self.priv, pub or self.pub)
        self.assertEqual(r.returncode, 0, r.stderr)

    def alterar(self, caminho):
        with open(caminho, "ab") as f:
            f.write(b" ")


class TestHash(BaseTest):
    def test_TI01_hash_correto(self):
        r = run("hash", self.doc)
        self.assertEqual(r.returncode, 0)
        saida = r.stdout.strip()
        self.assertEqual(saida, self.hash_ref(self.doc))
        self.assertRegex(saida, r"^[0-9a-f]{64}$")

    def test_hash_vetor_conhecido(self):
        vazio = self.p("vazio")
        wr(vazio, b"")
        self.assertEqual(
            run("hash", vazio).stdout.strip(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )

    def test_check_correto(self):
        r = run("check", self.doc, self.hash_ref(self.doc))
        self.assertEqual(r.returncode, 0)
        self.assertIn("VALIDO", r.stdout)

    def test_check_aceita_maiusculas(self):
        r = run("check", self.doc, self.hash_ref(self.doc).upper())
        self.assertEqual(r.returncode, 0)

    def test_TI02_arquivo_modificado_diverge(self):
        ref = self.hash_ref(self.doc)
        self.alterar(self.doc)
        r = run("check", self.doc, ref)
        self.assertEqual(r.returncode, 1)
        self.assertIn("DIVERGENTE", r.stdout)

    def test_check_referencia_malformada(self):
        r = run("check", self.doc, "abc123")
        self.assertEqual(r.returncode, 2)
        self.assertIn("Erro", r.stderr)

    def test_hash_arquivo_inexistente(self):
        r = run("hash", self.p("nao_existe.txt"))
        self.assertEqual(r.returncode, 2)
        self.assertIn("nao encontrado", r.stderr)

    def test_hash_diretorio(self):
        self.assertEqual(run("hash", self.d).returncode, 2)


class TestChaves(BaseTest):
    def test_TI03_gera_pem_validos(self):
        self.keygen()
        with open(self.priv, "rb") as f:
            self.assertTrue(f.read().startswith(b"-----BEGIN PRIVATE KEY-----"))  # PKCS#8
        with open(self.pub, "rb") as f:
            self.assertTrue(f.read().startswith(b"-----BEGIN PUBLIC KEY-----"))  # SPKI
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey, Ed25519PublicKey)
        k1 = serialization.load_pem_private_key(rd(self.priv), None)
        k2 = serialization.load_pem_public_key(rd(self.pub))
        self.assertIsInstance(k1, Ed25519PrivateKey)
        self.assertIsInstance(k2, Ed25519PublicKey)

    def test_keygen_nao_sobrescreve_sem_force(self):
        self.keygen()
        self.assertEqual(run("keygen", self.priv, self.pub).returncode, 2)
        self.assertEqual(run("keygen", self.priv, self.pub, "--force").returncode, 0)

    @unittest.skipIf(os.name == "nt", "permissoes POSIX")
    def test_chave_privada_permissao_restrita(self):
        self.keygen()
        self.assertEqual(os.stat(self.priv).st_mode & 0o077, 0)


class TestAssinatura(BaseTest):
    def test_TI04_assinar_e_verificar(self):
        self.keygen()
        r = run("sign", self.doc, self.priv, self.sig)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(os.path.getsize(self.sig), 64)
        r = run("verify", self.doc, self.pub, self.sig)
        self.assertEqual(r.returncode, 0)
        self.assertIn("ASSINATURA VALIDA", r.stdout)

    def test_assinatura_sem_prehash(self):
        """A assinatura deve ser sobre os bytes originais, nao sobre o hash."""
        from cryptography.hazmat.primitives import serialization
        self.keygen()
        run("sign", self.doc, self.priv, self.sig)
        pub = serialization.load_pem_public_key(rd(self.pub))
        pub.verify(rd(self.sig), rd(self.doc))

    def test_TI05_arquivo_alterado_apos_assinatura(self):
        self.keygen()
        run("sign", self.doc, self.priv, self.sig)
        self.alterar(self.doc)
        r = run("verify", self.doc, self.pub, self.sig)
        self.assertEqual(r.returncode, 1)
        self.assertIn("INVALIDA", r.stdout)
        self.assertNotIn("ASSINATURA VALIDA", r.stdout)

    def test_TI06_outra_chave_publica(self):
        self.keygen()
        run("sign", self.doc, self.priv, self.sig)
        self.keygen(self.p("priv2.pem"), self.p("pub2.pem"))
        r = run("verify", self.doc, self.p("pub2.pem"), self.sig)
        self.assertEqual(r.returncode, 1)
        self.assertIn("INVALIDA", r.stdout)

    def test_assinatura_corrompida(self):
        self.keygen()
        run("sign", self.doc, self.priv, self.sig)
        b = bytearray(rd(self.sig))
        b[0] ^= 0x01
        wr(self.sig, bytes(b))
        self.assertEqual(run("verify", self.doc, self.pub, self.sig).returncode, 1)

    def test_assinatura_tamanho_errado(self):
        self.keygen()
        wr(self.sig, b"curta")
        r = run("verify", self.doc, self.pub, self.sig)
        self.assertEqual(r.returncode, 1)
        self.assertIn("INVALIDA", r.stdout)

    def test_arquivo_inexistente(self):
        self.keygen()
        self.assertEqual(run("sign", self.p("x"), self.priv, self.sig).returncode, 2)
        run("sign", self.doc, self.priv, self.sig)
        self.assertEqual(run("verify", self.p("x"), self.pub, self.sig).returncode, 2)

    def test_chave_inexistente(self):
        self.assertEqual(run("sign", self.doc, self.p("x.pem"), self.sig).returncode, 2)

    def test_chave_incompativel_rsa(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        rsa_k = rsa.generate_private_key(65537, 2048)
        wr(self.priv, rsa_k.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        wr(self.pub, rsa_k.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        r = run("sign", self.doc, self.priv, self.sig)
        self.assertEqual(r.returncode, 2)
        self.assertIn("incompativel", r.stderr)
        wr(self.sig, b"\x00" * 64)
        self.assertEqual(run("verify", self.doc, self.pub, self.sig).returncode, 2)

    def test_chave_pem_invalida(self):
        wr(self.pub, b"isto nao e PEM")
        wr(self.sig, b"\x00" * 64)
        self.assertEqual(run("verify", self.doc, self.pub, self.sig).returncode, 2)

    def test_chave_trocada_de_papel(self):
        self.keygen()
        self.assertEqual(run("sign", self.doc, self.pub, self.sig).returncode, 2)


class TestCLI(BaseTest):
    def test_sem_argumentos(self):
        self.assertNotEqual(run().returncode, 0)

    def test_comando_desconhecido(self):
        self.assertNotEqual(run("foo").returncode, 0)


if __name__ == "__main__":
    unittest.main()
