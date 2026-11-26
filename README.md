# seguranca — Ferramenta CLI de Integridade e Assinatura Digital

Trabalho Prático — Etapa 1 · Segurança da Informação  
Ferramenta de linha de comando em **Python 3** para calcular/comparar **SHA-256** e gerar chaves, assinar e verificar com **Ed25519**.

## Requisitos
- Python 3.9 ou superior
- Biblioteca [`cryptography`](https://cryptography.io) (mantida pela PyCA)

## Instalação
```bash
git clone <https://github.com/Erick-Albert1/seguranca-grupo-Erick-Cairo.git>
cd seguranca-grupo-Erick-Cairo
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Execução
O comando lógico `seguranca` corresponde a `python src/seguranca.py` (Windows: `python src\seguranca.py`).

| Operação | Comando |
|---|---|
| Gerar chaves (R01) | `python src/seguranca.py keygen chave_privada.pem chave_publica.pem` |
| Calcular hash (R02) | `python src/seguranca.py hash documento.txt` |
| Comparar hash (R03) | `python src/seguranca.py check documento.txt HASH_REFERENCIA` |
| Assinar (R04) | `python src/seguranca.py sign documento.txt chave_privada.pem assinatura.sig` |
| Verificar (R05/R06) | `python src/seguranca.py verify documento.txt chave_publica.pem assinatura.sig` |

Opção extra: `keygen ... --force` sobrescreve chaves existentes (por padrão a ferramenta se recusa a sobrescrever).

### Códigos de saída
| Código | Significado |
|---|---|
| `0` | Sucesso (hash corresponde / assinatura válida / operação concluída) |
| `1` | Verificação falhou (hash divergente / assinatura inválida) |
| `2` | Erro de uso ou execução (arquivo inexistente, chave incompatível, argumentos inválidos…) |

### Exemplo completo
```bash
python src/seguranca.py keygen priv.pem pub.pem
python src/seguranca.py hash exemplos/documento.txt
python src/seguranca.py check exemplos/documento.txt <hash_impresso_acima>
python src/seguranca.py sign exemplos/documento.txt priv.pem doc.sig
python src/seguranca.py verify exemplos/documento.txt pub.pem doc.sig   # ASSINATURA VALIDA (saida 0)
echo "alteracao" >> exemplos/documento.txt
python src/seguranca.py verify exemplos/documento.txt pub.pem doc.sig   # ASSINATURA INVALIDA (saida 1)
```
> Após o teste, restaure o arquivo de exemplo com `git checkout exemplos/documento.txt`.

## Contrato de interoperabilidade
- Hash: SHA-256, 64 caracteres hexadecimais minúsculos (aceita referência em maiúsculas no `check`).
- Assinatura: Ed25519 sobre os **bytes originais** do arquivo (sem pré-hash), arquivo binário de **exatamente 64 bytes**.
- Chave pública: PEM `SubjectPublicKeyInfo` (`BEGIN PUBLIC KEY`).
- Chave privada: PEM PKCS#8 sem senha (`BEGIN PRIVATE KEY`), gravada com permissão `0600` em sistemas POSIX.
- Arquivos lidos em modo binário, sem normalização.

## Testes automatizados
```bash
python -m unittest discover -s tests -v
```
Cobrem TI01–TI06 e tratamento de erros (arquivo/chave inexistente, chave RSA incompatível, PEM inválido, assinatura corrompida ou de tamanho incorreto, hash malformado). Evidências em [`docs/evidencias_testes.txt`](docs/evidencias_testes.txt).

## Estrutura
```
├── README.md
├── requirements.txt
├── src/seguranca.py
├── tests/test_seguranca.py
├── exemplos/documento.txt        (dado fictício)
└── docs/
    ├── RELATORIO_TECNICO.md
    └── evidencias_testes.txt
```

## Entrega
Versão avaliada: tag **`v1.0-entrega`**.

> Aviso: chaves geradas por este projeto são didáticas. Nunca versione chaves privadas reais (`*.pem` está no `.gitignore`).
