# Relatório Técnico — Etapa 1

## 7.1 Identificação
- **Integrantes:** <ERICK ALBERT> · <CAIRO JOSÉ> 
- **Turma:** <TURMA V>
- **Linguagem:** Python 3.12
- **Repositório:** <https://github.com/Erick-Albert1/seguranca-grupo-Erick-Cairo.git> (tag `v1.0-entrega`)

## 7.2 Descrição da Solução
- **Bibliotecas:** `hashlib` (SHA-256, biblioteca padrão), `cryptography` (Ed25519, PEM PKCS#8/SPKI), `argparse`, `unittest`.
- **Organização:** `src/seguranca.py` concentra o núcleo criptográfico (`sha256_arquivo`, `gerar_par_chaves`, `carregar_chave_*`), os comandos (`cmd_*`) e a CLI. Testes em `tests/`, exemplo fictício em `exemplos/`.
- **Decisões técnicas:** (i) assinatura Ed25519 sobre os bytes originais, sem pré-hash; (ii) leitura binária; hash calculado em blocos de 1 MiB; (iii) códigos de saída distintos: `0` sucesso, `1` verificação falhou, `2` erro; (iv) validação do tipo de chave (rejeita RSA/EC); (v) `keygen` não sobrescreve arquivos sem `--force` e grava a chave privada com permissão 0600; (vi) assinatura com tamanho ≠ 64 bytes é tratada como inválida; (vii) mensagens de erro em `stderr`, resultados em `stdout`.

## 7.3 Funcionalidades Implementadas
| Req. | Atendimento |
|---|---|
| R01 | `keygen` gera Ed25519; privada PKCS#8, pública SPKI (PEM) |
| R02 | `hash` imprime SHA-256 (64 hex minúsculos) |
| R03 | `check` compara com a referência (normaliza caixa; valida formato) |
| R04 | `sign` grava 64 bytes de assinatura |
| R05 | `verify` valida com a chave pública |
| R06 | `verify` retorna código 1 e "ASSINATURA INVALIDA" para adulteração, chave errada ou assinatura corrompida |

## 7.4 Testes Realizados
Comando: `python -m unittest discover -s tests -v` — 24 testes, todos aprovados. Evidências: `docs/evidencias_testes.txt`.

| ID | Teste | Resultado obtido | Evidência |
|---|---|---|---|
| TI01 | SHA-256 de um arquivo | Hash correto (confere com `hashlib` e vetor conhecido) | `test_TI01_hash_correto`, `test_hash_vetor_conhecido` |
| TI02 | Modificar arquivo e comparar | Divergência, saída 1 | `test_TI02_arquivo_modificado_diverge` |
| TI03 | Gerar par de chaves | PEM PKCS#8 / SPKI válidos, Ed25519 | `test_TI03_gera_pem_validos` |
| TI04 | Assinar e verificar original | Assinatura válida, 64 bytes, saída 0 | `test_TI04_assinar_e_verificar` |
| TI05 | Alterar após assinatura | Inválida, saída 1 | `test_TI05_arquivo_alterado_apos_assinatura` |
| TI06 | Outra chave pública | Inválida, saída 1 | `test_TI06_outra_chave_publica` |
| Extra | Erros (arquivo/chave inexistente, RSA, PEM inválido, assinatura curta/corrompida, hash malformado) | Saída 2 (ou 1 para assinatura inválida) com mensagem clara | classes `TestHash`, `TestAssinatura` |

## 7.5 Análise Técnica e Conclusão
**Limitações:** chave privada sem senha; ausência de identidade vinculada à chave pública (sem certificado/PKI); assinatura "destacada" sem carimbo de tempo; arquivo inteiro carregado em memória para assinar (requisito do Ed25519 puro); sem revogação de chaves.

1. **Por que um hash isolado não comprova autoria?** Qualquer pessoa pode calcular o SHA-256 de qualquer arquivo e ele não depende de segredo; o hash só detecta alteração (integridade) se o valor de referência vier por canal confiável. Um atacante que altera o documento pode simplesmente recalcular e substituir o hash.
2. **Função das chaves:** a chave privada, mantida em sigilo pelo signatário, produz a assinatura; a chave pública, distribuída livremente, permite a qualquer um verificá-la, sem permitir gerar novas assinaturas. Assim se obtém autenticidade e não repúdio (desde que a chave pública esteja vinculada à identidade correta).
3. **Por que a alteração invalida a assinatura?** A assinatura é função matemática dos bytes exatos do documento e da chave privada. Qualquer mudança, mesmo de 1 bit, altera a mensagem e a equação de verificação Ed25519 deixa de ser satisfeita.
4. **Cuidados para produção:** proteger a chave privada (senha/KDF, HSM ou cofre, permissões, rotação e revogação); certificados/PKI para vincular chave à instituição; carimbo de tempo; distribuição autenticada da chave pública; logs de auditoria; auditoria do código e atualização das dependências; verificação de integridade da própria ferramenta (ex.: dependências com hash fixado).

**Conclusão:** a ferramenta atende R01–R06 com testes automatizados e interface compatível com o contrato de interoperabilidade.
