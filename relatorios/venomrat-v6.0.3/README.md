# VenomRAT v6.0.3 — análise estática preliminar (laboratório)

**Data:** 08/11/2026  
**Escopo:** inspeção de cabeçalhos RAR 5, nomes de arquivos, metadados e verificação de senha, sem executar ou descompactar o programa.

> Este repositório contém apenas documentação defensiva. **Nenhuma amostra, executável, DLL, chave, cookie ou credencial foi publicada aqui.**

## Identificação

| Propriedade | Resultado |
| --- | --- |
| Arquivo original analisado | `VenomRAT v6.0.3.rar` |
| SHA-256 do RAR | `aebd73bf1d395815e6673b39f400384ad5eaad4265260da7923e4c600d32a5b8` |
| Tamanho | 100.590.483 bytes (95,93 MiB) |
| Tamanho descompactado **declarado nos cabeçalhos** | 303.146.222 bytes (289,10 MiB) |
| Entradas / arquivos / diretórios | 306 / 282 / 24 |
| Estrutura do código | 118 `.cs`, 100 `.dll`, 29 `.resx`, 9 `.exe` |
| Período dos carimbos de arquivo | 15/03/2022–29/05/2024 UTC (não confiável como prova de origem) |
| Payload executado | **Não** |
| Extração de payload | **Não** |

## Verificação criptográfica dos cabeçalhos

Os **282 arquivos criptografados** continham registros de verificação RAR 5 consistentes com a senha informada separadamente pelo responsável pelo laboratório. Todos os 282 verificadores foram confirmados usando PBKDF2-HMAC-SHA256 e a checagem própria de RAR 5; uma senha de controle incorreta falhou em três entradas testadas.

**Importante:** esta etapa apenas valida a senha nos cabeçalhos. **Não confirma o checksum dos arquivos descompactados**, sua autenticidade, suas assinaturas ou o funcionamento dos componentes. O mecanismo disponível para ler os payloads apresentou erro de checksum mesmo após a confirmação dos valores de senha, então não houve extração validada.

Por segurança, a senha **não** é armazenada neste relatório.

## Sinais observados apenas nos nomes do pacote

- `Client.exe`, executáveis em `Stub/`: possíveis componentes cliente/stubs.
- `Keylogger.exe` e `Plugins/hvnc.exe`: indícios nominais de captura de digitação e área de trabalho virtual oculta.
- `FormRemoteDesktop.cs`, `HandleWebcam.cs`, `HandlePassword.cs`, `HandleStealer.cs`, `FormReverseProxy.cs`: código-fonte listado por nome, **não extraído nem inspecionado**.
- `ClientsFolder/.../Recovery/`: possíveis dados de navegação/credenciais; **nenhum conteúdo foi lido ou divulgado**.
- Arquivo de extensão `.p12`: possível material de certificado/chave; **nenhum conteúdo foi lido ou divulgado**.

Os nomes sustentam hipóteses de capacidade, **não provas de execução**.

## Contexto de terceiros (não atribuído automaticamente a esta amostra)

A Microsoft descreve VenomRAT como um trojan de acesso remoto e roubo de informações. A Proofpoint descreveu em 13/11/2025 a interrupção de infraestrutura ligada à família.

- [Microsoft Security Intelligence — VenomRAT](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan%3AWin32%2FVenomRAT%21AMTB)
- [Proofpoint — VenomRAT is defanged (2025)](https://www.proofpoint.com/us/blog/threat-insight/security-brief-venomrat-defanged)
- [RAR 5.0 — especificação técnica](https://www.rarlab.com/technote.htm)

## Limites e próximos passos

**Risco preliminar: elevado.** Ainda não foram verificados: hashes de arquivos internos, indicadores de C2, persistência, tráfego, assinaturas, comportamentos em execução ou integridade de payloads. O próximo passo correto é uma extração **somente em laboratório isolado**, com ferramenta compatível e verificação posterior de integridade, seguida de inspeção estática de PE/.NET sem executar binários.

**Não** enviar malware, dados privados, certificados ou credenciais ao GitHub ou a plataformas públicas de análise.  
**Estado deste registro:** análise de metadados, não laudo definitivo.
