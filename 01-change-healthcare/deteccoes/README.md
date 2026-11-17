# Regras de detecção (Sigma)

Sete regras [Sigma](https://sigmahq.io/) que cobrem a cadeia do ataque à Change Healthcare, do login sem MFA até a nota de resgate. Sigma é um formato aberto de regras de detecção que pode ser convertido para a linguagem de qualquer SIEM (Splunk, Microsoft Sentinel, Elastic, QRadar).

| # | Regra | Etapa do ataque | ATT&CK | Severidade |
| --- | --- | --- | --- | --- |
| 01 | [Login sem MFA em acesso remoto](regras-sigma/01_login_acesso_remoto_sem_mfa.yml) | Acesso inicial | T1078, T1133 | Alta |
| 02 | [PsExec instalado como serviço](regras-sigma/02_psexec_instalado_como_servico.yml) | Movimentação lateral | T1569.002, T1021.002 | Média |
| 03 | [Logs de eventos apagados](regras-sigma/03_logs_de_eventos_apagados.yml) | Evasão de defesa | T1070.001 | Alta |
| 04 | [Consulta DNS ao MEGA](regras-sigma/04_exfiltracao_mega_dns.yml) | Exfiltração | T1567.002 | Média |
| 05 | [Rclone copiando dados](regras-sigma/05_rclone_exfiltracao.yml) | Exfiltração | T1567.002 | Alta |
| 06 | [Exclusão de cópias de sombra](regras-sigma/06_inibir_recuperacao_do_sistema.yml) | Impacto | T1490 | Alta |
| 07 | [Nota de resgate do ALPHV](regras-sigma/07_nota_de_resgate_alphv.yml) | Impacto | T1486 | Crítica |

A ordem importa: quanto mais cedo a regra dispara, menor o estrago. A regra 01 teria alertado no primeiro dia; a regra 07 só dispara quando a criptografia já começou.

## Validação

As regras foram validadas com o [sigma-cli](https://github.com/SigmaHQ/sigma-cli) 4.0.1, sem erros:

```bash
pip install sigma-cli pysigma-backend-splunk
sigma check regras-sigma/
# Found 0 errors, 0 condition errors and 0 issues.
```

> Os validadores de tags que baixam dados da internet (ATT&CK, D3FEND) foram desativados por falta de rede no ambiente; as tags ATT&CK foram conferidas manualmente.

## Exemplo de conversão para Splunk

```bash
sigma convert -t splunk --without-pipeline regras-sigma/06_inibir_recuperacao_do_sistema.yml
```

| # | Consulta Splunk gerada |
| --- | --- |
| 01 | `ResultType=0 AuthenticationRequirement="singleFactorAuthentication" (AppDisplayName IN ("*Citrix*", "*VPN*", "*Remote Desktop*"))` |
| 02 | `Provider_Name="Service Control Manager" EventID=7045 ServiceName="PSEXESVC"` |
| 03 | `(Image="*\\wevtutil.exe" OR OriginalFileName="wevtutil.exe") (CommandLine IN ("* cl *", "* clear-log *"))` |
| 04 | `QueryName IN ("*mega.nz", "*mega.co.nz", "*mega.io")` |
| 05 | `(Image="*\\rclone.exe" OR Description="Rsync for cloud storage") (CommandLine IN ("* copy *", "* sync *", "* mega:*", "*--config*"))` |
| 06 | `(Image="*\\vssadmin.exe" CommandLine="*delete*" CommandLine="*shadows*") OR (Image="*\\WMIC.exe" CommandLine="*shadowcopy*" CommandLine="*delete*") OR (Image="*\\bcdedit.exe" CommandLine="*recoveryenabled*" CommandLine="*no*")` |
| 07 | `TargetFilename="*\\RECOVER-*" TargetFilename="*-FILES.txt"` |

Em produção, use um *pipeline* que mapeie os campos para o seu ambiente (por exemplo `-p splunk_windows` para logs do Sysmon) e restrinja o índice e o sourcetype.

## Fontes de log necessárias

| Regra | Fonte de log |
| --- | --- |
| 01 | Logs de entrada do Microsoft Entra ID (Sign-in logs) |
| 02 | Log de Sistema do Windows (evento 7045) |
| 03, 05, 06 | Criação de processos: Sysmon evento 1 ou Windows 4688 com linha de comando |
| 04 | Consultas DNS: Sysmon evento 22 ou logs do servidor DNS |
| 07 | Criação de arquivos: Sysmon evento 11 ou EDR |

## Limitações

- A regra 01 usa campos do Microsoft Entra ID. Num Citrix Gateway puro, os campos equivalentes precisam ser ajustados ao parser do SIEM.
- As regras 02 e 05 podem gerar falsos positivos onde PsExec e Rclone são usados legitimamente: o ideal é manter uma lista de servidores e contas autorizados.
- Detecções por nome de arquivo (07) são fáceis de contornar; servem como último alarme, não como defesa principal.
- As regras não foram testadas contra telemetria real de ataque. O próximo passo seria simulá-las em laboratório com o [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team).
