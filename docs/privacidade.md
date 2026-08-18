# Privacidade e exposição de rede do vega-web

Este documento descreve o que o `vega-web` expõe na rede, para quem, e quais
riscos ficam por sua conta ao habilitá-lo — leia antes de rodar
`systemctl enable --now vega-web` numa máquina alcançável além da sua LAN
confiável.

## Resumo

`vega-web` é pensado para uso **somente dentro de uma rede confiável**
(LAN doméstica/escritório). Ele não tem certificado de uma autoridade
pública — o certificado é autoassinado, gerado na própria máquina no
primeiro start. Isso significa que **todo navegador vai mostrar um aviso de
"autoridade não confiável"** na primeira visita; o nome usado no acesso deve
estar em `VEGA_WEB_TLS_NAMES`, evitando também um erro de identidade. Isso é
esperado e não indica um ataque, mas também significa que não há proteção
automática contra um servidor falso se impersonando na rede — só use em
redes em que você confia nos outros dispositivos.

## O que é exposto

- **Antes do login**: só a página de login em si (formulário
  usuário/senha) e a negociação TLS. Nenhum dado do sistema é acessível sem
  autenticação — inclusive as páginas somente-leitura exigem sessão válida.
- **Depois do login**: dados dos módulos de administração somente-leitura.
  O terminal exige uma segunda autenticação e só abre para contas do grupo
  `wheel`; ele é um shell completo e, portanto, tem a mesma capacidade da
  conta em uma sessão SSH, inclusive `sudo` quando a política local permitir.
- **Credenciais**: a senha digitada no login é usada uma única vez, na
  chamada a `pam_authenticate`, e não é armazenada em nenhum lugar — nem em
  log, nem em disco, nem na sessão. A sessão guarda só o nome do usuário.

## Autenticação

O login usa as contas Linux já existentes na máquina via PAM (serviço
`vega-web`, `/etc/pam.d/vega-web` — inclui as mesmas regras de
`common-auth`/`common-account` usadas pelo resto do sistema). Isso quer
dizer que qualquer política que já vale para o login do sistema
(bloqueio por tentativas, expiração de senha, contas desabilitadas) também
vale aqui, automaticamente.

## Proteções operacionais

- Tentativas de login são limitadas por IP e usuário, com atraso progressivo,
  recuperação após 15 minutos e no máximo quatro autenticações PAM simultâneas.
- Sessões expiram após 30 minutos sem atividade ou 12 horas absolutas. O
  armazenamento aceita até 1024 sessões, no máximo 10 por usuário.
- Sucessos, falhas, bloqueios e saturação do PAM são registrados no journal,
  sem registrar senhas.
- **Sessão em memória**: reiniciar o serviço desloga todo mundo (não é
  vazamento, mas pode surpreender).
- **Sem 2FA**: só usuário/senha, como qualquer outro consumidor de PAM sem
  módulos adicionais configurados.
- O terminal exige novamente a senha, consome a autorização no primeiro
  WebSocket, limita mensagens a 64 KiB e aceita no máximo quatro sessões
  simultâneas por padrão. Fechar a conexão encerra o grupo de processos do PTY.

Os limites podem ser ajustados por `VEGA_WEB_LOGIN_ATTEMPTS`,
`VEGA_WEB_LOGIN_RECOVERY_SECS`, `VEGA_WEB_LOGIN_DELAY_MS`,
`VEGA_WEB_LOGIN_MAX_DELAY_SECS`, `VEGA_WEB_PAM_CONCURRENCY`,
`VEGA_WEB_SESSION_IDLE_SECS`, `VEGA_WEB_SESSION_MAX_SECS`,
`VEGA_WEB_SESSION_GLOBAL_LIMIT`, `VEGA_WEB_SESSION_USER_LIMIT` e
`VEGA_WEB_TERMINAL_LIMIT`.

## Certificados

O certificado autoassinado inclui os nomes de `VEGA_WEB_TLS_NAMES`. Se esses
nomes mudarem, o serviço recusa o certificado incompatível e orienta uma
regeneração explícita. Para certificado administrado externamente, instale
`cert.pem` e `key.pem` no diretório TLS e defina
`VEGA_WEB_TLS_EXTERNAL=true`; nesse modo o Vega nunca sobrescreve os arquivos.

## Se quiser expor além da LAN

Este design deliberadamente não cobre esse caso (ver a pergunta que definiu
o escopo do projeto). Se decidir fazer isso mesmo assim, no mínimo:
substitua o certificado autoassinado por um de uma CA pública (ex. via proxy
reverso com Let's Encrypt) e aplique controles adicionais de borda. O rate
limiting local é uma defesa complementar, não proteção suficiente para
exposição direta à internet.
