# Arquitetura do vega-web

Status: consultas, terminal e broker administrativo implementados. Instalação
de RPM e abertura de porta usam reautenticação e execução com UID real,
limitadas a administradores de `wheel`. O terminal é uma fronteira separada.

## Objetivo e limites

`vega-web` é um quarto frontend do Vega, ao lado de `vega-gtk` e
`vega-cli`: um painel HTTPS pensado para uso dentro da LAN (não para
exposição pública), sem substituir nem duplicar a lógica de `vegad` — só
consome o mesmo contrato `dbus/org.lyraos.Vega1.*.xml`, através do cliente
tipado `lyra-vega-dbus` já compartilhado pelo `vega-gtk`.

## Restrição que define o desenho

`vegad` autoriza cada ação mutante via `pkcheck --system-bus-name <sender>`
(`vegad/internal/dbusserver/polkit.go`) e resolve o usuário via
`GetConnectionUnixUser` sobre essa mesma conexão
(`vegad/internal/dbusserver/desktopuser.go`) — ou seja, a identidade vem do
peer credential *real* da conexão D-Bus, não de qualquer dado que a
aplicação afirme. Isso significa que `vega-web`, rodando como um único
processo de longa duração, não pode "dizer que é o usuário X" para o
`vegad` — só preservaria as regras de polkit por usuário se a chamada D-Bus
fosse fisicamente feita por um processo com o UID real daquele usuário.
Esse é o motivo da Fase 1 ser só leitura: os métodos somente-leitura do
`vegad` (`List*`/`Get*`/`Status`) não passam por `requirePolkit`, então não
têm esse problema — qualquer usuário autenticado no `vega-web` pode
enxergá-los sem precisar impersonar UID nenhum.

## Estrutura (Fase 1)

```text
vega-web/
├── Cargo.toml
├── build.rs          # libpam ligada somente ao helper de autenticação
└── src/
    ├── main.rs        # wiring: TLS, D-Bus, rotas, servidor axum
    ├── state.rs        # AppState, SessionStore (em memória)
    ├── auth.rs         # login/logout, middleware require_session
    ├── pam_ffi.rs       # bindings libpam, compilados somente no helper
    ├── tls.rs          # certificado autoassinado (gerado no 1º start)
    ├── layout.rs        # HTML compartilhado (sem framework JS)
    └── pages/
        ├── dashboard.rs
        ├── services.rs
        └── snapshots.rs
```

### Por que bindings manuais de PAM, não a crate `pam`

A crate `pam` (e `pam-client`) dependem de `pam-sys`, que gera bindings via
`bindgen`/`clang-sys` em tempo de build — nesta máquina de desenvolvimento
isso falha sem `libclang.so` (não instalado por padrão) e, mesmo quando
disponível, adiciona `clang`+`llvm` ao `BuildRequires` só para chamar ~5
funções de uma ABI C estável e documentada há décadas. `vega-web/src/pam_ffi.rs`
declara essas funções à mão (`pam_start`, `pam_authenticate`,
`pam_acct_mgmt`, `pam_end`, `pam_strerror`) e linka contra `libpam` via
`build.rs`, exigindo só `pam-devel` — mesmo pacote que já fornece os headers
usados por qualquer outro software C que fale com PAM no openSUSE. Sendo
código de autenticação, o hand-roll também fica pequeno o bastante para
revisar por inteiro, em vez de confiar numa dependência externa com cadeia
de build maior.

### Isolamento de PAM e hashes

O HTTPS roda como `vega-web`, sem associação a `shadow` e sem carregar
`libpam`. Login e reautenticação encaminham um pedido limitado ao helper
root ativado por `vega-web-auth.socket`. Os dois lados conferem o UID do
peer; o helper executa autenticação e account management usando a pilha
fixa `/etc/pam.d/vega-web`. A conexão não permite escolher comandos ou outra
pilha PAM. O prazo da instância e a limpeza dos filhos são controlados por
systemd, preservando as vagas e os limites do frontend.

Atualizações removem a associação antiga a `shadow` e encerram o processo
anterior antes de reiniciar; a unit também oculta os arquivos de hashes.
Protocolo, limites de confiança, configuração e qualificação estão em
[pam-isolation.md](pam-isolation.md).

### Sessão e TLS

- Sessão: token aleatório de 32 bytes num cookie assinado/criptografado
  (`axum_extra::extract::cookie::PrivateCookieJar`); os dados da sessão
  (usuário autenticado) ficam só no servidor, num `HashMap` em memória. A
  chave de assinatura é gerada a cada start — reiniciar o serviço invalida
  todas as sessões, o que é intencional (evita guardar segredo persistente
  só para isso).
- Os terminais observam a mesma sessão HTTP. Logout, remoção, substituição,
  expulsão pelos limites do store e expiração revogam seus canais ativos.
  Os prazos padrão são 30 minutos de inatividade HTTP e 12 horas desde o
  login. Tráfego do terminal não prolonga esses prazos. Cada observador tem
  seu próprio timer, sem depender de outra requisição para detectar expiração.
- TLS: certificado autoassinado gerado no primeiro start
  (`VEGA_WEB_TLS_DIR`, padrão `/etc/vega/web/tls`, permissão `0600`). O
  aviso de certificado não confiável no navegador é esperado — ver
  `docs/privacidade.md`.

## Terminal web administrativo

O terminal usa xterm.js incorporado ao pacote (sem CDN), WebSocket e um PTY.
Antes de cada conexão o usuário precisa confirmar novamente sua senha; a
autorização vale por 60 segundos e é consumida pela primeira conexão. Há no
máximo quatro terminais simultâneos por padrão
(`VEGA_WEB_TERMINAL_LIMIT`). O upgrade WebSocket exige que `Origin` seja o
mesmo host HTTPS, e mensagens de entrada são limitadas a 64 KiB.

`vega-web-terminal.socket` é `root:vega-web`, modo `0660`, e ativa uma instância
root de `vega-web-terminal@.service` para cada conexão. O broker:

1. valida com `SO_PEERCRED` que o peer é realmente o usuário `vega-web`;
2. resolve a conta local sem aceitar UID 0 e exige participação em `wheel`;
3. cria o PTY e, no filho, aplica `initgroups`, `setgid` e `setuid` antes de
   executar exclusivamente o shell cadastrado em `/etc/passwd`;
4. limpa o ambiente, define um `PATH` fixo e inicia o shell como login shell;
5. cria um encaminhador que remove root e grupos suplementares, ficando
   como `vega-web` para interpretar quadros, transportar bytes e redimensionar
   o PTY;
6. mantém um supervisor root que observa desconexão e término dos filhos,
   e revalida a identidade e participação em `wheel` a cada segundo;
7. ao encerrar, termina o encaminhador e sinaliza o shell/grupo com HUP,
   seguido de KILL após até 500 ms. Conserva os filhos sem coletá-los até
   concluir os sinais, evitando reutilização de PID nesse intervalo.

O supervisor precisa conservar root para sinalizar o shell de outro UID;
ele não interpreta os quadros de entrada após a identidade inicial. O
`KillMode=control-group` da unidade termina também descendentes que criaram
outra sessão ou grupo de processos. Descendentes que ignoram TERM são
eliminados pelo systemd ao atingir `TimeoutStopSec=5`.

A revogação HTTP cancela toda a ponte WebSocket/IPC, incluindo conexão e
escritas bloqueadas. O fechamento do socket chega ao supervisor mesmo se
o encaminhador estiver bloqueado no PTY. A tentativa de enviar o quadro
WebSocket Close tem prazo de 250 ms; o término da tarefa libera sua vaga.
Uma nova conexão exige sessão válida e uma nova concessão de reautenticação.

Os ensaios e seus limites estão em [terminal-sessions.md](terminal-sessions.md).

O painel segue com `NoNewPrivileges=true`, `ProtectHome=true` e seu sandbox
original. Somente a unidade socket-activated da sessão fica fora desse
namespace; seu filho remove root para o UID autenticado antes do `exec`.
Isso permite que o shell tenha semântica equivalente a uma sessão SSH sem
afrouxar o processo HTTPS exposto à rede.

## Ações administrativas com identidade própria

As chamadas de instalação e firewall pelo UID compartilhado do serviço foram
retiradas. Os POST antigos falham com HTTP 403 sem acionar o daemon.

`/administracao` usa um token CSRF da sessão e uma nova senha. O broker root
valida PAM, conta e grupo, emite uma concessão curta de uso único e executa
uma operação tipada depois do commit. Um worker abre o D-Bus com UID/GID e
grupos reais. O root registra um agente Polkit para esse filho, limitado à
identidade autenticada e a uma ação, e o remove ao terminar.

Como a política original nega o contexto remoto, uma regra explícita oferece
um desafio de autenticação a `wheel` para instalação/firewall. Ela nunca
autoriza automaticamente ou libera o UID do HTTPS. Nenhuma sessão local
ativa é simulada. Logout e expiração invalidam pedidos ainda não consumidos;
transações aceitas podem continuar no daemon. Contrato, escopo da política,
auditoria e ensaios estão em [web-authorization.md](web-authorization.md).
