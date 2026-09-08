# Autorização das ações web

## Comportamento disponível

As páginas Software e Rede/Firewall permitem consultas. A instalação de
pacotes e a criação de regras de firewall pelo painel estão indisponíveis
até existir um backend que preserve a identidade e a autorização do usuário.
A interface informa esse limite e orienta usar o Vega na sessão local.

Os endereços antigos `POST /software` e `POST /rede` retornam HTTP 403 para
qualquer sessão autenticada, inclusive uma sessão administrativa. Não
interpretam o formulário nem chamam métodos mutantes do daemon. Sem sessão
válida, o middleware redireciona para o login. Métodos de escrita diferentes
de POST não têm handlers. Parâmetros antigos de sucesso na URL não exibem
mais confirmações de operações.

Cada POST recusado registra a identidade da sessão, a rota e o motivo
`per-user-authorization-unavailable`. Não registra senha, formulário ou query.
O terminal continua com seu fluxo separado de reautenticação e execução com
o UID real, descrito em [terminal-sessions.md](terminal-sessions.md).

## Por que o login não basta

O processo HTTPS usa `User=vega-web`. Sua conexão D-Bus apresenta essa conta
ao `vegad`, independentemente de quem fez login via PAM. O daemon chama
`pkcheck --system-bus-name <sender>` e resolve a identidade a partir da mesma
conexão. Um campo `username` no formulário não muda esse sujeito.

A política de instalação e firewall no `vegad` permite `auth_admin` para
sessão ativa e define `no` para `allow_any` e `allow_inactive`. Portanto,
executar uma chamada com `runuser` ou acrescentar um agente Polkit, por si
só, não prova que uma sessão web remota será autorizada. Nenhuma regra de
autorização global para `vega-web` é fornecida por esta correção.

## Contrato para habilitação futura

O mecanismo proposto é um broker local separado, com operações permitidas
explicitamente e processos por sessão. Sua implementação deve cumprir:

1. A autenticação privilegiada associa uma sessão a uma conta local e produz
   uma concessão opaca, curta e revogável. A conta não pode ser escolhida
   apenas por um UID/nome enviado pelo processo HTTPS ou pelo formulário.
2. A reautenticação confirma uma operação e seus parâmetros. O broker
   consome a concessão uma única vez, confere prazo, sessão e conta e rejeita
   reutilização ou troca de parâmetros. Nunca recebe um comando de shell.
3. Um processo com o UID e grupos reais da conta abre a conexão D-Bus usada
   na operação; o `vegad` mantém a validação de Polkit sobre esse remetente.
4. A integração PAM/sessão/agente Polkit deve tratar explicitamente o caso
   remoto, sem fingir uma sessão local ativa. Qualquer política adicional
   precisa ser limitada às ações e sujeitos pretendidos e comprovada numa
   imagem padrão; não pode liberar a conta HTTPS de forma global.
5. O registro de auditoria correlaciona usuário iniciador, identidade que
   autorizou, ação, resultado e transação. Cancelamento, logout, expiração e
   remoção de privilégios invalidam concessões ainda não consumidas.

Este é um contrato de implementação futura, não um backend já disponível.
A integração deve ser qualificada com instalação RPM e firewall reais em VM,
incluindo administrador autorizado, usuário recusado, cancelamento de prompt,
sessão revogada e identidade forjada. Até esses ensaios passarem, os controles
e handlers de escrita permanecem indisponíveis. A issue #8 continua aberta
para acompanhar essa parte funcional.

## Verificação da contenção atual

```sh
bash scripts/check-authorization-contracts.sh
```

O teste usa o router de produção, HTTP real e D-Bus privado com daemon
simulado. Controles positivos comprovam que os métodos simulados de
instalação e firewall aceitam chamadas e incrementam seus contadores. Depois,
consultas e tentativas de escrita pelo HTTP devem deixar esses contadores
zerados, mesmo com nomes de sessão `root` e `nobody`, campos de identidade
forjados, formulários antigos, conteúdo inválido e métodos alternativos.
Também verifica ausência dos controles e de confirmações falsas, além do
redirecionamento de sessões revogadas e requisições sem cookie.

As sessões são inseridas pelo teste: ele não autentica essas contas via PAM
nem altera usuários, Polkit, RPMs ou firewall do host. Esse ensaio comprova
o bloqueio independente da política do daemon; não qualifica a futura
autorização administrativa remota.
