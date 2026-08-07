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
"conexão não seguro/certificado inválido"** na primeira visita; isso é
esperado e não indica um ataque, mas também significa que não há proteção
automática contra um servidor falso se impersonando na rede — só use em
redes em que você confia nos outros dispositivos.

## O que é exposto

- **Antes do login**: só a página de login em si (formulário
  usuário/senha) e a negociação TLS. Nenhum dado do sistema é acessível sem
  autenticação — inclusive as páginas somente-leitura exigem sessão válida.
- **Depois do login**: dados dos módulos somente-leitura hoje implementados
  (Painel, Serviços, Snapshots) — os mesmos que `vegad` já expõe sem exigir
  polkit para `vega-gtk`/`vega-cli`. Nenhuma ação de escrita existe nesta
  versão.
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

## Limitações conhecidas desta versão

- **Sem limite de tentativas de login próprio do `vega-web`**: não há
  *rate limiting* nem bloqueio temporário por IP no próprio serviço — a
  única proteção contra força bruta vem de módulos PAM que já estejam
  configurados no sistema (ex. `pam_faillock`), se estiverem. Em uma rede
  não totalmente confiável, considere colocar o `vega-web` atrás de um
  proxy com *rate limiting* antes de expô-lo além do essencial.
- **Sessão em memória**: reiniciar o serviço desloga todo mundo (não é
  vazamento, mas pode surpreender).
- **Sem 2FA**: só usuário/senha, como qualquer outro consumidor de PAM sem
  módulos adicionais configurados.
- **Sem auditoria própria**: tentativas de login (sucesso/falha) não geram
  um log dedicado do `vega-web` ainda — ficam só no journal padrão do PAM
  do sistema.

## Se quiser expor além da LAN

Este design deliberadamente não cobre esse caso (ver a pergunta que definiu
o escopo do projeto). Se decidir fazer isso mesmo assim, no mínimo:
substitua o certificado autoassinado por um de uma CA pública (ex. via
proxy reverso com Let's Encrypt), e reavalie a ausência de *rate limiting*
citada acima — o que é um risco tolerável numa LAN confiável deixa de ser
tolerável na internet aberta.
