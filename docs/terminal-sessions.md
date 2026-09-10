# Sessões do terminal: revogação e qualificação

Sair do painel encerra os terminais abertos por aquela sessão, mesmo quando
o cliente ainda está conectado. O mesmo vale para expiração, remoção,
substituição ou expulsão da sessão pelos limites de armazenamento.

Os prazos padrão são 30 minutos sem atividade HTTP e 12 horas desde o login.
Digitar no terminal não renova a atividade HTTP. Ao fechar um canal, sua vaga
é liberada. Reconectar exige uma sessão válida e uma concessão de
reautenticação nova; a concessão anterior foi consumida no primeiro acesso.

O helper revalida a conta e seu pertencimento ao grupo `wheel` aproximadamente
a cada segundo. Quando esse privilégio deixa de existir, o shell é encerrado
mesmo que a sessão HTTP e o socket continuem abertos. Resolução de conta/grupo
que falha também encerra o terminal.

O shell executa com UID e grupos do usuário autenticado. O encaminhador
executa como `vega-web`, sem grupos suplementares além do grupo do serviço.
Um supervisor root conserva capacidade de sinalizar os filhos de outros UIDs.
Ele observa desconexão e término e revalida a conta; os quadros do terminal
são interpretados pelo encaminhador sem privilégios. O shell/grupo recebe
HUP e, se necessário, KILL após até 500 ms. O systemd limpa descendentes que
saíram desse grupo, com limite de parada de cinco segundos.

**Integração HTTP/WebSocket**

```sh
cargo test --locked
bash scripts/check-session-contracts.sh
```

O script usa um D-Bus privado e executa os handlers HTTP e WebSocket reais em
loopback. Exercita logout em outra aba, expiração por inatividade, expiração
absoluta apesar de atividade HTTP e revogação durante escrita IPC bloqueada.
Confere fechamento do canal/helper simulado, liberação da vaga, rejeição da
concessão consumida e necessidade de nova sessão/concessão. As sessões são
inseridas pelo teste; esse ensaio não autentica através de PAM.

**Helper, PTY e systemd reais**

Em Linux x86_64, com Python 3, QEMU, cpio, systemd e um kernel legível:

```sh
cargo build --locked --bin vega-web-terminal-helper
python3 scripts/check-terminal-helper-vm.py --kernel /caminho/para/vmlinuz
```

O script copia o helper, as units do repositório e os componentes de userspace
necessários para um initramfs temporário. A VM usa QEMU TCG, sem rede ou discos
do host. As contas artificiais e alterações de grupo existem somente na VM;
o script convidado exige um marcador e a identidade da imagem de teste.

O ensaio verifica:

- Socket real, `SO_PEERCRED`, três UIDs distintos e redimensionamento do PTY.
- Desconexão com shell resistente a HUP/TERM e descendente em outra sessão;
  todos os processos devem sair do cgroup e ser coletados.
- Desconexão/half-close durante escrita bloqueada no PTY e escrita bloqueada
  no socket de saída, confirmadas pela syscall e pelo descritor do processo.
- Remoção de `wheel` mantendo a conexão e a escrita PTY bloqueada.
- Término normal do shell, rejeição de peer impróprio, login root e usuário
  sem wheel, seguidos de uma nova conexão válida.

O log fica em `target/terminal-helper-vm.log`. Falhas por `exit-code` nas
negações/revogações e `timeout` na eliminação forçada do descendente resistente
são resultados esperados; o critério é ausência de processos sobreviventes e
o marcador final de sucesso da suíte. O teste falha se a limpeza exceder seu
limite, em vez de aceitar um shell abandonado.

A CI executa as duas integrações. A VM qualifica o helper real e a limpeza da
unidade; a integração HTTP qualifica a propagação de revogação ao IPC. Esses
ensaios não equivalem a uma autenticação PAM completa de ponta a ponta, nem
qualificam as outras ações privilegiadas do painel.
