# Autorização das ações web

## Operações e identidade

`/administracao` permite instalar um pacote RPM dos repositórios configurados
ou abrir uma porta TCP/UDP. Cada envio exige uma sessão válida, token CSRF
da própria sessão e nova autenticação com a senha da conta. A conta precisa
pertencer ao grupo administrativo `wheel`. O formulário não aceita usuário,
UID, comando, origem de software, serviço, caminho ou ambiente alternativo.

Software e Rede continuam usando a conexão D-Bus do HTTPS para consultas.
As alterações usam um broker separado: um processo com o UID e os grupos
reais do usuário abre sua própria conexão com o `vegad`. O daemon mantém sua
checagem Polkit sobre esse remetente. O servidor HTTPS não carrega PAM,
não lê hashes e nunca recebe uma autorização Polkit global.

A unidade empacotada configura `VEGA_WEB_ADMIN_SOCKET` e inicia o socket
administrativo como dependência do HTTPS. Instalar o RPM não habilita o
serviço de rede automaticamente. Sem `VEGA_WEB_ADMIN_SOCKET`, ou com valor vazio,
os controles ficam indisponíveis. Os antigos `POST /software` e `POST /rede`
continuam recusando alterações com HTTP 403, sem interpretar parâmetros ou
chamar métodos mutantes. O terminal mantém sua reautenticação separada.

## Broker e concessão de uso único

O socket `/run/vega-web-admin.sock`, `root:vega-web` e modo `0660`, ativa
uma instância root por conexão. Há quatro vagas e prazo máximo de 60 segundos
por instância, incluindo os filhos de módulos PAM. O cliente verifica o UID
root do peer antes de enviar a senha. O helper verifica por `SO_PEERCRED`
que o cliente é a conta `vega-web`, além da permissão de acesso ao socket.

O protocolo binário limita campos e prazos: cinco segundos por leitura de
pedido, usuário até 256 bytes e senha até 4096 bytes. Aceita somente nome
simples de pacote ou porta única 1–65535 e protocolo TCP/UDP. Não aceita
flags, URLs, caminhos, seletores de repositório ou comandos de shell.

PAM autentica e valida a conta no serviço fixo `vega-web`. O helper rejeita
root, a conta HTTPS, nomes remapeados pelo PAM e contas fora de `wheel`.
Mantém usuário, operação, parâmetros e vínculo opaco da sessão na mesma
conexão. Emite uma concessão aleatória de uso único, válida por dez segundos.
O commit precisa conter exatamente essa concessão e terminar com half-close;
dados adicionais, reutilização, troca de conexão e concessões expiradas são
recusados. A conta e os grupos são conferidos novamente antes da execução.

Senha e concessão não chegam ao worker. O root executa uma cópia nova do
helper, que abandona UID/GID e grupos antes de abrir o D-Bus. Não há exec ou
fork após abandonar root. Core dumps e ptrace ficam desabilitados; a unidade
não permite escrita no sistema, exceto contadores PAM existentes.

## Polkit na sessão remota

A política padrão do `vegad` recusa instalação/firewall fora de sessão local
ativa. Por isso o pacote acrescenta uma política explícita: membros de
`wheel` podem responder a um desafio `AUTH_SELF` para as ações
`org.lyraos.vega.software.install` e `org.lyraos.vega.firewall.configure`.
Ela nunca retorna `YES` ou uma autorização retida, e recusa a conta HTTPS.
As demais ações continuam com suas políticas existentes. Regras locais
anteriores podem negar as ações; o broker não ignora essa decisão.

Essa política também oferece o mesmo desafio a outros clientes de membros
de `wheel`: conhecer a própria senha e autenticar continua obrigatório.
Não é uma restrição baseada no nome do executável. Administradores devem
considerar `wheel` o grupo elegível para essas operações, como já ocorre no
terminal web. Contas comuns não ganham essa permissão com o pacote.

Após o commit, o broker root registra um agente Polkit limitado ao processo
filho que controla, identificado por PID, UID e instante de criação. O filho
permanece vivo até o agente ser removido. O agente só aceita o nome único do
Polkit no barramento, a ação prevista e a identidade que o PAM autenticou;
responde a um único desafio. Não registra um agente para toda a sessão do
usuário. Somente root pode enviar `AuthenticationAgentResponse2` ao Polkit.

Polkit 124 vincula o cookie ao UID que registrou o agente (root neste
fluxo); Polkit 127 o vincula ao UID do processo atendido. O broker tenta
esse último e só repete com o UID do agente se receber exatamente
`org.freedesktop.PolicyKit1.Error.Failed: No session for cookie` da mesma
Authority. A identidade autenticada permanece a do usuário em ambas as
tentativas. Não usa o método legado nem UID curinga. A diferença está no
[registro em 124](https://github.com/polkit-org/polkit/blob/124/src/polkitbackend/polkitbackendinteractiveauthority.c)
e no [registro em 127](https://github.com/polkit-org/polkit/blob/127/src/polkitbackend/polkitbackendinteractiveauthority.c).

O fluxo usa a autenticação do Polkit sem simular uma sessão local ativa.
Não depende de `subject.system_unit`: no Leap examinado, D-Bus 1.14.10 não
entrega o pidfd seguro necessário ao Polkit 127 para essa propriedade.
Referências: [Authority](https://polkit.pages.freedesktop.org/polkit/eggdbus-interface-org.freedesktop.PolicyKit1.Authority.html),
[AuthenticationAgent](https://polkit.pages.freedesktop.org/polkit/eggdbus-interface-org.freedesktop.PolicyKit1.AuthenticationAgent.html)
e [verificação de pidfd no Polkit 127](https://github.com/polkit-org/polkit/blob/127/src/polkitbackend/polkitbackendduktapeauthority.c).

## Cancelamento, resultado e auditoria

Logout ou expiração interrompem a requisição HTTP e fecham sua conexão com
o broker. Antes do commit, isso invalida a concessão e nenhuma operação é
iniciada. Uma pilha PAM travada termina pelo prazo da unidade, liberando a
vaga sem reiniciar o HTTPS. Remoção do grupo ou expiração da conta entre
preparação e commit também impedem a execução.

Após o commit, uma transação já aceita pelo daemon pode continuar mesmo que
o navegador desconecte. A resposta orienta verificar o estado antes de
repetir quando o resultado é incerto. Instalação retorna HTTP 202 e o número
da transação; esse aceite não é confirmação de instalação concluída.
Firewall retorna sucesso depois da chamada do daemon. Acompanhamento de
transações e recuperação de falhas do daemon são contratos separados.

Um identificador de auditoria independente correlaciona solicitação,
usuário/UID confirmado, ação, desafio Polkit e transação aceita. Falha na
entrega da resposta não apaga o aceite já registrado. Senhas, cookies,
concessões e vínculo opaco da sessão não entram nos registros do helper.
O HTTPS continua recebendo a senha em trânsito; o isolamento não protege
credenciais de um servidor HTTPS já comprometido. PAM/Polkit/systemd e o
broker root pertencem à fronteira privilegiada.

## Qualificação

```sh
cargo test --locked
bash scripts/check-authorization-contracts.sh
bash scripts/check-session-contracts.sh
cargo build --locked --bins
python3 scripts/check-admin-helper-vm.py --kernel /caminho/vmlinuz --modules-dir /caminho/modules/versao --vegad /caminho/vegad --policy /caminho/org.lyraos.vega.policy
```

A integração HTTP usa um barramento privado e testa identidade forjada,
CSRF de outra sessão, campos desconhecidos, parâmetros misturados ou
inválidos, limites de corpo e sessão removida antes de abrir o broker.
Os endpoints antigos permanecem negados mesmo com um daemon simulado que
aceitaria qualquer chamada.

A VM descartável usa PAM, Polkit, systemd, HTTPS, vegad, Zypper/RPM,
firewalld e nftables reais. Contas e senhas são artificiais, sem discos ou
rede externa do host; instala um RPM mínimo num repositório local exclusivo
da VM. Verifica concessões, grupos/contas, RPM e firewall efetivos, login,
logout/expiração durante PAM e encerramento de um módulo PAM travado.
Não substitui qualificação da ISO, publicação OBS nem ensaios de LDAP/SSSD,
2FA, políticas locais personalizadas ou atualização pelo solver.
