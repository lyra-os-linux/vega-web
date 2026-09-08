# Isolamento da autenticação PAM

## Fronteira de confiança

O processo HTTPS roda como `vega-web`, sem associação ao grupo `shadow`,
e não carrega `libpam`. Login e reautenticação do terminal usam o mesmo
cliente de um helper local separado. Não há fallback para autenticação PAM
dentro do processo de rede.

Em 08/09/2026, os metadados do host Lyra/openSUSE Leap 16.1 examinado eram
`root:shadow`, modo `0640`, tanto para `/etc/shadow` quanto para
`/etc/shadow-`. Portanto, a declaração antiga `m vega-web shadow`
concedia leitura por grupo. A conta de serviço não estava criada nesse host:
a comparação efetiva de leitura pelo processo foi feita em VM, reproduzindo
esses metadados com hashes artificiais e o grupo antigo.

O HTTPS ainda recebe a senha enviada pelo navegador e confia no resultado
do helper. Comprometer o HTTPS continua expondo credenciais em trânsito pela
aplicação e permitindo tentativas online pelo IPC; o isolamento retira seu
acesso direto aos hashes. PAM, seus módulos, systemd e o helper root fazem
parte da fronteira privilegiada. Isto não implementa o broker de autorização
administrativa pendente da [autorização web](web-authorization.md).

## Helper e protocolo

`vega-web-auth.socket` é `root:vega-web`, `0660`, aceita no máximo
quatro conexões simultâneas e ativa uma instância de
`vega-web-auth@.service` por conexão. O helper exige UID efetivo zero e
confere por `SO_PEERCRED` que o cliente é exatamente a conta `vega-web`;
pertencer apenas ao grupo do socket não basta. O cliente também confere que
o peer do socket é root antes de enviar credenciais.

O pedido contém uma versão fixa, comprimentos e somente usuário/senha.
Aceita até 256 bytes de usuário e 4096 bytes de senha, sem NUL, com texto
UTF-8 válido. Rejeita nomes com caracteres de controle, campos vazios,
comprimentos inválidos, truncamento e dados adicionais. Cada conexão aceita
um pedido e termina com half-close do cliente. Não transmite comandos,
caminhos nem o nome de um serviço PAM selecionável.

A leitura tem prazo total de cinco segundos, recalculado a cada operação;
enviar bytes lentamente não renova esse prazo. A conexão do cliente não
bloqueia numa fila local cheia e seu prazo total de I/O é de 35 segundos.
O systemd limita a instância a 30 segundos e encerra todo o cgroup, incluindo
filhos criados por módulos PAM. Não há persistência da senha no protocolo;
os buffers sensíveis geridos pelo código são zerados ao terminar. Core dumps
estão desabilitados e o helper também usa `PR_SET_DUMPABLE=0`.

O serviço PAM é fixo: `vega-web`, configurado em
`/etc/pam.d/vega-web`, incluindo `common-auth` e
`common-account`. O helper chama autenticação e validação da conta no
mesmo handle; conta bloqueada, expirada ou com senha expirada não gera
sucesso. Tokens nulos são recusados. A resposta é apenas sucesso/negação;
senhas e diagnósticos dos módulos não são enviados ao journal pelo helper.
Ver os contratos de [pam_authenticate](https://www.man7.org/linux/man-pages/man3/pam_authenticate.3.html)
e [pam_acct_mgmt](https://www.man7.org/linux/man-pages/man3/pam_acct_mgmt.3.html).

O sandbox do helper mantém o sistema e os diretórios pessoais protegidos;
permite os diretórios existentes de contadores `/run/faillock` e
`/var/lib/faillock`. Módulos personalizados que precisem de outros
caminhos graváveis ou de capacidades exigem configuração explícita e
qualificação própria. Os ensaios não cobrem LDAP/SSSD remoto, 2FA ou FIPS.

## Instalação e atualização RPM

As duas declarações sysusers criam a conta sem `shadow`. O RPM instala
o helper, socket, unit e migrador. Em atualização, o migrador:

1. para o HTTPS ativo, encerrando sessões e descritores abertos pelo processo
   antigo;
2. retira somente a associação suplementar a `shadow`, preservando
   os demais grupos, e confere o resultado;
3. recarrega as units e inicia o serviço apenas se ele estava ativo.

Repetir a migração é seguro; um serviço inativo permanece inativo. Em chroot
sem systemd ativo, só a migração da conta é executada. Se `shadow` tiver
sido configurado como grupo primário, ou se a associação não puder ser
retirada, a migração retorna erro e não reinicia o serviço. A unit HTTPS
ainda torna inacessíveis shadow, gshadow, seus backups usuais e opasswd.

O instalador de desenvolvimento usa o mesmo migrador. Instalação nova não
habilita o painel automaticamente pelo RPM. Os procedimentos não alteram
o modo ou proprietário de arquivos de senhas do sistema.

`VEGA_WEB_PAM_SERVICE` personalizado deixou de selecionar uma pilha no
HTTPS. Se existir um override com valor diferente de `vega-web`, o
servidor recusa iniciar, em vez de usar silenciosamente outra política.
Migre as regras desejadas para `/etc/pam.d/vega-web` e remova o override.
O caminho de IPC do cliente pode ser configurado por `VEGA_WEB_AUTH_SOCKET`.

## Limites de tentativas

Login e reautenticação compartilham limites por IP e usuário e quatro vagas
de autenticação por padrão. O limite de tentativas agora permanece ativo
depois do atraso da resposta: ao atingir o limiar, bloqueia durante o
período de recuperação configurado. Antes, o bloqueio terminava enquanto
o próprio handler esperava para responder. Os padrões são cinco falhas e
recuperação de 15 minutos; os atrasos progressivos e opções existentes
continuam disponíveis. Pedidos bloqueados não chegam ao helper.

## Qualificação

```sh
cargo test --locked
cargo build --locked --bins
python3 scripts/check-auth-helper-vm.py --kernel /caminho/para/vmlinuz
```

O ensaio usa kernel, systemd, PAM e módulos do ambiente de build, com contas,
senhas e arquivos artificiais em uma VM QEMU sem rede externa ou discos
do host. Um barramento D-Bus privado permite iniciar o HTTPS real; nenhum
vegad capaz de instalar pacotes ou alterar o sistema é usado nesse ensaio.

A VM compara leitura antes/depois, mantém um descritor antigo aberto para
provar seu encerramento, preserva um grupo suplementar alheio à migração e
verifica a unit HTTPS e a ausência de libpam carregada. Exercita login HTTPS,
reautenticação, logout, senha errada, usuário inexistente, expiração de conta
e senha, bloqueio, origem dos peers, entradas inválidas, prazo cumulativo,
capacidade, helper ausente/falso, PAM travado, limpeza dos filhos e liberação
das vagas HTTP. Os limites da aplicação usam dois erros e recuperação de
cinco segundos só na VM, para verificar bloqueio e recuperação sem esperar
15 minutos. O prazo de 30 segundos do helper é o de produção.

Essa VM qualifica o caminho de autenticação e a migração, não uma instalação
de ISO completa ou atualização de RPM pelo solver. Build/publicação OBS e
qualificação do RPM continuam sendo etapas separadas.
