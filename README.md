# vega-web

Painel web HTTPS (somente LAN) do [Vega](https://github.com/lyra-os-linux/vega),
centro de controle para openSUSE Leap. Login via PAM (contas do próprio
sistema); sem certificado público — ver [`docs/privacidade.md`](docs/privacidade.md)
antes de expor além da LAN. Inclui um terminal web completo, com
reautenticação, limitado a administradores do grupo `wheel`.

Software e Rede/Firewall permitem consultas. A página Administração oferece
instalação de RPM e abertura de porta com nova autenticação, token da sessão
e execução pelo UID real de um administrador de `wheel`. Requer o broker
administrativo configurado; ver [autorização web](docs/web-authorization.md).

Um quarto frontend do Vega, ao lado de
[`vega-gtk`](https://github.com/lyra-os-linux/vega) e
[`vega-cli`](https://github.com/lyra-os-linux/vega-cli): não duplica lógica
do daemon [`vegad`](https://github.com/lyra-os-linux/vegad), só consome o
mesmo contrato D-Bus através do cliente tipado
[`lyra-vega-dbus`](https://github.com/lyra-os-linux/lyra-vega-dbus). Ver
[`docs/architecture.md`](docs/architecture.md) para o desenho completo.

## Build

```sh
cargo build --release --locked
```

## Desenvolvimento

```sh
scripts/dev-install.sh    # builda e instala como o serviço vega-web.service
scripts/dev-uninstall.sh  # reverte
```

Licenciado sob GPL-3.0.

## Instalação NVIDIA opcional

Em Hardware e Kernel → NVIDIA (`/hardware/nvidia`), consulte o driver e a recuperação sem privilégios. A instalação
exige confirmação explícita e autorização administrativa. Conteúdo novo em
PT/EN/ES; diagnósticos técnicos do backend preservam seus identificadores.
No Web, a senha é revalidada pelo broker PAM/Polkit com o UID real do usuário;
a página acompanha a transação e não confunde aceitação com conclusão.

Requer `nvidia-official-v1` e `nvidia-recovery-v1` (vegad >= 5.1.29). Btrfs usa
Snapper; Server/ext4 simples usa Restic e restauração exclusivamente offline.
O backup deve ser criado e verificado antes do commit. Falha, perda do daemon,
expiração ou interrupção da observação nunca dispara repetição automática.
Veja [o contrato e a recuperação](https://github.com/lyra-os-linux/vegad/blob/main/docs/nvidia.md).
