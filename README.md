# vega-web

Painel web HTTPS (somente LAN) do [Vega](https://github.com/lyra-os-linux/vega),
centro de controle para openSUSE Leap. Login via PAM (contas do próprio
sistema); sem certificado público — ver [`docs/privacidade.md`](docs/privacidade.md)
antes de expor além da LAN. Inclui um terminal web completo, com
reautenticação, limitado a administradores do grupo `wheel`.

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
