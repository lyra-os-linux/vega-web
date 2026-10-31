//! Textos do diagnóstico de saúde, do teste de rede, do Liberar espaço e do
//! Pedir ajuda (add-web-diagnostics): os mesmos do Vega e do vega-cli, sem
//! dependência do HTTPS, para o painel e os testes.

/// O modo Rápido do vega-cli: leituras que não pesam num servidor em produção.
pub const QUICK_TESTS: &[&str] = &[
    "packages",
    "disk-health",
    "logs",
    "platform",
    "security",
    "boot",
    "network",
];

/// Testes de carga: deixam o servidor lento por alguns minutos.
pub const LOAD_TESTS: &[&str] = &["cpu-stress", "memory-stress", "disk-bench"];

pub fn test_name(id: &str) -> &str {
    match id {
        "packages" => "Integridade de pacotes",
        "disk-health" => "Saúde do disco",
        "fs-scrub" => "Sistema de arquivos",
        "cpu-stress" => "Processador sob carga",
        "memory-stress" => "Memória sob carga",
        "disk-bench" => "Desempenho do disco",
        "logs" => "Logs e falhas",
        "platform" => "Estado da plataforma",
        "security" => "Segurança",
        "network" => "Rede e internet",
        "boot" => "Tempo de boot",
        "repair:reinstall-packages" => "Reinstalando pacotes",
        "repair:verify-dependencies" => "Corrigindo dependências",
        "repair:restart-units" => "Reiniciando serviços",
        other => other,
    }
}

pub fn verdict_label(verdict: &str) -> &str {
    match verdict {
        "ok" => "Saudável",
        "attention" => "Atenção",
        "fail" => "Falha",
        "unavailable" => "Indisponível",
        "cancelled" => "Cancelado",
        "aborted" => "Interrompido",
        "skipped" => "Não testado",
        other => other,
    }
}

/// Classe CSS do aviso de um veredito.
pub fn verdict_level(verdict: &str) -> &'static str {
    match verdict {
        "ok" => "success",
        "attention" => "warn",
        "fail" => "error",
        _ => "info",
    }
}

/// O conserto de um achado, com os argumentos do relatório.
pub fn remedy_text(remedy: &str, args: &[String]) -> String {
    let joined = args.join(", ");
    let or = |fallback: &str| {
        if joined.is_empty() {
            fallback.to_owned()
        } else {
            joined.clone()
        }
    };
    match remedy {
        "reinstall-packages" if args.is_empty() => "Reinstalar os pacotes alterados".into(),
        "reinstall-packages" => format!("Reinstalar os pacotes: {joined}"),
        "verify-dependencies" => "Instalar as dependências que faltam".into(),
        "restart-units" if args.is_empty() => "Reiniciar os serviços que falharam".into(),
        "restart-units" => format!("Reiniciar os serviços: {joined}"),
        "enable-ntp" => "Ligar a sincronização de hora pela rede".into(),
        "enable-firewall" => "Ligar o firewall".into(),
        "close-port" if args.is_empty() => "Fechar as portas expostas no firewall".into(),
        "close-port" => format!(
            "Fechar no firewall: {}",
            args.iter()
                .map(|arg| arg
                    .replace("|service:", ": serviço ")
                    .replace("|port:", ": porta "))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        "apply-security-patches" => "Instalar as correções de segurança".into(),
        "disable-wait-online" => "Não esperar pela rede para terminar o boot".into(),
        "disable-service" if args.is_empty() => {
            "Desabilitar os serviços lentos que você habilitou".into()
        }
        "disable-service" => format!("Desabilitar no boot: {joined}"),
        "reconnect" => format!("Reconectar a rede ({})", or("Wi-Fi")),
        "renew-dhcp" => format!("Pedir um novo endereço IP ({})", or("rede")),
        "temporary-dns" => format!("Usar DNS público só nesta conexão ({})", or("rede")),
        other => other.to_owned(),
    }
}

/// A página do painel que ajuda: (endereço, rótulo).
pub type Link = (&'static str, &'static str);

pub type Guide = (&'static str, &'static str, Option<Link>);

/// Orientação para achados sem conserto automático: (código, texto, link).
/// Gerada do `GUIDE` de vega-gtk/ui/js/pages/hardware-diagnostics.js.
pub const GUIDE: &[Guide] = &[
    (
        "smart.failed",
        "Faça backup dos seus arquivos agora e planeje a troca do disco. O Vega não tenta consertar disco com defeito.",
        Some(("/backup", "Abrir Backup")),
    ),
    (
        "smart.critical-warning",
        "Faça backup dos seus arquivos agora e planeje a troca do disco. O Vega não tenta consertar disco com defeito.",
        Some(("/backup", "Abrir Backup")),
    ),
    (
        "smart.spare-low",
        "Faça backup dos seus arquivos agora e planeje a troca do disco. O Vega não tenta consertar disco com defeito.",
        Some(("/backup", "Abrir Backup")),
    ),
    (
        "smart.media-errors",
        "Faça backup dos seus arquivos agora e planeje a troca do disco. O Vega não tenta consertar disco com defeito.",
        Some(("/backup", "Abrir Backup")),
    ),
    (
        "smart.sectors",
        "Faça backup dos seus arquivos agora e planeje a troca do disco. O Vega não tenta consertar disco com defeito.",
        Some(("/backup", "Abrir Backup")),
    ),
    (
        "smart.prefail",
        "Faça backup dos seus arquivos agora e planeje a troca do disco. O Vega não tenta consertar disco com defeito.",
        Some(("/backup", "Abrir Backup")),
    ),
    (
        "smart.self-test-errors",
        "Faça backup dos seus arquivos agora e planeje a troca do disco. O Vega não tenta consertar disco com defeito.",
        Some(("/backup", "Abrir Backup")),
    ),
    (
        "smart.error-log",
        "Faça backup dos seus arquivos agora e planeje a troca do disco. O Vega não tenta consertar disco com defeito.",
        Some(("/backup", "Abrir Backup")),
    ),
    (
        "btrfs.device-errors",
        "Faça backup dos seus arquivos agora e planeje a troca do disco. O Vega não tenta consertar disco com defeito.",
        Some(("/backup", "Abrir Backup")),
    ),
    (
        "scrub.errors",
        "Faça backup dos seus arquivos agora e planeje a troca do disco. O Vega não tenta consertar disco com defeito.",
        Some(("/backup", "Abrir Backup")),
    ),
    (
        "smart.worn",
        "O disco está chegando ao fim da vida útil. Mantenha backups em dia e planeje a troca.",
        Some(("/backup", "Abrir Backup")),
    ),
    (
        "smart.hot",
        "Limpe as saídas de ar, use o computador sobre uma superfície rígida e evite deixá-lo no colo durante tarefas pesadas.",
        None,
    ),
    (
        "platform.hot-idle",
        "Limpe as saídas de ar, use o computador sobre uma superfície rígida e evite deixá-lo no colo durante tarefas pesadas.",
        None,
    ),
    (
        "cpu.slow-under-load",
        "Limpe as saídas de ar, use o computador sobre uma superfície rígida e evite deixá-lo no colo durante tarefas pesadas.",
        None,
    ),
    (
        "thermal.abort",
        "Limpe as saídas de ar, use o computador sobre uma superfície rígida e evite deixá-lo no colo durante tarefas pesadas.",
        None,
    ),
    (
        "platform.battery-worn",
        "A bateria guarda bem menos carga do que quando era nova. Considere trocá-la.",
        None,
    ),
    (
        "platform.firmware-updates",
        "Há atualizações de firmware. O Vega instala pelo fwupd e avisa se for preciso reiniciar.",
        None,
    ),
    (
        "backup.stale",
        "Faça um backup agora, com o disco de backup conectado.",
        Some(("/backup", "Abrir Backup")),
    ),
    (
        "backup.none",
        "Configure um backup para não perder seus arquivos se o disco falhar.",
        Some(("/backup", "Abrir Backup")),
    ),
    (
        "storage.low-space",
        "Pouco espaço livre faz atualizações e snapshots falharem. Veja o que dá para apagar com segurança.",
        Some(("/armazenamento", "Abrir Liberar espaço")),
    ),
    (
        "platform.ntp",
        "A sincronização está ligada, mas sem resposta. Confira a conexão com a internet.",
        Some(("/data-hora", "Abrir Data e hora")),
    ),
    (
        "platform.secure-boot-off",
        "Se quiser essa proteção, ative o Secure Boot nas configurações de firmware (UEFI) do computador.",
        None,
    ),
    (
        "platform.kernel-tainted",
        "O kernel registrou uma falha. Reinicie o computador; se voltar a acontecer, veja os logs.",
        Some(("/logs", "Abrir Logs")),
    ),
    (
        "logs.coredumps",
        "Os dados brutos mostram quais programas falharam. Manter o sistema atualizado costuma resolver.",
        Some(("/software", "Ver atualizações")),
    ),
    (
        "gpu.rtd3-awake",
        "Algum programa está usando a NVIDIA. Feche-o para economizar bateria.",
        Some(("/monitor", "Abrir Monitor")),
    ),
    (
        "gpu.bench-failed",
        "Confira o estado do driver da GPU.",
        None,
    ),
    (
        "power.abort",
        "Conecte o carregador e execute o teste de novo.",
        None,
    ),
    (
        "memory.insufficient",
        "Feche alguns programas para liberar memória e execute o teste de novo.",
        None,
    ),
    (
        "bench.insufficient-space",
        "Libere ao menos 10 GiB no disco e execute o teste de novo.",
        Some(("/armazenamento", "Abrir Armazenamento")),
    ),
    (
        "stage.timeout",
        "Tente de novo. Se voltar a acontecer, exporte o relatório e abra uma issue.",
        None,
    ),
    (
        "stage.tool-failed",
        "Tente de novo. Se voltar a acontecer, exporte o relatório e abra uma issue.",
        None,
    ),
    (
        "bench.failed",
        "Tente de novo. Se voltar a acontecer, exporte o relatório e abra uma issue.",
        None,
    ),
    (
        "stress.incomplete",
        "Tente de novo. Se voltar a acontecer, exporte o relatório e abra uma issue.",
        None,
    ),
    (
        "scrub.incomplete",
        "Tente de novo. Se voltar a acontecer, exporte o relatório e abra uma issue.",
        None,
    ),
    (
        "boot.slow",
        "Veja abaixo quais serviços atrasam o boot. Desabilitar o que você não usa acelera a inicialização.",
        None,
    ),
    (
        "boot.wait-online",
        "Algum programa precisa da rede logo no boot, por isso a espera fica. Se não usa esse programa, desabilite-o em Serviços.",
        Some(("/servicos", "Abrir Serviços")),
    ),
    (
        "boot.missing-device",
        "O /etc/fstab ainda monta um disco que foi removido. Tire a linha dele do fstab ou marque-a com nofail.",
        Some(("/armazenamento", "Abrir Armazenamento")),
    ),
    (
        "boot.slow-service",
        "Este serviço faz parte do sistema. Se o atraso continuar, veja o log dele.",
        Some(("/logs", "Abrir Logs")),
    ),
    (
        "network.no-link",
        "Confira o cabo ou ligue o Wi-Fi e escolha uma rede.",
        Some(("/rede", "Abrir Rede")),
    ),
    (
        "network.wifi-weak",
        "Aproxime-se do roteador ou tire obstáculos do caminho.",
        None,
    ),
    (
        "network.gateway-unreachable",
        "Desligue o roteador da tomada, espere 30 segundos e ligue de novo.",
        None,
    ),
    (
        "network.no-internet",
        "O roteador responde, mas a internet não chega até ele. Verifique o modem ou fale com o provedor.",
        None,
    ),
    (
        "network.captive-portal",
        "Abra a página de login da rede em Rede → Minha internet não funciona.",
        Some(("/rede", "Abrir Rede")),
    ),
    (
        "security.ssh-root-password",
        "Desative o login do root por senha no SSH (PermitRootLogin) ou desligue o servidor SSH se não usa.",
        Some(("/servicos", "Abrir Serviços")),
    ),
    (
        "security.ssh-password",
        "Prefira entrar no SSH com chave em vez de senha (PasswordAuthentication no).",
        Some(("/servicos", "Abrir Serviços")),
    ),
    (
        "security.exposed-port",
        "Feche a porta se não usa esse serviço a partir de outros computadores.",
        Some(("/rede", "Abrir Firewall")),
    ),
    (
        "security.empty-password",
        "Defina uma senha para essas contas, ou remova-as.",
        Some(("/usuarios", "Abrir Usuários")),
    ),
    (
        "security.sudo-open",
        "Só administradores (grupo wheel) devem usar sudo. Revise as contas.",
        Some(("/usuarios", "Abrir Usuários")),
    ),
    (
        "security.disk-unencrypted",
        "A criptografia do disco se escolhe na instalação; para ativá-la, faça backup e reinstale com a opção de criptografar.",
        None,
    ),
    (
        "security.selinux",
        "O SELinux reforça o isolamento dos serviços. A política do Lyra para ele ainda está em definição.",
        None,
    ),
    (
        "repair.restart-needed",
        "Reinicie quando puder para concluir a atualização.",
        None,
    ),
    (
        "repair.failed",
        "Tente de novo. Se voltar a acontecer, exporte o relatório e abra uma issue.",
        None,
    ),
    (
        "repair.unit-failed",
        "O serviço continua falhando. Veja o log dele para entender o motivo.",
        Some(("/logs", "Abrir Logs")),
    ),
];

/// Informações que também merecem uma orientação.
pub const INFO_GUIDE: &[&str] = &[
    "platform.firmware-updates",
    "backup.none",
    "security.disk-unencrypted",
    "security.selinux",
    "repair.restart-needed",
];

/// A orientação de um achado sem conserto: o texto e, quando houver, a
/// página do painel que ajuda.
pub fn guide(code: &str, severity: &str) -> Option<(&'static str, Option<Link>)> {
    if severity == "info" && !INFO_GUIDE.contains(&code) {
        return None;
    }
    GUIDE
        .iter()
        .find(|(id, _, _)| *id == code)
        .map(|(_, text, go)| (*text, *go))
}

/// 268435456 → "256 MiB", como no vega-cli.
pub fn bytes(n: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    if n >= GIB {
        let tenths = n * 10 / GIB;
        format!("{},{} GiB", tenths / 10, tenths % 10)
    } else if n >= MIB {
        format!("{} MiB", n / MIB)
    } else if n >= KIB {
        format!("{} KiB", n / KIB)
    } else {
        format!("{n} B")
    }
}

pub fn cleanup_name(id: &str) -> &str {
    match id {
        "coredumps" => "Relatórios de falha (core dumps)",
        "journal" => "Logs antigos do sistema",
        "package-cache" => "Pacotes baixados",
        "flatpak-unused" => "Runtimes Flatpak sem uso",
        "old-kernels" => "Kernels antigos (com snapshot antes)",
        "snapshots" => "Snapshots fora da política",
        other => other,
    }
}

/// Kernels antigos e snapshots só saem se o administrador marcar.
pub fn cleanup_default_on(id: &str) -> bool {
    !matches!(id, "old-kernels" | "snapshots")
}

/// Por que uma categoria não pode ser limpa agora.
pub fn cleanup_reason(reason: &str) -> String {
    match reason {
        "nothing" => "Nada para limpar".into(),
        "busy" => "Em uso agora".into(),
        "not-configured" => "Não configurado nesta instalação".into(),
        "protected" => "Protegido".into(),
        "failed" => "A medição falhou".into(),
        other => match other.strip_prefix("missing-tool:") {
            Some(package) => format!("Requer o pacote {package}"),
            None => other.to_owned(),
        },
    }
}

pub fn network_step_name(id: &str) -> &str {
    match id {
        "link" => "Cabo ou Wi-Fi",
        "address" => "Endereço IP",
        "gateway" => "Roteador",
        "dns" => "DNS",
        "internet" => "Internet",
        other => other,
    }
}

pub fn network_step_status(status: &str) -> &str {
    match status {
        "ok" => "Funcionando",
        "warn" => "Atenção",
        "fail" => "Aqui está o problema",
        "skipped" => "Não testado",
        other => other,
    }
}

/// Fases do último boot, na ordem da barra do Vega.
pub const BOOT_PHASES: &[(&str, &str)] = &[
    ("firmware", "Firmware"),
    ("loader", "Carregador"),
    ("kernel", "Kernel"),
    ("initrd", "initrd"),
    ("userspace", "Sistema"),
];
