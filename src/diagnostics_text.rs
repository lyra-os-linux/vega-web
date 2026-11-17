//! Textos do diagnóstico de saúde, do teste de rede, do Liberar espaço e do
//! Pedir ajuda (add-web-diagnostics): os mesmos do Vega e do vega-cli, sem
//! dependência do HTTPS, para o painel e os testes. Os textos ficam em
//! português no código; `tr` traz o inglês e o espanhol (vega-web#25).

use crate::lang::Lang;

/// The text in `lang`; unknown texts (from the daemon, ids) pass through.
pub fn tr(lang: Lang, pt: &str) -> &str {
    if lang == Lang::Pt {
        return pt;
    }
    TRANSLATIONS
        .iter()
        .find(|(source, _, _)| *source == pt)
        .map_or(pt, |(_, en, es)| lang.text(en, en, es))
}

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

pub fn test_name(lang: Lang, id: &str) -> &str {
    tr(
        lang,
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
        },
    )
}

pub fn verdict_label(lang: Lang, verdict: &str) -> &str {
    tr(
        lang,
        match verdict {
            "ok" => "Saudável",
            "attention" => "Atenção",
            "fail" => "Falha",
            "unavailable" => "Indisponível",
            "cancelled" => "Cancelado",
            "aborted" => "Interrompido",
            "skipped" => "Não testado",
            other => other,
        },
    )
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
pub fn remedy_text(lang: Lang, remedy: &str, args: &[String]) -> String {
    let joined = args.join(", ");
    let or = |fallback: &str| {
        if joined.is_empty() {
            tr(lang, fallback).to_owned()
        } else {
            joined.clone()
        }
    };
    let t = |pt: &'static str, en: &'static str, es: &'static str| lang.text(pt, en, es);
    match remedy {
        "reinstall-packages" if args.is_empty() => {
            tr(lang, "Reinstalar os pacotes alterados").into()
        }
        "reinstall-packages" => format!(
            "{}: {joined}",
            t(
                "Reinstalar os pacotes",
                "Reinstall the packages",
                "Reinstalar los paquetes"
            )
        ),
        "verify-dependencies" => tr(lang, "Instalar as dependências que faltam").into(),
        "restart-units" if args.is_empty() => tr(lang, "Reiniciar os serviços que falharam").into(),
        "restart-units" => format!(
            "{}: {joined}",
            t(
                "Reiniciar os serviços",
                "Restart the services",
                "Reiniciar los servicios"
            )
        ),
        "enable-ntp" => tr(lang, "Ligar a sincronização de hora pela rede").into(),
        "enable-firewall" => tr(lang, "Ligar o firewall").into(),
        "close-port" if args.is_empty() => tr(lang, "Fechar as portas expostas no firewall").into(),
        "close-port" => format!(
            "{}: {}",
            t(
                "Fechar no firewall",
                "Close in the firewall",
                "Cerrar en el cortafuegos"
            ),
            args.iter()
                .map(|arg| arg
                    .replace("|service:", t(": serviço ", ": service ", ": servicio "))
                    .replace("|port:", t(": porta ", ": port ", ": puerto ")))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        "apply-security-patches" => tr(lang, "Instalar as correções de segurança").into(),
        "disable-wait-online" => tr(lang, "Não esperar pela rede para terminar o boot").into(),
        "disable-service" if args.is_empty() => {
            tr(lang, "Desabilitar os serviços lentos que você habilitou").into()
        }
        "disable-service" => format!(
            "{}: {joined}",
            t(
                "Desabilitar no boot",
                "Disable at boot",
                "Desactivar en el arranque"
            )
        ),
        "reconnect" => format!(
            "{} ({})",
            t(
                "Reconectar a rede",
                "Reconnect the network",
                "Reconectar la red"
            ),
            or("Wi-Fi")
        ),
        "renew-dhcp" => format!(
            "{} ({})",
            t(
                "Pedir um novo endereço IP",
                "Request a new IP address",
                "Pedir una nueva dirección IP"
            ),
            or("rede")
        ),
        "temporary-dns" => format!(
            "{} ({})",
            t(
                "Usar DNS público só nesta conexão",
                "Use public DNS on this connection only",
                "Usar DNS público solo en esta conexión"
            ),
            or("rede")
        ),
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
pub fn guide(lang: Lang, code: &str, severity: &str) -> Option<(&'static str, Option<Link>)> {
    if severity == "info" && !INFO_GUIDE.contains(&code) {
        return None;
    }
    GUIDE
        .iter()
        .find(|(id, _, _)| *id == code)
        .map(|(_, text, go)| {
            (
                tr(lang, text),
                go.map(|(href, label)| (href, tr(lang, label))),
            )
        })
}

/// 268435456 → "256 MiB", como no vega-cli; vírgula decimal fora do inglês.
pub fn bytes(lang: Lang, n: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    if n >= GIB {
        let tenths = n * 10 / GIB;
        let point = if lang == Lang::En { '.' } else { ',' };
        format!("{}{point}{} GiB", tenths / 10, tenths % 10)
    } else if n >= MIB {
        format!("{} MiB", n / MIB)
    } else if n >= KIB {
        format!("{} KiB", n / KIB)
    } else {
        format!("{n} B")
    }
}

pub fn cleanup_name(lang: Lang, id: &str) -> &str {
    tr(
        lang,
        match id {
            "coredumps" => "Relatórios de falha (core dumps)",
            "journal" => "Logs antigos do sistema",
            "package-cache" => "Pacotes baixados",
            "flatpak-unused" => "Runtimes Flatpak sem uso",
            "old-kernels" => "Kernels antigos (com snapshot antes)",
            "snapshots" => "Snapshots fora da política",
            other => other,
        },
    )
}

/// Kernels antigos e snapshots só saem se o administrador marcar.
pub fn cleanup_default_on(id: &str) -> bool {
    !matches!(id, "old-kernels" | "snapshots")
}

/// Por que uma categoria não pode ser limpa agora.
pub fn cleanup_reason(lang: Lang, reason: &str) -> String {
    match reason {
        "nothing" => tr(lang, "Nada para limpar").into(),
        "busy" => tr(lang, "Em uso agora").into(),
        "not-configured" => tr(lang, "Não configurado nesta instalação").into(),
        "protected" => tr(lang, "Protegido").into(),
        "failed" => tr(lang, "A medição falhou").into(),
        other => match other.strip_prefix("missing-tool:") {
            Some(package) => format!(
                "{} {package}",
                lang.text(
                    "Requer o pacote",
                    "Requires the package",
                    "Requiere el paquete"
                )
            ),
            None => other.to_owned(),
        },
    }
}

pub fn network_step_name(lang: Lang, id: &str) -> &str {
    tr(
        lang,
        match id {
            "link" => "Cabo ou Wi-Fi",
            "address" => "Endereço IP",
            "gateway" => "Roteador",
            "dns" => "DNS",
            "internet" => "Internet",
            other => other,
        },
    )
}

pub fn network_step_status(lang: Lang, status: &str) -> &str {
    tr(
        lang,
        match status {
            "ok" => "Funcionando",
            "warn" => "Atenção",
            "fail" => "Aqui está o problema",
            "skipped" => "Não testado",
            other => other,
        },
    )
}

/// Fases do último boot, na ordem da barra do Vega.
pub const BOOT_PHASES: &[(&str, &str)] = &[
    ("firmware", "Firmware"),
    ("loader", "Carregador"),
    ("kernel", "Kernel"),
    ("initrd", "initrd"),
    ("userspace", "Sistema"),
];

/// pt → (en, es): do vega-gtk/po (en-US.po, es-ES.po), mais os textos que
/// só existem no painel.
const TRANSLATIONS: &[(&str, &str, &str)] = &[
    (
        "A bateria guarda bem menos carga do que quando era nova. Considere trocá-la.",
        "The battery holds much less charge than when it was new. Consider replacing it.",
        "La batería guarda mucha menos carga que cuando era nueva. Considere cambiarla.",
    ),
    (
        "A criptografia do disco se escolhe na instalação; para ativá-la, faça backup e reinstale com a opção de criptografar.",
        "Disk encryption is chosen during installation; to turn it on, back up and reinstall with the encryption option.",
        "El cifrado del disco se elige en la instalación; para activarlo, haga una copia de seguridad y reinstale con la opción de cifrar.",
    ),
    (
        "A sincronização está ligada, mas sem resposta. Confira a conexão com a internet.",
        "Synchronization is on but not responding. Check the internet connection.",
        "La sincronización está activada pero sin respuesta. Compruebe la conexión a internet.",
    ),
    (
        "Abra a página de login da rede em Rede → Minha internet não funciona.",
        "Open the network's login page in Network → My internet does not work.",
        "Abra la página de inicio de sesión de la red en Red → Mi internet no funciona.",
    ),
    (
        "Abrir Armazenamento",
        "Open Storage",
        "Abrir Almacenamiento",
    ),
    ("Abrir Backup", "Open Backup", "Abrir Copias de seguridad"),
    (
        "Abrir Data e hora",
        "Open Date and time",
        "Abrir Fecha y hora",
    ),
    ("Abrir Firewall", "Open Firewall", "Abrir Cortafuegos"),
    ("Abrir Liberar espaço", "Free up space", "Liberar espacio"),
    ("Abrir Logs", "Open Logs", "Abrir Registros"),
    ("Abrir Monitor", "Open Monitor", "Abrir Monitor"),
    ("Abrir Rede", "Open Network", "Abrir Red"),
    ("Abrir Serviços", "Open Services", "Abrir Servicios"),
    ("Abrir Usuários", "Open Users", "Abrir Usuarios"),
    (
        "Algum programa está usando a NVIDIA. Feche-o para economizar bateria.",
        "A program is using the NVIDIA GPU. Close it to save battery.",
        "Algún programa está usando la NVIDIA. Ciérrelo para ahorrar batería.",
    ),
    (
        "Algum programa precisa da rede logo no boot, por isso a espera fica. Se não usa esse programa, desabilite-o em Serviços.",
        "A program needs the network early in the boot, so the wait stays. If you do not use that program, disable it in Services.",
        "Algún programa necesita la red al inicio del arranque, por eso la espera se mantiene. Si no usa ese programa, deshabilítelo en Servicios.",
    ),
    (
        "Aproxime-se do roteador ou tire obstáculos do caminho.",
        "Move closer to the router or remove obstacles in between.",
        "Acérquese al router o quite obstáculos del camino.",
    ),
    (
        "Aqui está o problema",
        "Here is the problem",
        "Aquí está el problema",
    ),
    ("Atenção", "Attention", "Atención"),
    ("Cabo ou Wi-Fi", "Cable or Wi-Fi", "Cable o Wi-Fi"),
    ("Cancelado", "Cancelled", "Cancelado"),
    ("Carregador", "Boot loader", "Cargador"),
    (
        "Conecte o carregador e execute o teste de novo.",
        "Plug in the charger and run the test again.",
        "Conecte el cargador y ejecute la prueba de nuevo.",
    ),
    (
        "Configure um backup para não perder seus arquivos se o disco falhar.",
        "Set up a backup so you do not lose your files if the disk fails.",
        "Configure una copia de seguridad para no perder sus archivos si el disco falla.",
    ),
    (
        "Confira o cabo ou ligue o Wi-Fi e escolha uma rede.",
        "Check the cable or turn Wi-Fi on and pick a network.",
        "Revise el cable o encienda el Wi-Fi y elija una red.",
    ),
    (
        "Confira o estado do driver da GPU.",
        "Check the state of the GPU driver.",
        "Compruebe el estado del controlador de la GPU.",
    ),
    (
        "Corrigindo dependências",
        "Fixing dependencies",
        "Corrigiendo dependencias",
    ),
    (
        "Defina uma senha para essas contas, ou remova-as.",
        "Set a password for these accounts, or remove them.",
        "Defina una contraseña para estas cuentas, o elimínelas.",
    ),
    (
        "Desabilitar os serviços lentos que você habilitou",
        "Disable the slow services you enabled",
        "Deshabilitar los servicios lentos que usted habilitó",
    ),
    (
        "Desative o login do root por senha no SSH (PermitRootLogin) ou desligue o servidor SSH se não usa.",
        "Turn off root password login in SSH (PermitRootLogin), or switch off the SSH server if you do not use it.",
        "Desactive el inicio de sesión de root con contraseña en SSH (PermitRootLogin), o apague el servidor SSH si no lo usa.",
    ),
    (
        "Desempenho do disco",
        "Disk performance",
        "Rendimiento del disco",
    ),
    (
        "Desligue o roteador da tomada, espere 30 segundos e ligue de novo.",
        "Unplug the router, wait 30 seconds and plug it back in.",
        "Desenchufe el router, espere 30 segundos y vuelva a enchufarlo.",
    ),
    ("Endereço IP", "IP address", "Dirección IP"),
    (
        "Estado da plataforma",
        "Platform state",
        "Estado de la plataforma",
    ),
    (
        "Este serviço faz parte do sistema. Se o atraso continuar, veja o log dele.",
        "This service is part of the system. If the delay continues, check its log.",
        "Este servicio es parte del sistema. Si el retraso continúa, revise su registro.",
    ),
    ("Falha", "Failure", "Fallo"),
    (
        "Faça backup dos seus arquivos agora e planeje a troca do disco. O Vega não tenta consertar disco com defeito.",
        "Back up your files now and plan to replace the disk. Vega does not try to repair a failing disk.",
        "Haga una copia de seguridad de sus archivos ahora y planee cambiar el disco. Vega no intenta reparar un disco defectuoso.",
    ),
    (
        "Faça um backup agora, com o disco de backup conectado.",
        "Back up now, with the backup disk connected.",
        "Haga una copia ahora, con el disco de copias conectado.",
    ),
    (
        "Fechar as portas expostas no firewall",
        "Close the exposed ports in the firewall",
        "Cerrar los puertos expuestos en el cortafuegos",
    ),
    (
        "Feche a porta se não usa esse serviço a partir de outros computadores.",
        "Close the port if you do not use this service from other computers.",
        "Cierre el puerto si no usa este servicio desde otros equipos.",
    ),
    (
        "Feche alguns programas para liberar memória e execute o teste de novo.",
        "Close some programs to free memory and run the test again.",
        "Cierre algunos programas para liberar memoria y ejecute la prueba de nuevo.",
    ),
    ("Funcionando", "Working", "Funcionando"),
    (
        "Há atualizações de firmware. O Vega instala pelo fwupd e avisa se for preciso reiniciar.",
        "Firmware updates are available. Vega installs them through fwupd and tells you if a restart is needed.",
        "Hay actualizaciones de firmware. Vega las instala con fwupd y avisa si hace falta reiniciar.",
    ),
    ("Indisponível", "Unavailable", "No disponible"),
    (
        "Instalar as correções de segurança",
        "Install the security patches",
        "Instalar los parches de seguridad",
    ),
    (
        "Instalar as dependências que faltam",
        "Install the missing dependencies",
        "Instalar las dependencias que faltan",
    ),
    (
        "Integridade de pacotes",
        "Package integrity",
        "Integridad de paquetes",
    ),
    ("Interrompido", "Stopped", "Detenido"),
    (
        "Libere ao menos 10 GiB no disco e execute o teste de novo.",
        "Free at least 10 GiB on the disk and run the test again.",
        "Libere al menos 10 GiB en el disco y ejecute la prueba de nuevo.",
    ),
    (
        "Ligar a sincronização de hora pela rede",
        "Turn on network time synchronization",
        "Activar la sincronización de hora por red",
    ),
    (
        "Ligar o firewall",
        "Turn on the firewall",
        "Activar el cortafuegos",
    ),
    (
        "Limpe as saídas de ar, use o computador sobre uma superfície rígida e evite deixá-lo no colo durante tarefas pesadas.",
        "Clean the air vents, use the computer on a hard surface and avoid keeping it on your lap during heavy work.",
        "Limpie las salidas de aire, use el equipo sobre una superficie rígida y evite tenerlo en el regazo durante tareas pesadas.",
    ),
    (
        "Logs antigos do sistema",
        "Old system logs",
        "Registros antiguos del sistema",
    ),
    ("Logs e falhas", "Logs and failures", "Registros y fallos"),
    (
        "Memória sob carga",
        "Memory under load",
        "Memoria bajo carga",
    ),
    ("Nada para limpar", "Nothing to clean", "Nada que limpiar"),
    (
        "Não esperar pela rede para terminar o boot",
        "Do not wait for the network to finish booting",
        "No esperar a la red para terminar el arranque",
    ),
    ("Não testado", "Not tested", "No probado"),
    (
        "O /etc/fstab ainda monta um disco que foi removido. Tire a linha dele do fstab ou marque-a com nofail.",
        "/etc/fstab still mounts a disk that was removed. Remove its line from fstab or mark it nofail.",
        "/etc/fstab todavía monta un disco que se quitó. Quite su línea del fstab o márquela con nofail.",
    ),
    (
        "O SELinux reforça o isolamento dos serviços. A política do Lyra para ele ainda está em definição.",
        "SELinux strengthens the isolation of services. Lyra's policy for it is still being defined.",
        "SELinux refuerza el aislamiento de los servicios. La política de Lyra para él aún se está definiendo.",
    ),
    (
        "O disco está chegando ao fim da vida útil. Mantenha backups em dia e planeje a troca.",
        "The disk is reaching the end of its service life. Keep backups up to date and plan the replacement.",
        "El disco se acerca al final de su vida útil. Mantenga las copias de seguridad al día y planee el cambio.",
    ),
    (
        "O kernel registrou uma falha. Reinicie o computador; se voltar a acontecer, veja os logs.",
        "The kernel recorded a fault. Restart the computer; if it happens again, check the logs.",
        "El kernel registró un fallo. Reinicie el equipo; si vuelve a ocurrir, revise los registros.",
    ),
    (
        "O roteador responde, mas a internet não chega até ele. Verifique o modem ou fale com o provedor.",
        "The router answers, but the internet does not reach it. Check the modem or contact your provider.",
        "El router responde, pero internet no llega hasta él. Revise el módem o hable con su proveedor.",
    ),
    (
        "O serviço continua falhando. Veja o log dele para entender o motivo.",
        "The service still fails. Check its log to find out why.",
        "El servicio sigue fallando. Revise su registro para saber por qué.",
    ),
    (
        "Os dados brutos mostram quais programas falharam. Manter o sistema atualizado costuma resolver.",
        "The raw data shows which programs crashed. Keeping the system up to date usually fixes it.",
        "Los datos sin procesar muestran qué programas fallaron. Mantener el sistema actualizado suele resolverlo.",
    ),
    (
        "Pacotes baixados",
        "Downloaded packages",
        "Paquetes descargados",
    ),
    (
        "Pouco espaço livre faz atualizações e snapshots falharem. Veja o que dá para apagar com segurança.",
        "Low free space makes updates and snapshots fail. See what can be safely deleted.",
        "Poco espacio libre hace fallar las actualizaciones y las instantáneas. Vea qué se puede borrar con seguridad.",
    ),
    (
        "Prefira entrar no SSH com chave em vez de senha (PasswordAuthentication no).",
        "Prefer key login to passwords for SSH (PasswordAuthentication no).",
        "Prefiera entrar por SSH con clave en lugar de contraseña (PasswordAuthentication no).",
    ),
    (
        "Processador sob carga",
        "Processor under load",
        "Procesador bajo carga",
    ),
    ("Rede e internet", "Network and internet", "Red e internet"),
    (
        "Reiniciando serviços",
        "Restarting services",
        "Reiniciando servicios",
    ),
    (
        "Reiniciar os serviços que falharam",
        "Restart the failed services",
        "Reiniciar los servicios que fallaron",
    ),
    (
        "Reinicie quando puder para concluir a atualização.",
        "Restart when you can to finish the update.",
        "Reinicie cuando pueda para terminar la actualización.",
    ),
    (
        "Reinstalando pacotes",
        "Reinstalling packages",
        "Reinstalando paquetes",
    ),
    (
        "Reinstalar os pacotes alterados",
        "Reinstall the changed packages",
        "Reinstalar los paquetes modificados",
    ),
    (
        "Relatórios de falha (core dumps)",
        "Crash reports (core dumps)",
        "Informes de fallos (core dumps)",
    ),
    (
        "Requer o pacote {package}",
        "Requires the {package} package",
        "Requiere el paquete {package}",
    ),
    ("Roteador", "Router", "Router"),
    ("Saudável", "Healthy", "Saludable"),
    ("Saúde do disco", "Disk health", "Salud del disco"),
    (
        "Se quiser essa proteção, ative o Secure Boot nas configurações de firmware (UEFI) do computador.",
        "If you want this protection, turn on Secure Boot in the computer's firmware (UEFI) settings.",
        "Si quiere esta protección, active Secure Boot en la configuración del firmware (UEFI) del equipo.",
    ),
    ("Segurança", "Security", "Seguridad"),
    ("Sistema", "System", "Sistema"),
    ("Sistema de arquivos", "File system", "Sistema de archivos"),
    (
        "Snapshots fora da política",
        "Snapshots beyond the policy",
        "Instantáneas fuera de la política",
    ),
    (
        "Só administradores (grupo wheel) devem usar sudo. Revise as contas.",
        "Only administrators (wheel group) should use sudo. Review the accounts.",
        "Solo los administradores (grupo wheel) deben usar sudo. Revise las cuentas.",
    ),
    ("Tempo de boot", "Boot time", "Tiempo de arranque"),
    (
        "Tente de novo. Se voltar a acontecer, exporte o relatório e abra uma issue.",
        "Try again. If it happens again, export the report and open an issue.",
        "Inténtelo de nuevo. Si vuelve a ocurrir, exporte el informe y abra una incidencia.",
    ),
    (
        "Veja abaixo quais serviços atrasam o boot. Desabilitar o que você não usa acelera a inicialização.",
        "See below which services slow the boot. Disabling what you do not use speeds up startup.",
        "Vea abajo qué servicios retrasan el arranque. Deshabilitar lo que no usa acelera el inicio.",
    ),
    ("Ver atualizações", "View updates", "Ver actualizaciones"),
    ("Protegido", "Protected", "Protegido"),
    ("Em uso agora", "In use right now", "En uso ahora"),
    (
        "A medição falhou",
        "The measurement failed",
        "La medición falló",
    ),
    (
        "Não configurado nesta instalação",
        "Not configured on this installation",
        "No configurado en esta instalación",
    ),
    (
        "Kernels antigos (com snapshot antes)",
        "Old kernels (with a snapshot first)",
        "Núcleos antiguos (con instantánea antes)",
    ),
    (
        "Runtimes Flatpak sem uso",
        "Unused Flatpak runtimes",
        "Runtimes de Flatpak sin uso",
    ),
    ("Wi-Fi", "Wi-Fi", "Wi-Fi"),
    ("rede", "network", "red"),
];
