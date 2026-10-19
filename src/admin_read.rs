//! Administrative reads performed through the broker with the user's own
//! identity. The worker serializes one of these payloads as JSON; the panel
//! keeps it in the session for a few minutes and renders it.
use serde::{Deserialize, Serialize};

/// Which read a `Operation::Read` performs. Each maps to one `*.read-admin`
/// polkit action and one page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadQuery {
    KernelBoot,
    BackupConfigs,
    Snapshots,
    LogUnits,
    Firewall,
}

impl ReadQuery {
    pub const ALL: [ReadQuery; 5] = [
        Self::KernelBoot,
        Self::BackupConfigs,
        Self::Snapshots,
        Self::LogUnits,
        Self::Firewall,
    ];

    /// Stable key for the session cache and the form `action`.
    pub fn key(self) -> &'static str {
        match self {
            Self::KernelBoot => "kernel",
            Self::BackupConfigs => "backup",
            Self::Snapshots => "snapshots",
            Self::LogUnits => "logs",
            Self::Firewall => "firewall",
        }
    }

    pub fn from_key(key: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|query| query.key() == key)
    }

    pub fn code(self) -> u8 {
        match self {
            Self::KernelBoot => 20,
            Self::BackupConfigs => 21,
            Self::Snapshots => 22,
            Self::LogUnits => 23,
            Self::Firewall => 24,
        }
    }

    pub fn from_code(code: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|query| query.code() == code)
    }

    pub fn action_id(self) -> &'static str {
        match self {
            Self::KernelBoot => "org.lyraos.vega.kernel.read-admin",
            Self::BackupConfigs => "org.lyraos.vega.backup.read-admin",
            Self::Snapshots => "org.lyraos.vega.snapshots.read-admin",
            Self::LogUnits => "org.lyraos.vega.logs.read-admin",
            Self::Firewall => "org.lyraos.vega.firewall.read-admin",
        }
    }

    pub fn return_href(self) -> &'static str {
        match self {
            Self::KernelBoot => "/hardware",
            Self::BackupConfigs => "/backup",
            Self::Snapshots => "/snapshots",
            Self::LogUnits => "/logs",
            Self::Firewall => "/rede",
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            Self::KernelBoot => "Ler o status de boot e as entradas do carregador",
            Self::BackupConfigs => "Ler as configurações de backup",
            Self::Snapshots => "Ler a lista de snapshots",
            Self::LogUnits => "Ler a lista de unidades do journal",
            Self::Firewall => "Ler os serviços e as portas do firewall",
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct KernelBoot {
    pub loader: String,
    pub default_entry: String,
    pub timeout: u32,
    pub cmdline: String,
    pub entries: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct BackupConfig {
    pub id: String,
    pub paths: Vec<String>,
    pub destination: String,
    pub frequency: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct BackupConfigs {
    pub configs: Vec<BackupConfig>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct Snapshot {
    pub id: u32,
    pub timestamp: i64,
    pub trigger: String,
    pub description: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct Snapshots {
    pub available: bool,
    pub snapshots: Vec<Snapshot>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct LogUnits {
    pub units: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct FirewallService {
    pub name: String,
    pub label: String,
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct FirewallPort {
    pub port: String,
    pub protocol: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct Firewall {
    pub services: Vec<FirewallService>,
    pub ports: Vec<FirewallPort>,
}

/// Upper bound of a serialized payload crossing the broker.
pub const MAX_PAYLOAD: usize = 1 << 20;
