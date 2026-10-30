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
    /// The last periodic health check (`Diagnostics.LastPeriodic`).
    LastPeriodic,
    /// What `Cleanup.Clean` could free (`Cleanup.Scan`).
    CleanupScan,
}

impl ReadQuery {
    pub const ALL: [ReadQuery; 7] = [
        Self::KernelBoot,
        Self::BackupConfigs,
        Self::Snapshots,
        Self::LogUnits,
        Self::Firewall,
        Self::LastPeriodic,
        Self::CleanupScan,
    ];

    /// Stable key for the session cache and the form `action`.
    pub fn key(self) -> &'static str {
        match self {
            Self::KernelBoot => "kernel",
            Self::BackupConfigs => "backup",
            Self::Snapshots => "snapshots",
            Self::LogUnits => "logs",
            Self::Firewall => "firewall",
            Self::LastPeriodic => "periodic",
            Self::CleanupScan => "cleanup",
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
            Self::LastPeriodic => 25,
            Self::CleanupScan => 26,
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
            Self::LastPeriodic => "org.lyraos.vega.hardware.read-admin",
            Self::CleanupScan => "org.lyraos.vega.storage.read-admin",
        }
    }

    pub fn return_href(self) -> &'static str {
        match self {
            Self::KernelBoot => "/hardware",
            Self::BackupConfigs => "/backup",
            Self::Snapshots => "/snapshots",
            Self::LogUnits => "/logs",
            Self::Firewall => "/rede",
            Self::LastPeriodic => "/hardware/diagnostico",
            Self::CleanupScan => "/armazenamento",
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            Self::KernelBoot => "Ler o status de boot e as entradas do carregador",
            Self::BackupConfigs => "Ler as configurações de backup",
            Self::Snapshots => "Ler a lista de snapshots",
            Self::LogUnits => "Ler a lista de unidades do journal",
            Self::Firewall => "Ler os serviços e as portas do firewall",
            Self::LastPeriodic => "Ler o resultado da última verificação periódica",
            Self::CleanupScan => "Medir o espaço que pode ser liberado",
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

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct PeriodicStage {
    pub id: String,
    pub verdict: String,
    pub summary: String,
}

/// `Diagnostics.LastPeriodic`; `job` 0 means the check never ran.
#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct LastPeriodic {
    pub job: u32,
    pub finished: i64,
    pub novelties: u32,
    pub stages: Vec<PeriodicStage>,
    pub novelty_texts: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct CleanupCategory {
    pub id: String,
    pub bytes: u64,
    pub can_clean: bool,
    pub count: Option<u64>,
    pub size_unknown: bool,
    pub minimum: bool,
    pub reason: Option<String>,
    pub items: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct CleanupScan {
    pub categories: Vec<CleanupCategory>,
}

/// The network test and its report, read in one broker operation.
#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct NetworkCheck {
    pub job: u32,
    pub report: String,
}

/// Upper bound of a serialized payload crossing the broker.
pub const MAX_PAYLOAD: usize = 1 << 20;
