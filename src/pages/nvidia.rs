//! NVIDIA reads run as vega-web. Installation uses the existing per-user
//! PAM/Polkit broker; a session-bound observer never retries a mutation.
use super::{html_escape, render};
use crate::{
    auth::CurrentUser,
    state::{AppState, SESSION_COOKIE, SessionLease},
};
use axum::{
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::PrivateCookieJar;
use lyra_vega_dbus::{MetadataClient, SoftwareClient, SoftwareEvent, SoftwareEventStream};
use rand::RngExt;
use serde::Deserialize;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug)]
pub enum Language {
    Pt,
    En,
    Es,
}
impl Language {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pt" => Some(Self::Pt),
            "en" => Some(Self::En),
            "es" => Some(Self::Es),
            _ => None,
        }
    }
    fn code(self) -> &'static str {
        match self {
            Self::Pt => "pt",
            Self::En => "en",
            Self::Es => "es",
        }
    }
    pub fn text(self, pt: &'static str, en: &'static str, es: &'static str) -> &'static str {
        match self {
            Self::Pt => pt,
            Self::En => en,
            Self::Es => es,
        }
    }
}

#[derive(Deserialize, Default)]
pub struct Options {
    lang: Option<String>,
}
fn language(options: &Options, headers: &HeaderMap) -> Language {
    if let Some(lang) = options.lang.as_deref().and_then(Language::parse) {
        return lang;
    }
    let mut candidates = Vec::new();
    if let Some(value) = headers
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok())
    {
        for (index, item) in value.split(',').enumerate() {
            let mut parts = item.trim().split(';');
            let code = parts
                .next()
                .unwrap_or("")
                .split('-')
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            let quality = parts
                .find_map(|p| p.trim().strip_prefix("q="))
                .map_or(1.0, |v| v.parse::<f32>().unwrap_or(0.0));
            if quality > 0.0
                && quality <= 1.0
                && let Some(lang) = Language::parse(&code)
            {
                candidates.push((quality, index, lang))
            }
        }
    }
    candidates.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(&b.1)));
    candidates
        .first()
        .map_or(Language::En, |(_, _, lang)| *lang)
}

// UI view of the shared SDK recovery response.
type RecoveryRow = (bool, String, String, String, String);

async fn diagnostics(
    state: &AppState,
) -> Result<(lyra_vega_dbus::NvidiaStatus, RecoveryRow), String> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let metadata = state
            .dbus
            .metadata()
            .metadata()
            .await
            .map_err(|e| e.to_string())?;
        if !["nvidia-official-v1", "nvidia-recovery-v1"]
            .iter()
            .all(|required| metadata.capabilities.iter().any(|c| c == required))
        {
            return Err("Update vegad: nvidia-recovery-v1 is required".into());
        }
        let status = state
            .dbus
            .software()
            .nvidia_status()
            .await
            .map_err(|e| e.to_string())?;
        let recovery = state
            .dbus
            .software()
            .nvidia_recovery()
            .await
            .map_err(|e| e.to_string())?;
        Ok((
            status,
            (
                recovery.available,
                recovery.kind,
                recovery.reference,
                recovery.state,
                recovery.detail,
            ),
        ))
    })
    .await
    .map_err(|_| "NVIDIA diagnostics timed out".to_owned())?
}

fn installable(status: &lyra_vega_dbus::NvidiaStatus, recovery: &RecoveryRow) -> bool {
    status.supported && matches!(status.state.as_str(), "available" | "unmanaged") && recovery.0
}

fn state_label(lang: Language, state: &str) -> &'static str {
    match state {
        "available" => lang.text(
            "Disponível para instalação",
            "Available to install",
            "Disponible para instalar",
        ),
        "unmanaged" => lang.text(
            "Driver oficial instalado; falta a integração Lyra",
            "Official driver installed; Lyra integration is missing",
            "Controlador oficial instalado; falta la integración Lyra",
        ),
        "active" => lang.text(
            "Driver ativo e verificado",
            "Driver active and verified",
            "Controlador activo y verificado",
        ),
        "reboot-required" => lang.text(
            "Reinicialização necessária",
            "Restart required",
            "Es necesario reiniciar",
        ),
        "no-gpu" => lang.text(
            "Nenhuma GPU NVIDIA detectada",
            "No NVIDIA GPU detected",
            "No se detectó ninguna GPU NVIDIA",
        ),
        _ => lang.text(
            "Instalação bloqueada; confira o diagnóstico",
            "Installation blocked; review the diagnostics",
            "Instalación bloqueada; revise el diagnóstico",
        ),
    }
}

fn recovery_body(lang: Language, recovery: &RecoveryRow) -> String {
    let explanation = if recovery.1 == "restic-offline" {
        lang.text("Cópia local verificada do sistema. Para restaurar, inicie por mídia de recuperação e monte a raiz original. Dados dos serviços, pasta pessoal e ESP ficam fora da cópia. Não protege contra falha do disco.",
        "Verified local OS backup. To restore, boot rescue media and mount the original root. Service data, home and ESP are excluded. This does not protect against disk failure.",
        "Copia local verificada del sistema. Para restaurar, arranque un medio de rescate y monte la raíz original. Se excluyen datos de servicios, carpetas personales y ESP. No protege contra fallos del disco.")
    } else if recovery.1 == "snapper" {
        lang.text(
            "Snapshot Snapper da raiz. Nenhum rollback ou reinício automático.",
            "Root Snapper snapshot. No automatic rollback or restart.",
            "Snapshot Snapper de la raíz. Sin reversión ni reinicio automáticos.",
        )
    } else {
        lang.text(
            "Uma estratégia de recuperação qualificada é obrigatória.",
            "A qualified recovery strategy is required.",
            "Se requiere una estrategia de recuperación cualificada.",
        )
    };
    let mut body = format!(
        "<h3>{}</h3><p>{explanation}</p><p><code>{} {} ({})</code></p><p>{}</p>",
        lang.text("Recuperação", "Recovery", "Recuperación"),
        html_escape(&recovery.1),
        html_escape(&recovery.2),
        html_escape(&recovery.3),
        html_escape(&recovery.4)
    );
    if recovery.1 == "restic-offline"
        && recovery.2.len() == 32
        && recovery.2.bytes().all(|c| c.is_ascii_hexdigit())
    {
        body.push_str(&format!(
            "<pre>/usr/lib/vega/vegad nvidia-recover --target /mnt --reference {} --confirm</pre>",
            recovery.2
        ));
    }
    body
}

fn response(username: &str, body: String) -> Response {
    let mut response = render("NVIDIA", "/hardware", username, body).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
    response
}

pub async fn handler(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Extension(CurrentUser(username)): Extension<CurrentUser>,
    Query(options): Query<Options>,
    headers: HeaderMap,
) -> Response {
    let Some(lease) = jar
        .get(SESSION_COOKIE)
        .and_then(|c| state.sessions.lease(c.value(), Instant::now()))
    else {
        return Redirect::to("/login").into_response();
    };
    if lease.username != username {
        return Redirect::to("/login").into_response();
    }
    let lang = language(&options, &headers);
    let mut body="<p><a href=\"?lang=pt\">Português</a> · <a href=\"?lang=en\">English</a> · <a href=\"?lang=es\">Español</a></p>".to_owned();
    match diagnostics(&state).await {
        Err(error) => body.push_str(&format!(
            "<p>{}: {}</p>",
            lang.text(
                "Diagnóstico indisponível",
                "Diagnostics unavailable",
                "Diagnóstico no disponible"
            ),
            html_escape(&error)
        )),
        Ok((status, recovery)) => {
            body.push_str(&format!(
                "<h3>{}</h3><p>{}</p><p>Secure Boot: {}</p><p>{} [{}]</p>",
                state_label(lang, &status.state),
                html_escape(&status.gpu),
                html_escape(&status.secure_boot),
                html_escape(&status.detail),
                html_escape(&status.state)
            ));
            body.push_str(&recovery_body(lang, &recovery));
            if installable(&status, &recovery) && state.admin_socket.is_some() {
                body.push_str(&format!(r#"<h3>{}</h3><p>{}</p><form method="post" action="/administracao">
<input type="hidden" name="action" value="install-nvidia"><input type="hidden" name="csrf" value="{}"><input type="hidden" name="language" value="{}">
<label><input type="checkbox" name="confirmed" value="yes" required> {}</label>
<label>{}<br><input type="password" name="password" required autocomplete="current-password" maxlength="4096"></label>
<button type="submit">{}</button></form>"#,
                    lang.text("Instalação opcional","Optional installation","Instalación opcional"),
                    lang.text("RPMs oficiais NVIDIA 610.57.04, módulo assinado SUSE e integração Lyra. Requer internet, espaço para recuperação e conta administrativa. A cópia será verificada antes de instalar. Não desligue durante a operação.",
                    "Official NVIDIA 610.57.04 RPMs, SUSE-signed module and Lyra integration. Requires internet, recovery space and an administrator account. Recovery is verified before installation. Do not power off during the operation.",
                    "RPM oficiales NVIDIA 610.57.04, módulo firmado por SUSE e integración Lyra. Requiere internet, espacio para recuperación y cuenta administrativa. Se verificará la copia antes de instalar. No apague durante la operación."),
                    html_escape(&lease.csrf),lang.code(),lang.text("Revisei a instalação e a recuperação; desejo continuar.","I reviewed installation and recovery and want to continue.","He revisado la instalación y la recuperación y deseo continuar."),
                    lang.text("Senha","Password","Contraseña"),lang.text("Autorizar instalação","Authorize installation","Autorizar instalación")));
            }
        }
    }
    response(&username, body)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Running,
    Success,
    Failed,
    Unconfirmed,
}
#[derive(Clone)]
struct Job {
    binding: [u8; 32],
    created: Instant,
    lang: Language,
    transaction: u32,
    percent: u32,
    detail: String,
    phase: Phase,
}
#[derive(Clone, Default)]
pub struct Jobs(Arc<Mutex<HashMap<String, Job>>>);
impl Jobs {
    fn reserve(&self, binding: [u8; 32], lang: Language) -> Result<String, String> {
        let mut jobs = self.0.lock().unwrap();
        jobs.retain(|_, j| j.created.elapsed() < Duration::from_secs(3 * 60 * 60));
        if jobs.len() >= 64 || jobs.values().any(|j| j.phase == Phase::Running) {
            return Err("NVIDIA operation already pending or observer capacity reached".into());
        }
        let mut random = [0u8; 16];
        rand::rng().fill(&mut random);
        let id: String = random.iter().map(|b| format!("{b:02x}")).collect();
        jobs.insert(
            id.clone(),
            Job {
                binding,
                created: Instant::now(),
                lang,
                transaction: 0,
                percent: 0,
                detail: String::new(),
                phase: Phase::Running,
            },
        );
        Ok(id)
    }
    fn update(&self, id: &str, phase: Phase, percent: u32, detail: String) {
        if let Some(job) = self.0.lock().unwrap().get_mut(id) {
            job.phase = phase;
            job.percent = percent.min(100);
            job.detail = detail.chars().take(4096).collect();
        }
    }
}

pub struct Prepared {
    jobs: Jobs,
    id: Option<String>,
    events: Option<SoftwareEventStream>,
}
impl Drop for Prepared {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            self.jobs.0.lock().unwrap().remove(&id);
        }
    }
}
pub async fn prepare(
    state: &AppState,
    binding: [u8; 32],
    lang: Language,
) -> Result<Prepared, String> {
    let (status, recovery) = diagnostics(state).await?;
    if !installable(&status, &recovery) {
        return Err(format!(
            "NVIDIA installation unavailable: {} / {}",
            status.state, recovery.4
        ));
    }
    let id = state.nvidia_jobs.reserve(binding, lang)?;
    let mut pending = Prepared {
        jobs: state.nvidia_jobs.clone(),
        id: Some(id),
        events: None,
    };
    // Subscribe before PAM/Polkit: completion may arrive before IPC returns.
    pending.events = Some(
        state
            .dbus
            .software()
            .subscribe()
            .await
            .map_err(|e| e.to_string())?,
    );
    Ok(pending)
}
impl Prepared {
    pub fn accepted(mut self, transaction: u32, mut lease: SessionLease) -> Response {
        let id = self.id.take().expect("prepared job");
        let mut events = self.events.take().expect("prepared observer");
        let jobs = self.jobs.clone();
        jobs.0
            .lock()
            .unwrap()
            .get_mut(&id)
            .expect("reserved job")
            .transaction = transaction;
        let url = format!("/hardware/nvidia/progress/{id}");
        tokio::spawn(async move {
            if transaction == 0 {
                jobs.update(&id, Phase::Unconfirmed, 0, "Invalid transaction ID".into());
                return;
            }
            loop {
                let result = tokio::select! {
                    biased;
                    _=lease.revoked()=>{jobs.update(&id,Phase::Unconfirmed,0,"Session ended; review NVIDIA status before retrying".into());return},
                    result=events.next_transaction(transaction)=>result,
                };
                match result {
                    Ok(SoftwareEvent::Progress(p)) if p.transaction_id == transaction => {
                        jobs.update(&id, Phase::Running, p.percent, p.message)
                    }
                    Ok(SoftwareEvent::Finished(f)) if f.transaction_id == transaction => {
                        jobs.update(
                            &id,
                            if f.success {
                                Phase::Success
                            } else {
                                Phase::Failed
                            },
                            if f.success { 100 } else { 0 },
                            f.message,
                        );
                        return;
                    }
                    Ok(_) => {}
                    Err(error) => {
                        jobs.update(&id, Phase::Unconfirmed, 0, error.to_string());
                        return;
                    }
                }
            }
        });
        Redirect::to(&url).into_response()
    }
}

pub async fn progress(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Extension(CurrentUser(username)): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Response {
    let Some(lease) = jar
        .get(SESSION_COOKIE)
        .and_then(|c| state.sessions.lease(c.value(), Instant::now()))
    else {
        return Redirect::to("/login").into_response();
    };
    let job = state
        .nvidia_jobs
        .0
        .lock()
        .unwrap()
        .get(&id)
        .filter(|j| j.binding == lease.admin_binding && lease.username == username)
        .cloned();
    let Some(job) = job else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let lang = job.lang;
    let label = match job.phase {
        Phase::Running => lang.text(
            "Operação em andamento; aguarde a conclusão.",
            "Operation in progress; wait for completion.",
            "Operación en curso; espere la finalización.",
        ),
        Phase::Success => lang.text(
            "Instalação concluída e verificada. Confira o estado antes de reiniciar.",
            "Installation completed and verified. Review the status before restarting.",
            "Instalación completada y verificada. Revise el estado antes de reiniciar.",
        ),
        Phase::Failed => lang.text(
            "A instalação falhou. Confira o diagnóstico e a recuperação antes de repetir.",
            "Installation failed. Check diagnostics and recovery before retrying.",
            "La instalación falló. Revise el diagnóstico y la recuperación antes de repetir.",
        ),
        Phase::Unconfirmed => lang.text(
            "Resultado não confirmado. Consulte o diagnóstico; não repita automaticamente.",
            "Result not confirmed. Review diagnostics; do not retry automatically.",
            "Resultado no confirmado. Revise el diagnóstico; no repita automáticamente.",
        ),
    };
    let mut body = format!(
        "<h3>{label}</h3><p>#{} · {}%</p><p>{}</p><p><a href=\"/hardware/nvidia?lang={}\">{}</a></p>",
        job.transaction,
        job.percent,
        html_escape(&job.detail),
        lang.code(),
        lang.text(
            "Diagnóstico e recuperação",
            "Diagnostics and recovery",
            "Diagnóstico y recuperación"
        )
    );
    if job.phase != Phase::Running
        && let Ok((_, recovery)) = diagnostics(&state).await
    {
        body.push_str(&recovery_body(lang, &recovery));
    }
    let mut result = response(&username, body);
    if job.phase == Phase::Running {
        result.headers_mut().insert("refresh", "3".parse().unwrap());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SignalSoftware;
    #[zbus::interface(name = "org.lyraos.Vega1.Software")]
    impl SignalSoftware {
        #[zbus(signal)]
        async fn transaction_finished(
            emitter: &zbus::object_server::SignalEmitter<'_>,
            transaction_id: u32,
            success: bool,
            message: &str,
        ) -> zbus::Result<()>;
    }

    #[tokio::test]
    #[ignore = "requires private D-Bus: scripts/check-authorization-contracts.sh"]
    async fn authorization_integration_nvidia_observer_correlates_completion_and_session() {
        assert_eq!(
            std::env::var("VEGA_WEB_TEST_PRIVATE_BUS").as_deref(),
            Ok("1")
        );
        assert_eq!(
            std::env::var("DBUS_SYSTEM_BUS_ADDRESS").unwrap(),
            std::env::var("DBUS_SESSION_BUS_ADDRESS").unwrap()
        );
        for mode in ["success", "failure", "owner-loss", "session-loss"] {
            let daemon = zbus::connection::Builder::system()
                .unwrap()
                .name("org.lyraos.Vega1")
                .unwrap()
                .serve_at("/org/lyraos/Vega1", SignalSoftware)
                .unwrap()
                .build()
                .await
                .unwrap();
            let dbus = lyra_vega_dbus::VegaDbus::connect().await.unwrap();
            let events = dbus.software().subscribe().await.unwrap();
            let sessions = crate::state::SessionStore::default();
            sessions.insert(
                "test".into(),
                crate::state::Session::new("alice".into(), Instant::now()),
            );
            let lease = sessions.lease("test", Instant::now()).unwrap();
            let jobs = Jobs::default();
            let id = jobs.reserve(lease.admin_binding, Language::En).unwrap();
            let emitter =
                zbus::object_server::SignalEmitter::new(&daemon, "/org/lyraos/Vega1").unwrap();
            SignalSoftware::transaction_finished(&emitter, 999, true, "other transaction")
                .await
                .unwrap();
            if matches!(mode, "success" | "failure") {
                // Both signals precede the IPC acknowledgement.
                SignalSoftware::transaction_finished(
                    &emitter,
                    7,
                    mode == "success",
                    "<script>diagnostic</script>",
                )
                .await
                .unwrap();
            }
            let pending = Prepared {
                jobs: jobs.clone(),
                id: Some(id.clone()),
                events: Some(events),
            };
            let reply = pending.accepted(7, lease);
            assert_eq!(reply.status(), StatusCode::SEE_OTHER);
            assert_eq!(
                reply.headers()[header::LOCATION],
                format!("/hardware/nvidia/progress/{id}")
            );
            if mode == "owner-loss" {
                daemon.release_name("org.lyraos.Vega1").await.unwrap();
            }
            if mode == "session-loss" {
                sessions.remove("test");
            }
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    if jobs.0.lock().unwrap().get(&id).unwrap().phase != Phase::Running {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect(mode);
            let expected = match mode {
                "success" => Phase::Success,
                "failure" => Phase::Failed,
                _ => Phase::Unconfirmed,
            };
            assert!(
                jobs.0.lock().unwrap().get(&id).unwrap().phase == expected,
                "{mode}"
            );
            if mode != "owner-loss" {
                daemon.release_name("org.lyraos.Vega1").await.unwrap();
            }
        }
    }
    #[test]
    fn language_negotiation_and_explicit_override() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT_LANGUAGE,
            "en-US;q=0.5,pt-BR;q=0,es-ES;q=0.9".parse().unwrap(),
        );
        assert_eq!(language(&Options::default(), &headers).code(), "es");
        assert_eq!(
            language(
                &Options {
                    lang: Some("pt".into())
                },
                &headers
            )
            .code(),
            "pt"
        );
    }
    #[test]
    fn recovery_escapes_diagnostics_and_never_builds_arbitrary_command() {
        let row = (
            true,
            "restic-offline".into(),
            "<script>bad</script>".into(),
            "ready".into(),
            "<img src=x onerror=evil()>".into(),
        );
        for lang in [Language::Pt, Language::En, Language::Es] {
            let body = recovery_body(lang, &row);
            assert!(!body.contains("<script>"));
            assert!(!body.contains("<img"));
            assert!(!body.contains("nvidia-recover"));
            assert!(body.contains("&lt;script&gt;"));
        }
    }
    #[test]
    fn pending_requests_are_exclusive_and_drop_releases_reservation() {
        let jobs = Jobs::default();
        let id = jobs.reserve([1; 32], Language::En).unwrap();
        assert!(jobs.reserve([2; 32], Language::Pt).is_err());
        let pending = Prepared {
            jobs: jobs.clone(),
            id: Some(id),
            events: None,
        };
        drop(pending);
        assert!(jobs.reserve([2; 32], Language::Pt).is_ok());
    }
    #[test]
    fn observer_clamps_untrusted_progress_and_bounds_messages() {
        let jobs = Jobs::default();
        let id = jobs.reserve([1; 32], Language::En).unwrap();
        jobs.update(&id, Phase::Running, u32::MAX, "á".repeat(9000));
        let map = jobs.0.lock().unwrap();
        let j = map.get(&id).unwrap();
        assert_eq!(j.percent, 100);
        assert_eq!(j.detail.chars().count(), 4096);
    }
}
