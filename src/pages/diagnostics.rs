//! Diagnóstico de saúde, Minha internet não funciona, Liberar espaço e Pedir
//! ajuda (add-web-diagnostics). O que é público (lista de testes, job em
//! andamento, consertos disponíveis, verificação periódica) vem da conexão
//! D-Bus do HTTPS; o resto passa pelo broker com a senha do administrador, e
//! os relatórios lidos ficam na sessão por cinco minutos, como as outras
//! leituras administrativas.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Extension, Form, Path, Query, RawForm, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::PrivateCookieJar;
use lyra_vega_dbus::{CleanupEvent, CleanupEventStream, DiagnosticRemedy, DiagnosticsClient};
use rand::RngExt;
use serde::Deserialize;
use serde_json::Value;
use vega_web::admin_ipc::Operation;
use vega_web::admin_read::{CleanupScan, LastPeriodic, NetworkCheck, ReadQuery};
use vega_web::diagnostics_text as text;
use vega_web::help_text;
use vega_web::lang::Lang;

use crate::auth::CurrentUser;
use crate::state::{AppState, SESSION_COOKIE, SessionLease};

use super::admin::ActionForm;
use super::{Actions, READ_MAX_AGE, cached_read, csrf_token, error_body, html_escape, render};

const PAGE: &str = "/hardware/diagnostico";

fn session_json(state: &AppState, jar: &PrivateCookieJar, key: &str) -> Option<Value> {
    let cookie = jar.get(SESSION_COOKIE)?;
    let json = state
        .sessions
        .cached_read(cookie.value(), key, READ_MAX_AGE)?;
    serde_json::from_str(&json).ok()
}

fn report_key(job: u32, redact: bool) -> String {
    format!("{}-{job}", if redact { "help" } else { "report" })
}

fn str_of<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}

fn stages(report: &Value) -> Vec<&Value> {
    report
        .get("stages")
        .and_then(Value::as_array)
        .map(|stages| stages.iter().collect())
        .unwrap_or_default()
}

fn findings(stage: &Value) -> Vec<&Value> {
    stage
        .get("findings")
        .and_then(Value::as_array)
        .map(|findings| findings.iter().collect())
        .unwrap_or_default()
}

fn badge(lang: Lang, verdict: &str) -> String {
    let class = match verdict {
        "ok" => "on",
        "attention" | "fail" => "warn",
        _ => "",
    };
    format!(
        r#"<span class="badge {class}">{}</span>"#,
        html_escape(text::verdict_label(lang, verdict))
    )
}

fn seconds(lang: Lang, value: f64) -> String {
    let text = format!("{value:.1} s");
    if lang == Lang::En {
        text
    } else {
        text.replace('.', ",")
    }
}

/// After the broker accepted one of these operations, where the panel goes.
pub(crate) fn accepted(
    state: &AppState,
    jar: &PrivateCookieJar,
    user: &CurrentUser,
    operation: &Operation,
    transaction: u32,
    payload: &[u8],
) -> Option<Response> {
    let store = |key: &str| {
        if let (Some(cookie), Ok(json)) = (jar.get(SESSION_COOKIE), std::str::from_utf8(payload)) {
            state
                .sessions
                .store_read(cookie.value(), key, json.to_owned());
        }
    };
    match operation {
        Operation::DiagnosticsStart(_) | Operation::RepairFindings { .. } => {
            Some(Redirect::to(&format!("{PAGE}?job={transaction}")).into_response())
        }
        Operation::NetworkCheck => {
            store("network");
            Some(Redirect::to("/rede/internet").into_response())
        }
        Operation::DiagnosticsReport { job, redact } => {
            // Job 0 is the latest report: file it under its real number.
            let job = serde_json::from_slice::<Value>(payload)
                .ok()
                .and_then(|report| report.get("jobId").and_then(Value::as_u64))
                .and_then(|id| u32::try_from(id).ok())
                .filter(|id| *id > 0)
                .unwrap_or(*job);
            store(&report_key(job, *redact));
            let page = if *redact { "ajuda" } else { "relatorio" };
            Some(Redirect::to(&format!("{PAGE}/{page}/{job}")).into_response())
        }
        Operation::MarkLogsSeen(_) => {
            let t =
                |pt: &'static str, en: &'static str, es: &'static str| user.lang.text(pt, en, es);
            Some(
                render(
                    t("Já vi os logs", "I have seen the logs", "Ya vi los registros"),
                    PAGE,
                    user,
                    format!(
                        r#"<p class="notice success">{}</p><p><a class="button-link" href="{PAGE}">{}</a></p>"#,
                        t(
                            "Pronto. O próximo teste de logs só conta o que acontecer daqui em diante.",
                            "Done. The next logs test only counts what happens from now on.",
                            "Listo. La próxima prueba de registros solo cuenta lo que ocurra a partir de ahora.",
                        ),
                        t("Voltar", "Back", "Volver"),
                    ),
                )
                .into_response(),
            )
        }
        _ => None,
    }
}

#[derive(Deserialize)]
pub struct JobQuery {
    job: Option<u32>,
}

/// Hardware e Kernel → Diagnóstico de saúde.
pub async fn handler(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<JobQuery>,
) -> Response {
    let actions = Actions::new(&state, &jar, &user);
    let lang = user.lang;
    let t = move |pt: &'static str, en: &'static str, es: &'static str| lang.text(pt, en, es);
    let diagnostics = state.dbus.diagnostics();
    let mut body = format!(
        "<p>{}</p>",
        t(
            "Testa disco, sistema, segurança, rede e boot sem alterar nada. As ações pedem a sua senha.",
            "Tests disk, system, security, network and boot without changing anything. Actions ask for your password.",
            "Prueba disco, sistema, seguridad, red y arranque sin cambiar nada. Las acciones piden su contraseña.",
        )
    );
    body.push_str(&actions.notice());
    let current = diagnostics.current().await;
    let running = matches!(&current, Ok(job) if job.job_id != 0);
    match &current {
        Ok(job) if job.job_id != 0 => body.push_str(&format!(
            r#"<section class="panel"><div class="panel-head"><h3>{} {} {}</h3><span class="badge">{}%</span></div>
<p>{}: <strong>{}</strong></p>
<div class="bar-track"><div class="bar-value bar-accent" style="width: {}%"></div></div>
<p class="empty">{}</p></section>"#,
            t("Diagnóstico", "Diagnostics", "Diagnóstico"),
            job.job_id,
            t("em andamento", "in progress", "en curso"),
            job.percent.min(100),
            t("Testando", "Testing", "Probando"),
            html_escape(text::test_name(lang, &job.stage)),
            job.percent.min(100),
            t("A página se atualiza sozinha.", "The page refreshes by itself.", "La página se actualiza sola."),
        )),
        Ok(_) => {
            if let Some(job) = query.job.filter(|job| *job > 0) {
                body.push_str(&format!(
                    r#"<div class="notice success"><strong>{}</strong><span>{}</span>{}</div>"#,
                    match lang {
                        Lang::Pt => format!("Diagnóstico {job} concluído."),
                        Lang::En => format!("Diagnostics {job} finished."),
                        Lang::Es => format!("Diagnóstico {job} terminado."),
                    },
                    t(
                        "O relatório inclui trechos do journal, por isso a leitura pede a sua senha.",
                        "The report includes journal excerpts, so reading it asks for your password.",
                        "El informe incluye fragmentos del journal, por eso la lectura pide su contraseña.",
                    ),
                    actions.button(
                        t("Ver o relatório", "View the report", "Ver el informe"),
                        "diagnostics-report",
                        &[("job", &job.to_string()), ("redact", "false")]
                    )
                ));
            }
        }
        Err(error) => body.push_str(&error_body(
            t("Estado do diagnóstico indisponível", "Diagnostics status unavailable", "Estado del diagnóstico no disponible"),
            error,
        )),
    }

    match diagnostics.list_tests().await {
        Ok(tests) if !running => {
            let quick: Vec<&str> = text::QUICK_TESTS
                .iter()
                .copied()
                .filter(|id| tests.iter().any(|test| test.id == *id && test.available))
                .collect();
            body.push_str(&format!(
                r#"<div class="section-actions"><h3>{}</h3>{}</div>
<p>{}</p>"#,
                t("Executar", "Run", "Ejecutar"),
                if quick.is_empty() {
                    String::new()
                } else {
                    actions.primary(
                        t("Executar o diagnóstico rápido", "Run the quick diagnostics", "Ejecutar el diagnóstico rápido"),
                        "diagnostics-start",
                        &[("tests", &quick.join(","))],
                    )
                },
                t(
                    "O modo rápido roda pacotes, disco, logs, plataforma, segurança, boot e rede, sem carga no processador. Leva alguns minutos.",
                    "Quick mode runs packages, disk, logs, platform, security, boot and network, without processor load. It takes a few minutes.",
                    "El modo rápido ejecuta paquetes, disco, registros, plataforma, seguridad, arranque y red, sin carga en el procesador. Tarda unos minutos.",
                ),
            ));
            let rows: String = tests
                .iter()
                .map(|test| {
                    let note = if !test.available {
                        format!(
                            "{} ({})",
                            t("Indisponível", "Unavailable", "No disponible"),
                            html_escape(&test.reason)
                        )
                    } else if text::LOAD_TESTS.contains(&test.id.as_str()) {
                        t(
                            "Deixa o servidor lento por alguns minutos",
                            "Slows the server down for a few minutes",
                            "Ralentiza el servidor durante unos minutos",
                        )
                        .to_owned()
                    } else {
                        String::new()
                    };
                    let run = if test.available && test.id != "network" {
                        actions.button(
                            t("Executar", "Run", "Ejecutar"),
                            "diagnostics-start",
                            &[("tests", &test.id)],
                        )
                    } else if test.available {
                        format!(
                            r#"<a class="button-link" href="/rede/internet">{}</a>"#,
                            t("Abrir", "Open", "Abrir")
                        )
                    } else {
                        String::new()
                    };
                    format!(
                        "<tr><td>{}</td><td>~{} s</td><td>{note}</td><td>{run}</td></tr>",
                        html_escape(text::test_name(lang, &test.id)),
                        test.estimated_seconds,
                    )
                })
                .collect();
            body.push_str(&format!(
                r#"<table><thead><tr><th>{}</th><th>{}</th><th>{}</th><th></th></tr></thead><tbody>{rows}</tbody></table>"#,
                t("Teste", "Test", "Prueba"),
                t("Duração", "Duration", "Duración"),
                t("Observação", "Note", "Observación"),
            ));
        }
        Ok(_) => {}
        Err(error) => body.push_str(&error_body(
            t(
                "Lista de testes indisponível",
                "Test list unavailable",
                "Lista de pruebas no disponible",
            ),
            error,
        )),
    }

    body.push_str(&format!(
        r#"<div class="section-actions"><h3>{}</h3>{}</div><p>{}</p>"#,
        t("Relatório", "Report", "Informe"),
        actions.button(
            t(
                "Ver o último relatório",
                "View the latest report",
                "Ver el último informe"
            ),
            "diagnostics-report",
            &[("job", "0"), ("redact", "false")]
        ),
        t(
            "O último relatório, com o resultado por teste, os achados e o que fazer.",
            "The latest report, with the result per test, the findings and what to do.",
            "El último informe, con el resultado por prueba, los hallazgos y qué hacer.",
        ),
    ));

    body.push_str(&periodic_section(&state, &jar, &actions, lang).await);

    let mut response = render(
        t(
            "Diagnóstico de saúde",
            "Health diagnostics",
            "Diagnóstico de salud",
        ),
        PAGE,
        &user,
        body,
    )
    .into_response();
    if running {
        response
            .headers_mut()
            .insert("refresh", "2".parse().expect("static header"));
    }
    response
}

async fn periodic_section(
    state: &AppState,
    jar: &PrivateCookieJar,
    actions: &Actions,
    lang: Lang,
) -> String {
    let t = move |pt: &'static str, en: &'static str, es: &'static str| lang.text(pt, en, es);
    let mut section = format!(
        r#"<div class="section-actions"><h3>{}</h3></div>"#,
        t(
            "Verificação periódica",
            "Periodic check",
            "Verificación periódica"
        )
    );
    match state.dbus.diagnostics().get_periodic().await {
        Ok((enabled, frequency)) => {
            let daily = frequency == "daily";
            section.push_str(&format!(
                "<p>{} <strong>{}</strong>.</p>",
                t(
                    "Confere disco, logs, plataforma e segurança em segundo plano. Hoje:",
                    "Checks disk, logs, platform and security in the background. Now:",
                    "Revisa disco, registros, plataforma y seguridad en segundo plano. Ahora:",
                ),
                if !enabled {
                    t("desligada", "off", "desactivada")
                } else if daily {
                    t(
                        "ligada, todo dia",
                        "on, every day",
                        "activada, todos los días",
                    )
                } else {
                    t(
                        "ligada, toda semana",
                        "on, every week",
                        "activada, todas las semanas",
                    )
                }
            ));
            let mut buttons = String::new();
            for (label, on, frequency) in [
                (
                    t("Toda semana", "Every week", "Todas las semanas"),
                    "true",
                    "weekly",
                ),
                (
                    t("Todo dia", "Every day", "Todos los días"),
                    "true",
                    "daily",
                ),
                (t("Desligar", "Turn off", "Desactivar"), "false", "weekly"),
            ] {
                let current = if on == "false" {
                    !enabled
                } else {
                    enabled && daily == (frequency == "daily")
                };
                if !current {
                    buttons.push_str(&actions.button(
                        label,
                        "set-periodic",
                        &[("enabled", on), ("frequency", frequency)],
                    ));
                }
            }
            section.push_str(&format!(r#"<div class="row-actions">{buttons}</div>"#));
        }
        Err(error) => section.push_str(&error_body(
            t(
                "Verificação periódica indisponível",
                "Periodic check unavailable",
                "Verificación periódica no disponible",
            ),
            error,
        )),
    }
    match cached_read::<LastPeriodic>(state, jar, ReadQuery::LastPeriodic) {
        Some(run) if run.job == 0 => section.push_str(&format!(
            r#"<p class="empty">{}</p>"#,
            t(
                "A verificação periódica ainda não rodou nesta instalação.",
                "The periodic check has not run on this installation yet.",
                "La verificación periódica aún no se ha ejecutado en esta instalación.",
            )
        )),
        Some(run) => {
            let when = time::OffsetDateTime::from_unix_timestamp(run.finished)
                .map(|at| {
                    format!(
                        "{:02}/{:02}/{} {:02}:{:02} UTC",
                        at.day(),
                        u8::from(at.month()),
                        at.year(),
                        at.hour(),
                        at.minute()
                    )
                })
                .unwrap_or_default();
            let novelties: String = run
                .novelty_texts
                .iter()
                .map(|item| format!("<li>{}</li>", html_escape(item)))
                .collect();
            let stages: String = run
                .stages
                .iter()
                .map(|stage| {
                    format!(
                        "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                        html_escape(text::test_name(lang, &stage.id)),
                        badge(lang, &stage.verdict),
                        html_escape(&stage.summary)
                    )
                })
                .collect();
            section.push_str(&format!(
                r#"<section class="panel"><div class="panel-head"><h3>{}: {when}</h3><span class="badge {}">{} {}</span></div>{}<table><tbody>{stages}</tbody></table>{}</section>"#,
                t("Última verificação", "Last check", "Última verificación"),
                if run.novelties > 0 { "warn" } else { "on" },
                run.novelties,
                t("novidade(s)", "new item(s)", "novedad(es)"),
                if novelties.is_empty() {
                    String::new()
                } else {
                    format!("<ul>{novelties}</ul>")
                },
                actions.button(
                    t("Ver o relatório completo", "View the full report", "Ver el informe completo"),
                    "diagnostics-report",
                    &[("job", &run.job.to_string()), ("redact", "false")]
                ),
            ));
        }
        None => section.push_str(&actions.unlock(
            ReadQuery::LastPeriodic,
            t(
                "Resultado da última verificação",
                "Result of the last check",
                "Resultado de la última verificación",
            ),
        )),
    }
    section
}

/// O relatório: resultado por teste, boot, rede e os achados com o que fazer.
pub async fn report(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Extension(user): Extension<CurrentUser>,
    Path(job): Path<u32>,
) -> Response {
    let actions = Actions::new(&state, &jar, &user);
    let lang = user.lang;
    let t = move |pt: &'static str, en: &'static str, es: &'static str| lang.text(pt, en, es);
    let title = t(
        "Relatório do diagnóstico",
        "Diagnostics report",
        "Informe del diagnóstico",
    );
    let Some(report) = session_json(&state, &jar, &report_key(job, false)) else {
        let body = format!(
            r#"<div class="notice"><strong>{title} {job}</strong><span>{}</span>{}</div><p><a class="button-link" href="{PAGE}">{}</a></p>"#,
            t(
                "O relatório inclui trechos do journal. Confirme com sua senha para lê-lo; ele fica disponível por cinco minutos.",
                "The report includes journal excerpts. Confirm with your password to read it; it stays available for five minutes.",
                "El informe incluye fragmentos del journal. Confirme con su contraseña para leerlo; queda disponible durante cinco minutos.",
            ),
            actions.button(
                t("Ler o relatório", "Read the report", "Leer el informe"),
                "diagnostics-report",
                &[("job", &job.to_string()), ("redact", "false")]
            ),
            t("Voltar", "Back", "Volver"),
        );
        return render(title, PAGE, &user, body).into_response();
    };
    let remedies = state
        .dbus
        .diagnostics()
        .remedies(job)
        .await
        .unwrap_or_default();
    let csrf = csrf_token(&state, &jar, &user);
    let body = report_body(lang, job, &report, &remedies, &actions, csrf.as_deref());
    render(title, PAGE, &user, body).into_response()
}

fn report_body(
    lang: Lang,
    job: u32,
    report: &Value,
    remedies: &[DiagnosticRemedy],
    actions: &Actions,
    csrf: Option<&str>,
) -> String {
    let t = move |pt: &'static str, en: &'static str, es: &'static str| lang.text(pt, en, es);
    let host = report.get("host").cloned().unwrap_or(Value::Null);
    let mut body = format!(
        r#"<p>{} {job} · {} · {} · vegad {}</p>"#,
        t("Diagnóstico", "Diagnostics", "Diagnóstico"),
        html_escape(str_of(report, "started")),
        html_escape(str_of(&host, "os")),
        html_escape(str_of(&host, "vegad")),
    );
    let rows: String = stages(report)
        .iter()
        .map(|stage| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(text::test_name(lang, str_of(stage, "id"))),
                badge(lang, str_of(stage, "verdict")),
                html_escape(str_of(stage, "summary"))
            )
        })
        .collect();
    body.push_str(&format!(
        r#"<table><thead><tr><th>{}</th><th>{}</th><th>{}</th></tr></thead><tbody>{rows}</tbody></table>"#,
        t("Teste", "Test", "Prueba"),
        t("Resultado", "Result", "Resultado"),
        t("Resumo", "Summary", "Resumen"),
    ));
    if let Some(boot) = stages(report)
        .into_iter()
        .rfind(|stage| str_of(stage, "id") == "boot")
    {
        body.push_str(&boot_view(lang, boot));
    }
    if let Some(network) = stages(report)
        .into_iter()
        .rfind(|stage| str_of(stage, "id") == "network")
    {
        body.push_str(&network_steps(lang, network));
    }

    let mut attention = String::new();
    let mut info = String::new();
    for stage in stages(report) {
        let stage_id = str_of(stage, "id");
        for finding in findings(stage) {
            let severity = str_of(finding, "severity");
            let line = finding_view(lang, stage_id, finding);
            if severity == "attention" || severity == "fail" {
                attention.push_str(&line);
            } else {
                info.push_str(&line);
            }
        }
    }
    body.push_str(&format!(
        r#"<div class="section-actions"><h3>{}</h3></div>"#,
        t("Precisa de atenção", "Needs attention", "Requiere atención")
    ));
    if attention.is_empty() {
        body.push_str(&format!(
            r#"<p class="notice success">{}</p>"#,
            t(
                "Nenhum problema encontrado.",
                "No problems found.",
                "No se encontraron problemas."
            )
        ));
    } else {
        body.push_str(&attention);
    }
    if !info.is_empty() {
        body.push_str(&format!(
            "<details><summary>{}</summary>{info}</details>",
            t("Informações", "Information", "Información")
        ));
    }

    if let (false, Some(csrf)) = (remedies.is_empty(), csrf) {
        let items: String = remedies
            .iter()
            .map(|remedy| {
                let finding = stages(report)
                    .into_iter()
                    .find(|stage| str_of(stage, "id") == remedy.stage)
                    .and_then(|stage| findings(stage).get(remedy.finding_index as usize).copied());
                let label = finding
                    .map(|finding| str_of(finding, "text").to_owned())
                    .filter(|label| !label.is_empty())
                    .unwrap_or_else(|| text::remedy_text(lang, &remedy.remedy, &[]));
                format!(
                    r#"<label class="check"><input type="checkbox" name="finding" value="{}:{}" checked> {}: {}</label>"#,
                    html_escape(&remedy.stage),
                    remedy.finding_index,
                    html_escape(text::test_name(lang, &remedy.stage)),
                    html_escape(&label),
                )
            })
            .collect();
        body.push_str(&format!(
            r#"<div class="section-actions"><h3>{}</h3></div>
<p>{}</p>
<form method="post" action="{PAGE}/corrigir"><input type="hidden" name="csrf" value="{}"><input type="hidden" name="job" value="{job}">{items}<button type="submit" class="primary">{}</button></form>"#,
            t("Corrigir achados", "Fix findings", "Corregir hallazgos"),
            t(
                "Marque o que o Vega deve consertar. Antes, um snapshot permite desfazer; depois, os testes afetados rodam de novo.",
                "Check what Vega should fix. A snapshot is taken first so it can be undone; afterwards, the affected tests run again.",
                "Marque lo que Vega debe arreglar. Antes, una instantánea permite deshacer; después, las pruebas afectadas se ejecutan de nuevo.",
            ),
            html_escape(csrf),
            t("Corrigir os marcados", "Fix the checked ones", "Corregir los marcados"),
        ));
    }

    let logs = stages(report)
        .into_iter()
        .any(|stage| str_of(stage, "id") == "logs" && !findings(stage).is_empty());
    let mut more = String::new();
    if logs {
        more.push_str(&actions.button(
            t(
                "Já vi os logs",
                "I have seen the logs",
                "Ya vi los registros",
            ),
            "mark-logs-seen",
            &[("job", &job.to_string())],
        ));
    }
    more.push_str(&actions.button(
        t("Pedir ajuda", "Ask for help", "Pedir ayuda"),
        "diagnostics-report",
        &[("job", &job.to_string()), ("redact", "true")],
    ));
    body.push_str(&format!(
        r#"<div class="section-actions"><h3>{}</h3></div>
<p>{}</p>
<div class="row-actions">{more}</div><p><a class="button-link" href="{PAGE}">{}</a></p>"#,
        t("Mais", "More", "Más"),
        t(
            r#""Já vi os logs" faz os erros registrados até este diagnóstico deixarem de contar; o que acontecer depois volta a aparecer. "Pedir ajuda" monta um texto <strong>redigido</strong> para as Discussions ou para uma issue."#,
            r#""I have seen the logs" stops counting the errors logged up to this diagnostics run; what happens afterwards shows up again. "Ask for help" builds a <strong>redacted</strong> text for the Discussions or for an issue."#,
            r#""Ya vi los registros" hace que los errores registrados hasta este diagnóstico dejen de contar; lo que ocurra después vuelve a aparecer. "Pedir ayuda" arma un texto <strong>redactado</strong> para las Discussions o para una issue."#,
        ),
        t("Voltar", "Back", "Volver"),
    ));
    body
}

fn finding_view(lang: Lang, stage: &str, finding: &Value) -> String {
    let t = move |pt: &'static str, en: &'static str, es: &'static str| lang.text(pt, en, es);
    let severity = str_of(finding, "severity");
    let level = match severity {
        "fail" => "error",
        "attention" => "warn",
        _ => "",
    };
    let remedy = str_of(finding, "remedy");
    let guide = if !remedy.is_empty() {
        let args: Vec<String> = finding
            .get("remedyArgs")
            .and_then(Value::as_array)
            .map(|args| {
                args.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        format!(
            "<span>{}: {}</span>",
            t("Conserto disponível", "Fix available", "Arreglo disponible"),
            html_escape(&text::remedy_text(lang, remedy, &args))
        )
    } else {
        match text::guide(lang, str_of(finding, "code"), severity) {
            Some((guide, Some((href, label)))) => format!(
                r#"<span>{} <a href="{href}">{}</a></span>"#,
                html_escape(guide),
                html_escape(label)
            ),
            Some((guide, None)) => format!("<span>{}</span>", html_escape(guide)),
            None => String::new(),
        }
    };
    let raw = str_of(finding, "raw").trim();
    let raw = if raw.is_empty() {
        String::new()
    } else {
        format!(
            "<details><summary>{}</summary><pre><code>{}</code></pre></details>",
            t("Dados brutos", "Raw data", "Datos en bruto"),
            html_escape(raw)
        )
    };
    format!(
        r#"<div class="notice {level}"><strong>{}: {}</strong>{guide}{raw}</div>"#,
        html_escape(text::test_name(lang, stage)),
        html_escape(str_of(finding, "text")),
    )
}

/// As fases do último boot e o que mais demorou antes do login.
fn boot_view(lang: Lang, stage: &Value) -> String {
    let t = move |pt: &'static str, en: &'static str, es: &'static str| lang.text(pt, en, es);
    let metrics = stage.get("metrics").cloned().unwrap_or(Value::Null);
    let Some(phases) = metrics.get("phases") else {
        return String::new();
    };
    let present: Vec<(&str, f64)> = text::BOOT_PHASES
        .iter()
        .filter_map(|(id, label)| {
            let value = phases.get(*id).and_then(Value::as_f64).unwrap_or(0.0);
            (value > 0.0).then_some((text::tr(lang, label), value))
        })
        .collect();
    let total = metrics
        .get("totalSeconds")
        .and_then(Value::as_f64)
        .unwrap_or_else(|| present.iter().map(|(_, value)| value).sum());
    let phases: String = present
        .iter()
        .map(|(label, value)| {
            format!(
                "<tr><td>{label}</td><td>{}</td></tr>",
                seconds(lang, *value)
            )
        })
        .collect();
    let slowest: String = metrics
        .get("slowest")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|unit| {
            format!(
                "<tr><td><code>{}</code></td><td>{}</td></tr>",
                html_escape(str_of(unit, "unit")),
                seconds(
                    lang,
                    unit.get("seconds").and_then(Value::as_f64).unwrap_or(0.0)
                )
            )
        })
        .collect();
    format!(
        r#"<section class="panel"><div class="panel-head"><h3>{}</h3><span class="badge">{}</span></div><table><tbody>{phases}</tbody></table>{}</section>"#,
        t("Último boot", "Last boot", "Último arranque"),
        seconds(lang, total),
        if slowest.is_empty() {
            String::new()
        } else {
            format!(
                "<h4>{}</h4><table><tbody>{slowest}</tbody></table>",
                t(
                    "O que mais demorou antes do login",
                    "What took longest before login",
                    "Lo que más tardó antes del inicio de sesión",
                )
            )
        }
    )
}

/// Os passos do teste de rede, do cabo até a internet.
fn network_steps(lang: Lang, stage: &Value) -> String {
    let rows: String = stage
        .get("metrics")
        .and_then(|metrics| metrics.get("steps"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|step| {
            let status = str_of(step, "status");
            let class = match status {
                "ok" => "on",
                "fail" | "warn" => "warn",
                _ => "",
            };
            format!(
                r#"<tr><td>{}</td><td><span class="badge {class}">{}</span></td><td>{}</td></tr>"#,
                html_escape(text::network_step_name(lang, str_of(step, "id"))),
                html_escape(text::network_step_status(lang, status)),
                html_escape(str_of(step, "detail")),
            )
        })
        .collect();
    if rows.is_empty() {
        return String::new();
    }
    format!(
        r#"<section class="panel"><div class="panel-head"><h3>{}</h3>{}</div><table><tbody>{rows}</tbody></table></section>"#,
        lang.text(
            "Rede, passo a passo",
            "Network, step by step",
            "Red, paso a paso"
        ),
        badge(lang, str_of(stage, "verdict"))
    )
}

/// The checkboxes of "Corrigir achados" become one confirmation, the same
/// step every other administrative action goes through.
pub async fn fix(
    state: State<AppState>,
    jar: PrivateCookieJar,
    user: Extension<CurrentUser>,
    RawForm(body): RawForm,
) -> Response {
    let Ok(fields) = serde_urlencoded::from_bytes::<Vec<(String, String)>>(&body) else {
        return (StatusCode::BAD_REQUEST, "Formulário inválido.").into_response();
    };
    let mut csrf = None;
    let mut job = None;
    let mut chosen = Vec::new();
    for (name, value) in fields {
        match name.as_str() {
            "csrf" if csrf.is_none() => csrf = Some(value),
            "job" if job.is_none() => job = Some(value),
            "finding" => chosen.push(value),
            _ => return (StatusCode::BAD_REQUEST, "Formulário inválido.").into_response(),
        }
    }
    let (Some(csrf), Some(job)) = (csrf, job) else {
        return (StatusCode::BAD_REQUEST, "Formulário inválido.").into_response();
    };
    if chosen.is_empty() {
        return Redirect::to(&format!("{PAGE}/relatorio/{job}")).into_response();
    }
    let form = ActionForm::built(
        "repair-findings",
        &csrf,
        &[("job", job), ("findings", chosen.join(","))],
    );
    super::admin::confirm(state, jar, user, Form(form)).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelpForm {
    csrf: String,
    descricao: String,
}

pub async fn help_form(
    state: State<AppState>,
    jar: PrivateCookieJar,
    user: Extension<CurrentUser>,
    job: Path<u32>,
) -> Response {
    help(state, jar, user, job, None).await
}

pub async fn help_text_post(
    state: State<AppState>,
    jar: PrivateCookieJar,
    user: Extension<CurrentUser>,
    job: Path<u32>,
    Form(form): Form<HelpForm>,
) -> Response {
    help(state, jar, user, job, Some(form)).await
}

/// Pedir ajuda: o texto redigido, a descrição e os links já preenchidos.
async fn help(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Extension(user): Extension<CurrentUser>,
    Path(job): Path<u32>,
    form: Option<HelpForm>,
) -> Response {
    let actions = Actions::new(&state, &jar, &user);
    let lang = user.lang;
    let t = move |pt: &'static str, en: &'static str, es: &'static str| lang.text(pt, en, es);
    let page_title = t("Pedir ajuda", "Ask for help", "Pedir ayuda");
    let Some(report) = session_json(&state, &jar, &report_key(job, true)) else {
        let body = format!(
            r#"<div class="notice"><strong>{page_title}</strong><span>{}</span>{}</div>"#,
            match lang {
                Lang::Pt => format!(
                    "O texto sai do relatório <strong>redigido</strong> do diagnóstico {job}: sem nome do computador, usuários, endereços e caminhos pessoais. Confirme com sua senha para lê-lo."
                ),
                Lang::En => format!(
                    "The text comes from the <strong>redacted</strong> report of diagnostics {job}: no computer name, users, addresses or personal paths. Confirm with your password to read it."
                ),
                Lang::Es => format!(
                    "El texto sale del informe <strong>redactado</strong> del diagnóstico {job}: sin nombre del equipo, usuarios, direcciones ni rutas personales. Confirme con su contraseña para leerlo."
                ),
            },
            actions.button(
                t(
                    "Ler o relatório redigido",
                    "Read the redacted report",
                    "Leer el informe redactado"
                ),
                "diagnostics-report",
                &[("job", &job.to_string()), ("redact", "true")]
            )
        );
        return render(page_title, PAGE, &user, body).into_response();
    };
    let Some(csrf) = csrf_token(&state, &jar, &user) else {
        return Redirect::to("/login").into_response();
    };
    let description = match &form {
        Some(form) => {
            if !super::admin::matching_csrf(&csrf, &form.csrf) {
                return (
                    StatusCode::FORBIDDEN,
                    t(
                        "Confirmação de sessão inválida.",
                        "Invalid session confirmation.",
                        "Confirmación de sesión no válida.",
                    ),
                )
                    .into_response();
            }
            form.descricao.chars().take(2000).collect::<String>()
        }
        None => String::new(),
    };
    let help = help_text::build(
        lang,
        &report,
        &description,
        env!("CARGO_PKG_VERSION"),
        help_text::HELP_LIMIT,
    );
    let title = {
        let first = description.lines().next().unwrap_or("").trim();
        if first.is_empty() {
            t(
                "Ajuda com o Lyra OS Server",
                "Help with Lyra OS Server",
                "Ayuda con Lyra OS Server",
            )
            .to_owned()
        } else {
            format!(
                "{}: {}",
                t("Ajuda", "Help", "Ayuda"),
                help_text::cut(first, 80)
            )
        }
    };
    let links = if form.is_some() {
        format!(
            r#"<div class="row-actions"><a class="button primary" href="{}" target="_blank" rel="noopener noreferrer">{}</a><a class="button" href="{}" target="_blank" rel="noopener noreferrer">{}</a></div>
<p class="empty">{}</p>"#,
            html_escape(&help_text::url(lang, false, &title, &help)),
            t(
                "Perguntar nas Discussions",
                "Ask in the Discussions",
                "Preguntar en las Discussions"
            ),
            html_escape(&help_text::url(lang, true, &title, &help)),
            t("Abrir uma issue", "Open an issue", "Abrir una issue"),
            t(
                "Os links abrem o GitHub com o texto preenchido. Se o texto for longo, ele vai encurtado no link; copie o texto completo daqui.",
                "The links open GitHub with the text filled in. If the text is long, the link carries a shortened version; copy the full text from here.",
                "Los enlaces abren GitHub con el texto completado. Si el texto es largo, el enlace lleva una versión acortada; copie el texto completo desde aquí.",
            ),
        )
    } else {
        String::new()
    };
    let body = format!(
        r#"<p>{}</p>
<form method="post" action="{PAGE}/ajuda/{job}"><input type="hidden" name="csrf" value="{}">
<label>{}<br><textarea name="descricao" rows="4" maxlength="2000" required>{}</textarea></label>
<button type="submit" class="primary">{}</button></form>
{links}
<h3>{}</h3><pre class="help-text"><code>{}</code></pre>
<p><a class="button-link" href="{PAGE}/relatorio/{job}">{}</a></p>"#,
        match lang {
            Lang::Pt => format!(
                "Descreva o problema. O texto abaixo junta a sua descrição e o relatório <strong>redigido</strong> do diagnóstico {job}; confira antes de enviar."
            ),
            Lang::En => format!(
                "Describe the problem. The text below joins your description and the <strong>redacted</strong> report of diagnostics {job}; check it before sending."
            ),
            Lang::Es => format!(
                "Describa el problema. El texto de abajo une su descripción y el informe <strong>redactado</strong> del diagnóstico {job}; revíselo antes de enviarlo."
            ),
        },
        html_escape(&csrf),
        t(
            "O que está acontecendo",
            "What is happening",
            "Qué está pasando"
        ),
        html_escape(&description),
        t("Montar o texto", "Build the text", "Armar el texto"),
        t("Texto", "Text", "Texto"),
        html_escape(&help),
        t(
            "Voltar ao relatório",
            "Back to the report",
            "Volver al informe"
        ),
    );
    render(page_title, PAGE, &user, body).into_response()
}

/// Rede e Firewall → Minha internet não funciona.
pub async fn network(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    let actions = Actions::new(&state, &jar, &user);
    let lang = user.lang;
    let t = move |pt: &'static str, en: &'static str, es: &'static str| lang.text(pt, en, es);
    let page_title = t(
        "Minha internet não funciona",
        "My internet does not work",
        "Mi internet no funciona",
    );
    let mut body = format!(
        "<p>{}</p>",
        t(
            "Testa a conexão passo a passo, do cabo ou Wi-Fi até a internet, e aponta onde está o problema. Não muda nada sem a sua confirmação.",
            "Tests the connection step by step, from the cable or Wi-Fi to the internet, and points out where the problem is. It changes nothing without your confirmation.",
            "Prueba la conexión paso a paso, del cable o Wi-Fi hasta internet, e indica dónde está el problema. No cambia nada sin su confirmación.",
        )
    );
    body.push_str(&actions.notice());
    let check = session_json(&state, &jar, "network")
        .and_then(|value| serde_json::from_value::<NetworkCheck>(value).ok());
    match check {
        Some(check) => {
            let report: Value = serde_json::from_str(&check.report).unwrap_or(Value::Null);
            let network = stages(&report)
                .into_iter()
                .rfind(|stage| str_of(stage, "id") == "network");
            match network {
                Some(stage) => {
                    body.push_str(&network_steps(lang, stage));
                    if str_of(stage, "verdict") == "ok" {
                        body.push_str(&format!(
                            r#"<p class="notice success">{}</p>"#,
                            t(
                                "A conexão está funcionando.",
                                "The connection is working.",
                                "La conexión funciona."
                            )
                        ));
                    }
                    for finding in findings(stage) {
                        if str_of(finding, "severity") != "info" {
                            body.push_str(&finding_view(lang, "network", finding));
                        }
                    }
                    let remedies = state
                        .dbus
                        .diagnostics()
                        .remedies(check.job)
                        .await
                        .unwrap_or_default();
                    if !remedies.is_empty() {
                        let findings = remedies
                            .iter()
                            .map(|remedy| format!("{}:{}", remedy.stage, remedy.finding_index))
                            .collect::<Vec<_>>()
                            .join(",");
                        let label = remedies
                            .iter()
                            .map(|remedy| text::remedy_text(lang, &remedy.remedy, &[]))
                            .collect::<Vec<_>>()
                            .join("; ");
                        body.push_str(&format!(
                            r#"<div class="notice"><strong>{}</strong><span>{}</span>{}</div>"#,
                            t("Conserto disponível", "Fix available", "Arreglo disponible"),
                            html_escape(&label),
                            actions.primary(
                                t("Aplicar o conserto", "Apply the fix", "Aplicar el arreglo"),
                                "repair-findings",
                                &[("job", &check.job.to_string()), ("findings", &findings)]
                            )
                        ));
                    }
                }
                None => body.push_str(&format!(
                    r#"<p class="notice warn">{}</p>"#,
                    t(
                        "O teste de rede não rodou.",
                        "The network test did not run.",
                        "La prueba de red no se ejecutó."
                    )
                )),
            }
            body.push_str(&actions.button(
                t("Testar de novo", "Test again", "Probar de nuevo"),
                "network-check",
                &[],
            ));
        }
        None => body.push_str(&format!(
            r#"<div class="notice"><strong>{page_title}</strong><span>{}</span>{}</div>"#,
            t(
                "Leva poucos segundos. Confirme com sua senha.",
                "It takes a few seconds. Confirm with your password.",
                "Tarda unos segundos. Confirme con su contraseña.",
            ),
            actions.primary(
                t(
                    "Testar a conexão",
                    "Test the connection",
                    "Probar la conexión"
                ),
                "network-check",
                &[]
            )
        )),
    }
    body.push_str(&format!(
        r#"<p><a class="button-link" href="/rede">{}</a></p>"#,
        t("Voltar para Rede", "Back to Network", "Volver a Red")
    ));
    render(page_title, "/rede", &user, body).into_response()
}

/// Armazenamento → Liberar espaço: as categorias do sistema medidas pelo
/// broker, para o `storage.rs` montar a seção.
pub(crate) fn cleanup_section(
    state: &AppState,
    jar: &PrivateCookieJar,
    user: &CurrentUser,
) -> String {
    let actions = Actions::new(state, jar, user);
    let lang = user.lang;
    let t = move |pt: &'static str, en: &'static str, es: &'static str| lang.text(pt, en, es);
    let free_up = t("Liberar espaço", "Free up space", "Liberar espacio");
    let mut section = format!(
        r#"<div class="section-actions" id="liberar"><h3>{free_up}</h3></div><p>{}</p>"#,
        t(
            "Apaga relatórios de falha, logs antigos, pacotes baixados e outros itens do sistema que podem sair com segurança.",
            "Deletes crash reports, old logs, downloaded packages and other system items that can safely go.",
            "Borra informes de fallos, registros antiguos, paquetes descargados y otros elementos del sistema que pueden eliminarse con seguridad.",
        )
    );
    let Some(scan) = cached_read::<CleanupScan>(state, jar, ReadQuery::CleanupScan) else {
        section.push_str(&actions.unlock(
            ReadQuery::CleanupScan,
            t(
                "Medir o espaço que pode ser liberado",
                "Measure the space that can be freed",
                "Medir el espacio que se puede liberar",
            ),
        ));
        return section;
    };
    let Some(csrf) = csrf_token(state, jar, user) else {
        return section;
    };
    let mut items = String::new();
    let mut blocked = String::new();
    for category in &scan.categories {
        let size = if category.size_unknown {
            let count = category.count.unwrap_or(0);
            match lang {
                Lang::Pt => format!("pelo menos {count}, tamanho desconhecido"),
                Lang::En => format!("at least {count}, unknown size"),
                Lang::Es => format!("al menos {count}, tamaño desconocido"),
            }
        } else {
            text::bytes(lang, category.bytes)
        };
        if category.can_clean {
            items.push_str(&format!(
                r#"<label class="check"><input type="checkbox" name="category" value="{}"{}> {} — {}</label>"#,
                html_escape(&category.id),
                if text::cleanup_default_on(&category.id) { " checked" } else { "" },
                html_escape(text::cleanup_name(lang, &category.id)),
                html_escape(&size),
            ));
        } else {
            blocked.push_str(&format!(
                "<li>{}: {}</li>",
                html_escape(text::cleanup_name(lang, &category.id)),
                html_escape(&text::cleanup_reason(
                    lang,
                    category.reason.as_deref().unwrap_or("nothing")
                ))
            ));
        }
    }
    if items.is_empty() {
        section.push_str(&format!(
            r#"<p class="notice success">{}</p>"#,
            t(
                "Nada para limpar agora.",
                "Nothing to clean right now.",
                "Nada que limpiar ahora."
            )
        ));
    } else {
        section.push_str(&format!(
            r#"<form method="post" action="/armazenamento/limpar"><input type="hidden" name="csrf" value="{}">{items}<p class="empty">{}</p><button type="submit" class="primary">{free_up}</button></form>"#,
            html_escape(&csrf),
            t(
                "Kernels antigos e snapshots só saem se você marcar. Não dá para desfazer.",
                "Old kernels and snapshots only go if you check them. This cannot be undone.",
                "Los núcleos antiguos y las instantáneas solo se eliminan si los marca. No se puede deshacer.",
            ),
        ));
    }
    if !blocked.is_empty() {
        section.push_str(&format!(
            "<details><summary>{}</summary><ul>{blocked}</ul></details>",
            t(
                "Sem limpeza agora",
                "No cleanup right now",
                "Sin limpieza ahora"
            )
        ));
    }
    section
}

/// The cleanup checkboxes become one confirmation.
pub async fn clean(
    state: State<AppState>,
    jar: PrivateCookieJar,
    user: Extension<CurrentUser>,
    RawForm(body): RawForm,
) -> Response {
    let Ok(fields) = serde_urlencoded::from_bytes::<Vec<(String, String)>>(&body) else {
        return (StatusCode::BAD_REQUEST, "Formulário inválido.").into_response();
    };
    let mut csrf = None;
    let mut chosen = Vec::new();
    for (name, value) in fields {
        match name.as_str() {
            "csrf" if csrf.is_none() => csrf = Some(value),
            "category" => chosen.push(value),
            _ => return (StatusCode::BAD_REQUEST, "Formulário inválido.").into_response(),
        }
    }
    let Some(csrf) = csrf else {
        return (StatusCode::BAD_REQUEST, "Formulário inválido.").into_response();
    };
    if chosen.is_empty() {
        return Redirect::to("/armazenamento#liberar").into_response();
    }
    let form = ActionForm::built("cleanup-clean", &csrf, &[("categories", chosen.join(","))]);
    super::admin::confirm(state, jar, user, Form(form)).await
}

// ---------- Acompanhamento da limpeza ----------

#[derive(Clone)]
struct CleanupJob {
    binding: [u8; 32],
    created: Instant,
    job: u32,
    running: bool,
    result: String,
    freed: u64,
    categories: Vec<(String, String, u64)>,
}

#[derive(Clone, Default)]
pub struct CleanupJobs(Arc<Mutex<HashMap<String, CleanupJob>>>);

impl CleanupJobs {
    fn reserve(&self, binding: [u8; 32]) -> Result<String, String> {
        let mut jobs = self.0.lock().unwrap();
        jobs.retain(|_, job| job.created.elapsed() < Duration::from_secs(3 * 60 * 60));
        if jobs.len() >= 64 || jobs.values().any(|job| job.running) {
            return Err("Já há uma limpeza em andamento pelo painel. Aguarde o fim dela.".into());
        }
        let mut random = [0u8; 16];
        rand::rng().fill(&mut random);
        let id: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        jobs.insert(
            id.clone(),
            CleanupJob {
                binding,
                created: Instant::now(),
                job: 0,
                running: true,
                result: String::new(),
                freed: 0,
                categories: Vec::new(),
            },
        );
        Ok(id)
    }

    fn update(&self, id: &str, apply: impl FnOnce(&mut CleanupJob)) {
        if let Some(job) = self.0.lock().unwrap().get_mut(id) {
            apply(job);
        }
    }
}

pub struct PreparedCleanup {
    jobs: CleanupJobs,
    id: Option<String>,
    events: Option<CleanupEventStream>,
}

impl Drop for PreparedCleanup {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            self.jobs.0.lock().unwrap().remove(&id);
        }
    }
}

/// Subscribe before PAM/Polkit: a small cleanup may finish before the
/// broker answers.
pub(crate) async fn prepare_cleanup(
    state: &AppState,
    binding: [u8; 32],
) -> Result<PreparedCleanup, String> {
    let id = state.cleanup_jobs.reserve(binding)?;
    let mut pending = PreparedCleanup {
        jobs: state.cleanup_jobs.clone(),
        id: Some(id),
        events: None,
    };
    pending.events = Some(
        state
            .dbus
            .cleanup()
            .subscribe()
            .await
            .map_err(|error| format!("{error:?}"))?,
    );
    Ok(pending)
}

impl PreparedCleanup {
    pub fn accepted(mut self, job: u32, mut lease: SessionLease) -> Response {
        let id = self.id.take().expect("prepared cleanup");
        let mut events = self.events.take().expect("prepared observer");
        let jobs = self.jobs.clone();
        jobs.update(&id, |entry| entry.job = job);
        let url = format!("/armazenamento/limpeza/{id}");
        tokio::spawn(async move {
            let finish = |result: &str| {
                let result = result.to_owned();
                jobs.update(&id, |entry| {
                    entry.running = false;
                    entry.result = result;
                })
            };
            loop {
                let event = tokio::select! {
                    biased;
                    _ = lease.revoked() => { finish("unconfirmed"); return },
                    event = tokio::time::timeout(Duration::from_secs(30 * 60), events.next()) => event,
                };
                match event {
                    Ok(Ok(CleanupEvent::CategoryFinished(done))) if done.job_id == job => jobs
                        .update(&id, |entry| {
                            entry
                                .categories
                                .push((done.id, done.result, done.freed_bytes))
                        }),
                    Ok(Ok(CleanupEvent::Finished(done))) if done.job_id == job => {
                        jobs.update(&id, |entry| {
                            entry.freed = done.freed_bytes;
                            entry.running = false;
                            entry.result = done.result;
                        });
                        return;
                    }
                    Ok(Ok(_)) => {}
                    Ok(Err(_)) | Err(_) => {
                        finish("unconfirmed");
                        return;
                    }
                }
            }
        });
        Redirect::to(&url).into_response()
    }
}

pub async fn cleanup_progress(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Response {
    let Some(lease) = jar
        .get(SESSION_COOKIE)
        .and_then(|cookie| state.sessions.lease(cookie.value(), Instant::now()))
    else {
        return Redirect::to("/login").into_response();
    };
    let job = state
        .cleanup_jobs
        .0
        .lock()
        .unwrap()
        .get(&id)
        .filter(|job| job.binding == lease.admin_binding && lease.username == user.name)
        .cloned();
    let Some(job) = job else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let lang = user.lang;
    let t = move |pt: &'static str, en: &'static str, es: &'static str| lang.text(pt, en, es);
    let rows: String = job
        .categories
        .iter()
        .map(|(id, result, freed)| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(text::cleanup_name(lang, id)),
                match result.as_str() {
                    "ok" => t("Limpo", "Cleaned", "Limpio"),
                    "skipped" => t("Pulado", "Skipped", "Omitido"),
                    "failed" => t("Falhou", "Failed", "Falló"),
                    other => other,
                },
                text::bytes(lang, *freed)
            )
        })
        .collect();
    let headline = if job.running {
        format!(
            r#"<p class="notice">{}</p>"#,
            t(
                "Limpando… a página se atualiza sozinha.",
                "Cleaning… the page refreshes by itself.",
                "Limpiando… la página se actualiza sola.",
            )
        )
    } else {
        let freed = t("liberados", "freed", "liberados");
        match job.result.as_str() {
            "ok" => format!(
                r#"<p class="notice success"><strong>{} {freed}.</strong></p>"#,
                text::bytes(lang, job.freed)
            ),
            "partial" => format!(
                r#"<p class="notice warn"><strong>{} {freed}.</strong> {}</p>"#,
                text::bytes(lang, job.freed),
                t(
                    "Algumas categorias não puderam ser limpas; veja o log do vegad.",
                    "Some categories could not be cleaned; see the vegad log.",
                    "Algunas categorías no se pudieron limpiar; vea el registro de vegad.",
                )
            ),
            "failed" => format!(
                r#"<p class="notice error">{}</p>"#,
                t(
                    "A limpeza falhou; veja o log do vegad.",
                    "The cleanup failed; see the vegad log.",
                    "La limpieza falló; vea el registro de vegad.",
                )
            ),
            _ => format!(
                r#"<p class="notice warn">{}</p>"#,
                t(
                    "Resultado não confirmado. Meça de novo antes de repetir.",
                    "Result not confirmed. Measure again before repeating.",
                    "Resultado no confirmado. Mida de nuevo antes de repetir.",
                )
            ),
        }
    };
    let body = format!(
        r#"{headline}<p>{} {}</p>{}<p><a class="button-link" href="/armazenamento#liberar">{}</a></p>"#,
        t("Limpeza", "Cleanup", "Limpieza"),
        job.job,
        if rows.is_empty() {
            String::new()
        } else {
            format!("<table><tbody>{rows}</tbody></table>")
        },
        t(
            "Voltar para Armazenamento",
            "Back to Storage",
            "Volver a Almacenamiento"
        ),
    );
    let mut response = render(
        t("Liberar espaço", "Free up space", "Liberar espacio"),
        "/armazenamento",
        &user,
        body,
    )
    .into_response();
    if job.running {
        response
            .headers_mut()
            .insert("refresh", "2".parse().expect("static header"));
    }
    response
}

/// The dashboard tile: the periodic check state, without a password.
pub(crate) async fn dashboard_row(state: &AppState) -> Option<(String, String)> {
    let (enabled, frequency) = state.dbus.diagnostics().get_periodic().await.ok()?;
    let value = if !enabled {
        "desligada".to_owned()
    } else if frequency == "daily" {
        "ligada, todo dia".to_owned()
    } else {
        "ligada, toda semana".to_owned()
    };
    Some((
        if enabled { "" } else { "warn" }.to_owned(),
        format!(r#"{value} <a href="{PAGE}">Diagnóstico</a>"#),
    ))
}
