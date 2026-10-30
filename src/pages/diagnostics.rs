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

fn badge(verdict: &str) -> String {
    let class = match verdict {
        "ok" => "on",
        "attention" | "fail" => "warn",
        _ => "",
    };
    format!(
        r#"<span class="badge {class}">{}</span>"#,
        html_escape(text::verdict_label(verdict))
    )
}

fn seconds(value: f64) -> String {
    format!("{value:.1} s").replace('.', ",")
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
        Operation::MarkLogsSeen(_) => Some(
            render(
                "Já vi os logs",
                PAGE,
                user,
                format!(
                    r#"<p class="notice success">Pronto. O próximo teste de logs só conta o que acontecer daqui em diante.</p><p><a class="button-link" href="{PAGE}">Voltar</a></p>"#
                ),
            )
            .into_response(),
        ),
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
    let diagnostics = state.dbus.diagnostics();
    let mut body = String::from(
        r#"<p>Testa disco, sistema, segurança, rede e boot sem alterar nada. As ações pedem a sua senha.</p>"#,
    );
    body.push_str(&actions.notice());
    let current = diagnostics.current().await;
    let running = matches!(&current, Ok(job) if job.job_id != 0);
    match &current {
        Ok(job) if job.job_id != 0 => body.push_str(&format!(
            r#"<section class="panel"><div class="panel-head"><h3>Diagnóstico {} em andamento</h3><span class="badge">{}%</span></div>
<p>Testando: <strong>{}</strong></p>
<div class="bar-track"><div class="bar-value bar-accent" style="width: {}%"></div></div>
<p class="empty">A página se atualiza sozinha.</p></section>"#,
            job.job_id,
            job.percent.min(100),
            html_escape(text::test_name(&job.stage)),
            job.percent.min(100),
        )),
        Ok(_) => {
            if let Some(job) = query.job.filter(|job| *job > 0) {
                body.push_str(&format!(
                    r#"<div class="notice success"><strong>Diagnóstico {job} concluído.</strong><span>O relatório inclui trechos do journal, por isso a leitura pede a sua senha.</span>{}</div>"#,
                    actions.button(
                        "Ver o relatório",
                        "diagnostics-report",
                        &[("job", &job.to_string()), ("redact", "false")]
                    )
                ));
            }
        }
        Err(error) => body.push_str(&error_body("Estado do diagnóstico indisponível", error)),
    }

    match diagnostics.list_tests().await {
        Ok(tests) if !running => {
            let quick: Vec<&str> = text::QUICK_TESTS
                .iter()
                .copied()
                .filter(|id| tests.iter().any(|test| test.id == *id && test.available))
                .collect();
            body.push_str(&format!(
                r#"<div class="section-actions"><h3>Executar</h3>{}</div>
<p>O modo rápido roda pacotes, disco, logs, plataforma, segurança, boot e rede, sem carga no processador. Leva alguns minutos.</p>"#,
                if quick.is_empty() {
                    String::new()
                } else {
                    actions.primary(
                        "Executar o diagnóstico rápido",
                        "diagnostics-start",
                        &[("tests", &quick.join(","))],
                    )
                }
            ));
            let rows: String = tests
                .iter()
                .map(|test| {
                    let note = if !test.available {
                        format!("Indisponível ({})", html_escape(&test.reason))
                    } else if text::LOAD_TESTS.contains(&test.id.as_str()) {
                        "Deixa o servidor lento por alguns minutos".to_owned()
                    } else {
                        String::new()
                    };
                    let run = if test.available && test.id != "network" {
                        actions.button("Executar", "diagnostics-start", &[("tests", &test.id)])
                    } else if test.available {
                        r#"<a class="button-link" href="/rede/internet">Abrir</a>"#.to_owned()
                    } else {
                        String::new()
                    };
                    format!(
                        "<tr><td>{}</td><td>~{} s</td><td>{note}</td><td>{run}</td></tr>",
                        html_escape(text::test_name(&test.id)),
                        test.estimated_seconds,
                    )
                })
                .collect();
            body.push_str(&format!(
                r#"<table><thead><tr><th>Teste</th><th>Duração</th><th>Observação</th><th></th></tr></thead><tbody>{rows}</tbody></table>"#
            ));
        }
        Ok(_) => {}
        Err(error) => body.push_str(&error_body("Lista de testes indisponível", error)),
    }

    body.push_str(&format!(
        r#"<div class="section-actions"><h3>Relatório</h3>{}</div><p>O último relatório, com o resultado por teste, os achados e o que fazer.</p>"#,
        actions.button(
            "Ver o último relatório",
            "diagnostics-report",
            &[("job", "0"), ("redact", "false")]
        )
    ));

    body.push_str(&periodic_section(&state, &jar, &actions).await);

    let mut response = render("Diagnóstico de saúde", "/hardware", &user, body).into_response();
    if running {
        response
            .headers_mut()
            .insert("refresh", "2".parse().expect("static header"));
    }
    response
}

async fn periodic_section(state: &AppState, jar: &PrivateCookieJar, actions: &Actions) -> String {
    let mut section =
        String::from(r#"<div class="section-actions"><h3>Verificação periódica</h3></div>"#);
    match state.dbus.diagnostics().get_periodic().await {
        Ok((enabled, frequency)) => {
            let daily = frequency == "daily";
            section.push_str(&format!(
                "<p>Confere disco, logs, plataforma e segurança em segundo plano. Hoje: <strong>{}</strong>.</p>",
                if !enabled {
                    "desligada"
                } else if daily {
                    "ligada, todo dia"
                } else {
                    "ligada, toda semana"
                }
            ));
            let mut buttons = String::new();
            for (label, on, frequency) in [
                ("Toda semana", "true", "weekly"),
                ("Todo dia", "true", "daily"),
                ("Desligar", "false", "weekly"),
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
        Err(error) => section.push_str(&error_body("Verificação periódica indisponível", error)),
    }
    match cached_read::<LastPeriodic>(state, jar, ReadQuery::LastPeriodic) {
        Some(run) if run.job == 0 => section.push_str(
            r#"<p class="empty">A verificação periódica ainda não rodou nesta instalação.</p>"#,
        ),
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
                        html_escape(text::test_name(&stage.id)),
                        badge(&stage.verdict),
                        html_escape(&stage.summary)
                    )
                })
                .collect();
            section.push_str(&format!(
                r#"<section class="panel"><div class="panel-head"><h3>Última verificação: {when}</h3><span class="badge {}">{} novidade(s)</span></div>{}<table><tbody>{stages}</tbody></table>{}</section>"#,
                if run.novelties > 0 { "warn" } else { "on" },
                run.novelties,
                if novelties.is_empty() {
                    String::new()
                } else {
                    format!("<ul>{novelties}</ul>")
                },
                actions.button(
                    "Ver o relatório completo",
                    "diagnostics-report",
                    &[("job", &run.job.to_string()), ("redact", "false")]
                ),
            ));
        }
        None => section
            .push_str(&actions.unlock(ReadQuery::LastPeriodic, "Resultado da última verificação")),
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
    let Some(report) = session_json(&state, &jar, &report_key(job, false)) else {
        let body = format!(
            r#"<div class="notice"><strong>Relatório do diagnóstico {job}</strong><span>O relatório inclui trechos do journal. Confirme com sua senha para lê-lo; ele fica disponível por cinco minutos.</span>{}</div><p><a class="button-link" href="{PAGE}">Voltar</a></p>"#,
            actions.button(
                "Ler o relatório",
                "diagnostics-report",
                &[("job", &job.to_string()), ("redact", "false")]
            )
        );
        return render("Relatório do diagnóstico", "/hardware", &user, body).into_response();
    };
    let remedies = state
        .dbus
        .diagnostics()
        .remedies(job)
        .await
        .unwrap_or_default();
    let csrf = csrf_token(&state, &jar, &user);
    let body = report_body(job, &report, &remedies, &actions, csrf.as_deref());
    render("Relatório do diagnóstico", "/hardware", &user, body).into_response()
}

fn report_body(
    job: u32,
    report: &Value,
    remedies: &[DiagnosticRemedy],
    actions: &Actions,
    csrf: Option<&str>,
) -> String {
    let host = report.get("host").cloned().unwrap_or(Value::Null);
    let mut body = format!(
        r#"<p>Diagnóstico {job} · {} · {} · vegad {}</p>"#,
        html_escape(str_of(report, "started")),
        html_escape(str_of(&host, "os")),
        html_escape(str_of(&host, "vegad")),
    );
    let rows: String = stages(report)
        .iter()
        .map(|stage| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(text::test_name(str_of(stage, "id"))),
                badge(str_of(stage, "verdict")),
                html_escape(str_of(stage, "summary"))
            )
        })
        .collect();
    body.push_str(&format!(
        r#"<table><thead><tr><th>Teste</th><th>Resultado</th><th>Resumo</th></tr></thead><tbody>{rows}</tbody></table>"#
    ));
    if let Some(boot) = stages(report)
        .into_iter()
        .rfind(|stage| str_of(stage, "id") == "boot")
    {
        body.push_str(&boot_view(boot));
    }
    if let Some(network) = stages(report)
        .into_iter()
        .rfind(|stage| str_of(stage, "id") == "network")
    {
        body.push_str(&network_steps(network));
    }

    let mut attention = String::new();
    let mut info = String::new();
    for stage in stages(report) {
        let stage_id = str_of(stage, "id");
        for finding in findings(stage) {
            let severity = str_of(finding, "severity");
            let line = finding_view(stage_id, finding);
            if severity == "attention" || severity == "fail" {
                attention.push_str(&line);
            } else {
                info.push_str(&line);
            }
        }
    }
    body.push_str(r#"<div class="section-actions"><h3>Precisa de atenção</h3></div>"#);
    if attention.is_empty() {
        body.push_str(r#"<p class="notice success">Nenhum problema encontrado.</p>"#);
    } else {
        body.push_str(&attention);
    }
    if !info.is_empty() {
        body.push_str(&format!(
            "<details><summary>Informações</summary>{info}</details>"
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
                    .unwrap_or_else(|| text::remedy_text(&remedy.remedy, &[]));
                format!(
                    r#"<label class="check"><input type="checkbox" name="finding" value="{}:{}" checked> {}: {}</label>"#,
                    html_escape(&remedy.stage),
                    remedy.finding_index,
                    html_escape(text::test_name(&remedy.stage)),
                    html_escape(&label),
                )
            })
            .collect();
        body.push_str(&format!(
            r#"<div class="section-actions"><h3>Corrigir achados</h3></div>
<p>Marque o que o Vega deve consertar. Antes, um snapshot permite desfazer; depois, os testes afetados rodam de novo.</p>
<form method="post" action="{PAGE}/corrigir"><input type="hidden" name="csrf" value="{}"><input type="hidden" name="job" value="{job}">{items}<button type="submit" class="primary">Corrigir os marcados</button></form>"#,
            html_escape(csrf)
        ));
    }

    let logs = stages(report)
        .into_iter()
        .any(|stage| str_of(stage, "id") == "logs" && !findings(stage).is_empty());
    let mut more = String::new();
    if logs {
        more.push_str(&actions.button(
            "Já vi os logs",
            "mark-logs-seen",
            &[("job", &job.to_string())],
        ));
    }
    more.push_str(&actions.button(
        "Pedir ajuda",
        "diagnostics-report",
        &[("job", &job.to_string()), ("redact", "true")],
    ));
    body.push_str(&format!(
        r#"<div class="section-actions"><h3>Mais</h3></div>
<p>"Já vi os logs" faz os erros registrados até este diagnóstico deixarem de contar; o que acontecer depois volta a aparecer. "Pedir ajuda" monta um texto <strong>redigido</strong> para as Discussions ou para uma issue.</p>
<div class="row-actions">{more}</div><p><a class="button-link" href="{PAGE}">Voltar</a></p>"#
    ));
    body
}

fn finding_view(stage: &str, finding: &Value) -> String {
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
            "<span>Conserto disponível: {}</span>",
            html_escape(&text::remedy_text(remedy, &args))
        )
    } else {
        match text::guide(str_of(finding, "code"), severity) {
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
            "<details><summary>Dados brutos</summary><pre><code>{}</code></pre></details>",
            html_escape(raw)
        )
    };
    format!(
        r#"<div class="notice {level}"><strong>{}: {}</strong>{guide}{raw}</div>"#,
        html_escape(text::test_name(stage)),
        html_escape(str_of(finding, "text")),
    )
}

/// As fases do último boot e o que mais demorou antes do login.
fn boot_view(stage: &Value) -> String {
    let metrics = stage.get("metrics").cloned().unwrap_or(Value::Null);
    let Some(phases) = metrics.get("phases") else {
        return String::new();
    };
    let present: Vec<(&str, f64)> = text::BOOT_PHASES
        .iter()
        .filter_map(|(id, label)| {
            let value = phases.get(*id).and_then(Value::as_f64).unwrap_or(0.0);
            (value > 0.0).then_some((*label, value))
        })
        .collect();
    let total = metrics
        .get("totalSeconds")
        .and_then(Value::as_f64)
        .unwrap_or_else(|| present.iter().map(|(_, value)| value).sum());
    let phases: String = present
        .iter()
        .map(|(label, value)| format!("<tr><td>{label}</td><td>{}</td></tr>", seconds(*value)))
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
                seconds(unit.get("seconds").and_then(Value::as_f64).unwrap_or(0.0))
            )
        })
        .collect();
    format!(
        r#"<section class="panel"><div class="panel-head"><h3>Último boot</h3><span class="badge">{}</span></div><table><tbody>{phases}</tbody></table>{}</section>"#,
        seconds(total),
        if slowest.is_empty() {
            String::new()
        } else {
            format!(
                "<h4>O que mais demorou antes do login</h4><table><tbody>{slowest}</tbody></table>"
            )
        }
    )
}

/// Os passos do teste de rede, do cabo até a internet.
fn network_steps(stage: &Value) -> String {
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
                html_escape(text::network_step_name(str_of(step, "id"))),
                html_escape(text::network_step_status(status)),
                html_escape(str_of(step, "detail")),
            )
        })
        .collect();
    if rows.is_empty() {
        return String::new();
    }
    format!(
        r#"<section class="panel"><div class="panel-head"><h3>Rede, passo a passo</h3>{}</div><table><tbody>{rows}</tbody></table></section>"#,
        badge(str_of(stage, "verdict"))
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
    let Some(report) = session_json(&state, &jar, &report_key(job, true)) else {
        let body = format!(
            r#"<div class="notice"><strong>Pedir ajuda</strong><span>O texto sai do relatório <strong>redigido</strong> do diagnóstico {job}: sem nome do computador, usuários, endereços e caminhos pessoais. Confirme com sua senha para lê-lo.</span>{}</div>"#,
            actions.button(
                "Ler o relatório redigido",
                "diagnostics-report",
                &[("job", &job.to_string()), ("redact", "true")]
            )
        );
        return render("Pedir ajuda", "/hardware", &user, body).into_response();
    };
    let Some(csrf) = csrf_token(&state, &jar, &user) else {
        return Redirect::to("/login").into_response();
    };
    let description = match &form {
        Some(form) => {
            if !super::admin::matching_csrf(&csrf, &form.csrf) {
                return (StatusCode::FORBIDDEN, "Confirmação de sessão inválida.").into_response();
            }
            form.descricao.chars().take(2000).collect::<String>()
        }
        None => String::new(),
    };
    let help = help_text::build(
        &report,
        &description,
        env!("CARGO_PKG_VERSION"),
        help_text::HELP_LIMIT,
    );
    let title = {
        let first = description.lines().next().unwrap_or("").trim();
        if first.is_empty() {
            "Ajuda com o Lyra OS Server".to_owned()
        } else {
            format!("Ajuda: {}", help_text::cut(first, 80))
        }
    };
    let links = if form.is_some() {
        format!(
            r#"<div class="row-actions"><a class="button primary" href="{}" target="_blank" rel="noopener noreferrer">Perguntar nas Discussions</a><a class="button" href="{}" target="_blank" rel="noopener noreferrer">Abrir uma issue</a></div>
<p class="empty">Os links abrem o GitHub com o texto preenchido. Se o texto for longo, ele vai encurtado no link; copie o texto completo daqui.</p>"#,
            html_escape(&help_text::url(false, &title, &help)),
            html_escape(&help_text::url(true, &title, &help)),
        )
    } else {
        String::new()
    };
    let body = format!(
        r#"<p>Descreva o problema. O texto abaixo junta a sua descrição e o relatório <strong>redigido</strong> do diagnóstico {job}; confira antes de enviar.</p>
<form method="post" action="{PAGE}/ajuda/{job}"><input type="hidden" name="csrf" value="{}">
<label>O que está acontecendo<br><textarea name="descricao" rows="4" maxlength="2000" required>{}</textarea></label>
<button type="submit" class="primary">Montar o texto</button></form>
{links}
<h3>Texto</h3><pre class="help-text"><code>{}</code></pre>
<p><a class="button-link" href="{PAGE}/relatorio/{job}">Voltar ao relatório</a></p>"#,
        html_escape(&csrf),
        html_escape(&description),
        html_escape(&help),
    );
    render("Pedir ajuda", "/hardware", &user, body).into_response()
}

/// Rede e Firewall → Minha internet não funciona.
pub async fn network(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    let actions = Actions::new(&state, &jar, &user);
    let mut body = String::from(
        "<p>Testa a conexão passo a passo, do cabo ou Wi-Fi até a internet, e aponta onde está o problema. Não muda nada sem a sua confirmação.</p>",
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
                    body.push_str(&network_steps(stage));
                    if str_of(stage, "verdict") == "ok" {
                        body.push_str(r#"<p class="notice success">A conexão está funcionando.</p>"#);
                    }
                    for finding in findings(stage) {
                        if str_of(finding, "severity") != "info" {
                            body.push_str(&finding_view("network", finding));
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
                            .map(|remedy| text::remedy_text(&remedy.remedy, &[]))
                            .collect::<Vec<_>>()
                            .join("; ");
                        body.push_str(&format!(
                            r#"<div class="notice"><strong>Conserto disponível</strong><span>{}</span>{}</div>"#,
                            html_escape(&label),
                            actions.primary(
                                "Aplicar o conserto",
                                "repair-findings",
                                &[("job", &check.job.to_string()), ("findings", &findings)]
                            )
                        ));
                    }
                }
                None => body.push_str(r#"<p class="notice warn">O teste de rede não rodou.</p>"#),
            }
            body.push_str(&actions.button("Testar de novo", "network-check", &[]));
        }
        None => body.push_str(&format!(
            r#"<div class="notice"><strong>Minha internet não funciona</strong><span>Leva poucos segundos. Confirme com sua senha.</span>{}</div>"#,
            actions.primary("Testar a conexão", "network-check", &[])
        )),
    }
    body.push_str(r#"<p><a class="button-link" href="/rede">Voltar para Rede</a></p>"#);
    render("Minha internet não funciona", "/rede", &user, body).into_response()
}

/// Armazenamento → Liberar espaço: as categorias do sistema medidas pelo
/// broker, para o `storage.rs` montar a seção.
pub(crate) fn cleanup_section(
    state: &AppState,
    jar: &PrivateCookieJar,
    user: &CurrentUser,
) -> String {
    let actions = Actions::new(state, jar, user);
    let mut section = String::from(
        r#"<div class="section-actions" id="liberar"><h3>Liberar espaço</h3></div><p>Apaga relatórios de falha, logs antigos, pacotes baixados e outros itens do sistema que podem sair com segurança.</p>"#,
    );
    let Some(scan) = cached_read::<CleanupScan>(state, jar, ReadQuery::CleanupScan) else {
        section.push_str(&actions.unlock(
            ReadQuery::CleanupScan,
            "Medir o espaço que pode ser liberado",
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
            format!(
                "pelo menos {}, tamanho desconhecido",
                category.count.unwrap_or(0)
            )
        } else {
            text::bytes(category.bytes)
        };
        if category.can_clean {
            items.push_str(&format!(
                r#"<label class="check"><input type="checkbox" name="category" value="{}"{}> {} — {}</label>"#,
                html_escape(&category.id),
                if text::cleanup_default_on(&category.id) { " checked" } else { "" },
                html_escape(text::cleanup_name(&category.id)),
                html_escape(&size),
            ));
        } else {
            blocked.push_str(&format!(
                "<li>{}: {}</li>",
                html_escape(text::cleanup_name(&category.id)),
                html_escape(&text::cleanup_reason(
                    category.reason.as_deref().unwrap_or("nothing")
                ))
            ));
        }
    }
    if items.is_empty() {
        section.push_str(r#"<p class="notice success">Nada para limpar agora.</p>"#);
    } else {
        section.push_str(&format!(
            r#"<form method="post" action="/armazenamento/limpar"><input type="hidden" name="csrf" value="{}">{items}<p class="empty">Kernels antigos e snapshots só saem se você marcar. Não dá para desfazer.</p><button type="submit" class="primary">Liberar espaço</button></form>"#,
            html_escape(&csrf)
        ));
    }
    if !blocked.is_empty() {
        section.push_str(&format!(
            "<details><summary>Sem limpeza agora</summary><ul>{blocked}</ul></details>"
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
    let rows: String = job
        .categories
        .iter()
        .map(|(id, result, freed)| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(text::cleanup_name(id)),
                match result.as_str() {
                    "ok" => "Limpo",
                    "skipped" => "Pulado",
                    "failed" => "Falhou",
                    other => other,
                },
                text::bytes(*freed)
            )
        })
        .collect();
    let headline = if job.running {
        r#"<p class="notice">Limpando… a página se atualiza sozinha.</p>"#.to_owned()
    } else {
        match job.result.as_str() {
            "ok" => format!(
                r#"<p class="notice success"><strong>{} liberados.</strong></p>"#,
                text::bytes(job.freed)
            ),
            "partial" => format!(
                r#"<p class="notice warn"><strong>{} liberados.</strong> Algumas categorias não puderam ser limpas; veja o log do vegad.</p>"#,
                text::bytes(job.freed)
            ),
            "failed" => r#"<p class="notice error">A limpeza falhou; veja o log do vegad.</p>"#.to_owned(),
            _ => r#"<p class="notice warn">Resultado não confirmado. Meça de novo antes de repetir.</p>"#.to_owned(),
        }
    };
    let body = format!(
        r#"{headline}<p>Limpeza {}</p>{}<p><a class="button-link" href="/armazenamento#liberar">Voltar para Armazenamento</a></p>"#,
        job.job,
        if rows.is_empty() {
            String::new()
        } else {
            format!("<table><tbody>{rows}</tbody></table>")
        }
    );
    let mut response = render("Liberar espaço", "/armazenamento", &user, body).into_response();
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
