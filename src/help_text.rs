//! Texto do "Pedir ajuda" (add-help-report), montado a partir do relatório
//! **redigido** do diagnóstico. Porta do `help-text.js` do Vega: mesmo
//! limite, mesma ordem e o mesmo corte dos dados brutos.
use serde_json::Value;

/// Limite do texto: a URL de issue e de discussão fica abaixo de ~8 KB.
pub const HELP_LIMIT: usize = 6000;

/// Acima disso o GitHub recusa a URL.
pub const URL_LIMIT: usize = 7800;

/// O ponto único de ajuda do Lyra: as Discussions (Q&A) e o modelo de issue
/// "Pedir ajuda" ficam no repositório do Desktop, para as duas edições.
pub const HELP_REPO: &str = "https://github.com/lyra-os-linux/lyraos-desktop";

const ELLIPSIS: char = '…';

/// Corta `text` em `max` caracteres, terminando com "…" quando cortou.
pub fn cut(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_owned();
    }
    if max <= 1 {
        return ELLIPSIS.to_string();
    }
    let head: String = text.chars().take(max - 1).collect();
    format!("{}{ELLIPSIS}", head.trim_end())
}

fn str_field<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}

struct Finding {
    title: String,
    raw: String,
}

/// Monta o Markdown do pedido de ajuda. Só entram os achados de atenção e
/// falha. Se passar de `limit`, os dados brutos são encurtados por igual;
/// nenhum achado sai do texto.
pub fn build(report: &Value, description: &str, vega: &str, limit: usize) -> String {
    let host = report.get("host").cloned().unwrap_or(Value::Null);
    let stages: Vec<&Value> = report
        .get("stages")
        .and_then(Value::as_array)
        .map(|stages| stages.iter().collect())
        .unwrap_or_default();
    let mut head = vec!["## O que está acontecendo".to_owned(), String::new()];
    let description = description.trim();
    head.push(if description.is_empty() {
        "(sem descrição)".to_owned()
    } else {
        description.to_owned()
    });
    head.extend(["".into(), "## Sistema".into(), "".into()]);
    for (label, value) in [
        ("Computador", str_field(&host, "product")),
        ("Sistema", str_field(&host, "os")),
        ("Kernel", str_field(&host, "kernel")),
        ("vegad", str_field(&host, "vegad")),
        ("vega-web", vega),
        ("Diagnóstico", str_field(report, "started")),
    ] {
        if !value.is_empty() {
            head.push(format!("- {label}: {value}"));
        }
    }
    head.extend(["".into(), "## Testes".into(), "".into()]);
    for stage in &stages {
        let summary = str_field(stage, "summary");
        let summary = if summary.is_empty() {
            String::new()
        } else {
            format!(" — {summary}")
        };
        head.push(format!(
            "- {}: {}{summary}",
            crate::diagnostics_text::test_name(str_field(stage, "id")),
            crate::diagnostics_text::verdict_label(str_field(stage, "verdict")),
        ));
    }

    let mut findings = Vec::new();
    for stage in &stages {
        for finding in stage
            .get("findings")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let severity = str_field(finding, "severity");
            if severity != "attention" && severity != "fail" {
                continue;
            }
            findings.push(Finding {
                title: format!(
                    "- **{}:** {} (`{}`)",
                    crate::diagnostics_text::test_name(str_field(stage, "id")),
                    str_field(finding, "text"),
                    str_field(finding, "code"),
                ),
                raw: str_field(finding, "raw").trim().to_owned(),
            });
        }
    }

    let compose = |raw_max: usize| {
        let mut lines = head.clone();
        if !findings.is_empty() {
            lines.extend(["".into(), "## Achados".into(), "".into()]);
            for finding in &findings {
                lines.push(finding.title.clone());
                if !finding.raw.is_empty() && raw_max > 0 {
                    lines.extend([
                        String::new(),
                        "```".into(),
                        cut(&finding.raw, raw_max),
                        "```".into(),
                        String::new(),
                    ]);
                }
            }
        }
        format!("{}\n", lines.join("\n").trim_end())
    };
    let length = |text: &str| text.chars().count();

    let text = compose(usize::MAX);
    if length(&text) <= limit {
        return text;
    }
    // Encurta os dados brutos por igual até caber; sem espaço, tira só eles.
    let without_raw = length(&compose(0));
    let with_raw = findings
        .iter()
        .filter(|finding| !finding.raw.is_empty())
        .count();
    // Cada trecho custa a cerca do bloco de código (~10 caracteres).
    let mut share: i64 = if with_raw > 0 {
        (limit as i64 - without_raw as i64) / with_raw as i64 - 12
    } else {
        0
    };
    while share > 0 {
        let text = compose(share as usize);
        let size = length(&text);
        if size <= limit {
            return text;
        }
        share -= std::cmp::max(1, (size - limit).div_ceil(with_raw) as i64);
    }
    cut(&compose(0), limit)
}

/// Codifica um componente da URL como o `encodeURIComponent` do navegador.
pub fn encode_component(text: &str) -> String {
    let mut out = String::with_capacity(text.len() * 3);
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// A URL de uma discussão (Q&A) ou de uma issue com o texto já preenchido,
/// encurtado até caber no limite do GitHub.
pub fn url(issue: bool, title: &str, body: &str) -> String {
    let base = if issue {
        format!("{HELP_REPO}/issues/new?template=help.md&title=")
    } else {
        format!("{HELP_REPO}/discussions/new?category=q-a&title=")
    };
    let note = "\n\n(Texto encurtado; copie o texto completo da página do painel.)";
    let build = |text: &str| {
        format!(
            "{base}{}&body={}",
            encode_component(title),
            encode_component(text)
        )
    };
    let mut text = body.to_owned();
    let mut link = build(&text);
    while link.len() > URL_LIMIT && text.chars().count() > 200 {
        let keep = text.chars().count() * 85 / 100;
        text = format!("{}{note}", cut(body, keep));
        link = build(&text);
    }
    link
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn report(raw_size: usize, findings: usize) -> Value {
        let mut items: Vec<Value> = (0..findings)
            .map(|i| {
                json!({"severity": "attention", "code": format!("logs.item{i}"),
                       "text": format!("Achado {i}"), "raw": "x".repeat(raw_size)})
            })
            .collect();
        items.push(
            json!({"severity": "info", "code": "logs.noise.boot", "text": "Ruído", "raw": "ruído"}),
        );
        json!({
            "started": "2026-10-30T10:00:00-03:00",
            "host": {"product": "Standard PC", "os": "Lyra OS Server 16.1 RC 3", "kernel": "6.12.0",
                     "vegad": "5.6.2", "hostname": "[redacted]"},
            "stages": [
                {"id": "logs", "verdict": "attention", "summary": "3 erros", "findings": items},
                {"id": "platform", "verdict": "ok", "summary": "tudo certo", "findings": []}
            ]
        })
    }

    #[test]
    fn small_report_keeps_everything_but_info() {
        let text = build(
            &report(200, 3),
            "A internet cai toda hora",
            "5.2.0",
            HELP_LIMIT,
        );
        assert!(text.contains("A internet cai toda hora"));
        assert!(text.contains("- Computador: Standard PC"));
        assert!(text.contains("- vega-web: 5.2.0"));
        assert!(text.contains("- Logs e falhas: Atenção — 3 erros"));
        assert!(text.contains("- Estado da plataforma: Saudável — tudo certo"));
        assert_eq!(text.matches("`logs.item").count(), 3);
        assert!(!text.contains("Ruído"), "informação não entra");
        assert!(!text.contains('…'));
    }

    #[test]
    fn big_raw_data_is_cut_but_every_finding_stays() {
        let text = build(&report(1000, 40), "x", "5.2.0", HELP_LIMIT);
        assert!(text.chars().count() <= HELP_LIMIT);
        assert_eq!(text.matches("`logs.item").count(), 40);
        assert!(text.contains('…'));
        assert!(text.contains("- Estado da plataforma: Saudável"));
    }

    #[test]
    fn redacted_values_pass_through_untouched_and_empty_description_is_marked() {
        let text = build(&report(10, 1), "  ", "5.2.0", HELP_LIMIT);
        assert!(!text.contains("hostname"));
        assert!(text.contains("(sem descrição)"));
    }

    #[test]
    fn urls_fit_the_github_limit_and_encode_like_the_browser() {
        assert_eq!(encode_component("a b&c/ç"), "a%20b%26c%2F%C3%A7");
        let body = build(&report(1000, 40), "x", "5.2.0", HELP_LIMIT);
        for issue in [false, true] {
            let link = url(issue, "Ajuda: rede", &body);
            assert!(link.len() <= URL_LIMIT, "{}", link.len());
            assert!(link.starts_with(HELP_REPO));
        }
        assert!(url(true, "t", "b").contains("/issues/new?template=help.md&title=t&body=b"));
        assert!(url(false, "t", "b").contains("/discussions/new?category=q-a&title=t&body=b"));
    }
}
