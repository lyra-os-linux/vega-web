//! Small self-contained visual building blocks — inline SVG icons and usage
//! gauges — shared across pages. Everything renders as plain markup (no JS,
//! no external assets) so it fits the same LAN-only, dependency-free model
//! as the rest of vega-web. Callers are expected to pre-escape any dynamic
//! text passed in (same convention as the rest of this crate).

/// A 24x24 stroke icon, sized and colored by the `.icon` CSS class
/// (`currentColor`, so it follows the surrounding text/accent color and the
/// active theme automatically).
pub fn icon(name: &str) -> &'static str {
    macro_rules! svg {
        ($body:expr) => {
            concat!(
                r#"<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">"#,
                $body,
                "</svg>"
            )
        };
    }
    match name {
        "dashboard" => svg!(
            r#"<rect x="3" y="3" width="8" height="8" rx="2"/><rect x="13" y="3" width="8" height="8" rx="2"/><rect x="3" y="13" width="8" height="8" rx="2"/><rect x="13" y="13" width="8" height="8" rx="2"/>"#
        ),
        "software" => svg!(
            r#"<path d="M3 8l9-5 9 5-9 5-9-5z"/><path d="M3 8v8l9 5 9-5V8"/><path d="M12 13v8"/>"#
        ),
        "backup" => svg!(
            r#"<rect x="3" y="4" width="18" height="4" rx="1"/><path d="M5 8v10a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8"/><path d="M12 12v5"/><path d="M9.5 14.5 12 17l2.5-2.5"/>"#
        ),
        "snapshots" => svg!(
            r#"<path d="M4 8h3l1.5-2h7L17 8h3a1 1 0 0 1 1 1v9a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V9a1 1 0 0 1 1-1z"/><circle cx="12" cy="13" r="3.5"/>"#
        ),
        "hardware" | "cpu" => svg!(
            r#"<rect x="7" y="7" width="10" height="10" rx="1.5"/><rect x="10" y="2.5" width="1.6" height="3"/><rect x="14" y="2.5" width="1.6" height="3"/><rect x="10" y="18.5" width="1.6" height="3"/><rect x="14" y="18.5" width="1.6" height="3"/><rect x="2.5" y="10" width="3" height="1.6"/><rect x="2.5" y="14" width="3" height="1.6"/><rect x="18.5" y="10" width="3" height="1.6"/><rect x="18.5" y="14" width="3" height="1.6"/>"#
        ),
        "storage" | "disk" => svg!(
            r#"<ellipse cx="12" cy="5.5" rx="8" ry="3"/><path d="M4 5.5v6c0 1.66 3.58 3 8 3s8-1.34 8-3v-6"/><path d="M4 11.5v6c0 1.66 3.58 3 8 3s8-1.34 8-3v-6"/>"#
        ),
        "network" | "wifi" => svg!(
            r#"<path d="M2.5 9.5a15 15 0 0 1 19 0"/><path d="M6 13a10 10 0 0 1 12 0"/><path d="M9.5 16.5a5 5 0 0 1 5 0"/><circle cx="12" cy="19.5" r="1.1" fill="currentColor" stroke="none"/>"#
        ),
        "services" => svg!(
            r#"<rect x="2.5" y="8" width="19" height="8" rx="4"/><circle cx="16" cy="12" r="2.6" fill="currentColor" stroke="none"/>"#
        ),
        "users" => svg!(
            r#"<circle cx="9" cy="8" r="3.2"/><path d="M3 20c0-3.3 2.7-6 6-6s6 2.7 6 6"/><circle cx="17.5" cy="9" r="2.6"/><path d="M15.5 14.2c2.7.4 4.7 2.6 5 5.8"/>"#
        ),
        "logs" => svg!(
            r#"<rect x="2.5" y="4" width="19" height="16" rx="2"/><path d="M6.5 9.5 10 12l-3.5 2.5"/><path d="M12 15h5.5"/>"#
        ),
        "monitor" => svg!(r#"<path d="M2.5 12h4l2.2-6.5L13 18l2.3-6H21.5"/>"#),
        "datetime" => svg!(r#"<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3.5 2"/>"#),
        "gpu" => svg!(
            r#"<rect x="2.5" y="4.5" width="19" height="12" rx="2"/><path d="M9 20.5h6"/><path d="M12 16.5v4"/>"#
        ),
        "memory" => svg!(
            r#"<rect x="3" y="8" width="18" height="8" rx="1.5"/><path d="M6 8V5.5"/><path d="M9.5 8V5.5"/><path d="M13 8V5.5"/><path d="M16.5 8V5.5"/>"#
        ),
        "swap" => svg!(
            r#"<path d="M7 4v13"/><path d="M4 14l3 3 3-3"/><path d="M17 20V7"/><path d="M20 10l-3-3-3 3"/>"#
        ),
        "upload" => {
            svg!(r#"<path d="M12 19V6"/><path d="M6.5 11.5 12 6l5.5 5.5"/><path d="M4 21h16"/>"#)
        }
        "download" => {
            svg!(r#"<path d="M12 5v13"/><path d="M6.5 12.5 12 18l5.5-5.5"/><path d="M4 21h16"/>"#)
        }
        "firewall" => svg!(
            r#"<path d="M12 3l7 3v6c0 4.5-3 8-7 9-4-1-7-4.5-7-9V6l7-3z"/><path d="M9 12l2 2 4-4.5"/>"#
        ),
        "check" => svg!(r#"<circle cx="12" cy="12" r="9"/><path d="M8 12.5l2.5 2.5L16 9.5"/>"#),
        "warning" => svg!(
            r#"<path d="M12 4 2.5 20h19L12 4z"/><path d="M12 10v4.5"/><circle cx="12" cy="17.5" r="0.9" fill="currentColor" stroke="none"/>"#
        ),
        _ => svg!(r#"<circle cx="12" cy="12" r="9"/>"#),
    }
}

/// 0-100 usage bucket → CSS tone class, shared by every gauge/bar so a
/// system under pressure reads the same way everywhere it shows up.
fn tone_for_percent(percent: f64) -> &'static str {
    if percent >= 90.0 {
        "danger"
    } else if percent >= 75.0 {
        "warn"
    } else {
        "accent"
    }
}

/// A circular progress ring for a 0-100 percentage. Uses the classic
/// r=15.9155 trick (circle circumference ≈ 100), so `stroke-dasharray`
/// can be set directly from the percentage with no extra math in CSS.
fn gauge_ring(percent: f64, tone: &str) -> String {
    let clamped = percent.clamp(0.0, 100.0);
    format!(
        r#"<svg class="gauge-ring" viewBox="0 0 36 36" aria-hidden="true"><circle class="gauge-track" cx="18" cy="18" r="15.9155"/><circle class="gauge-value gauge-{tone}" cx="18" cy="18" r="15.9155" stroke-dasharray="{clamped:.1} 100"/></svg>"#
    )
}

/// A stat tile combining an icon, a circular usage gauge, a label and a
/// value. `label` and `value` must already be HTML-escaped by the caller.
pub fn gauge_stat(icon_name: &str, label: &str, value: &str, percent: f64) -> String {
    let tone = tone_for_percent(percent);
    format!(
        r#"<div class="stat-tile"><div class="stat-tile-icon">{icon}</div>{ring}<div class="stat-tile-body"><span class="stat-tile-label">{label}</span><strong class="stat-tile-value">{value}</strong></div></div>"#,
        icon = icon(icon_name),
        ring = gauge_ring(percent, tone),
    )
}

/// A plain icon + value card, for metrics that aren't a 0-100 percentage.
/// `label` and `value` must already be HTML-escaped by the caller.
pub fn icon_stat(icon_name: &str, label: &str, value: &str) -> String {
    format!(
        r#"<div class="card card-icon"><div class="card-icon-badge">{icon}</div><div><span class="card-label">{label}</span><strong>{value}</strong></div></div>"#,
        icon = icon(icon_name),
    )
}

/// A thin horizontal usage bar, for embedding inline (table cells, list
/// rows) where a full gauge ring would be too heavy.
pub fn bar(percent: f64) -> String {
    let clamped = percent.clamp(0.0, 100.0);
    let tone = tone_for_percent(clamped);
    format!(
        r#"<div class="bar-track"><div class="bar-value bar-{tone}" style="width:{clamped:.1}%"></div></div>"#
    )
}
