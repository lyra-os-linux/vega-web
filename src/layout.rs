const STYLE: &str = r#"
:root {
  color-scheme: light dark;
  --color-canvas: #f4f5f8;
  --color-sidebar: #ffffff;
  --color-surface: #ffffff;
  --color-inset: #f2f3f6;
  --color-field: #ffffff;
  --surface-hover: #f1eefe;
  --border-subtle: #e8e9ee;
  --border: #dfe1e8;
  --border-strong: #cbcfd9;
  --text-primary: #191b22;
  --text-secondary: #4a4f5c;
  --text-muted: #7a808f;
  --accent: #6d28d9;
  --accent-strong: #7c3aed;
  --accent-soft-bg: #efe9fe;
  --accent-soft-text: #5b21b6;
  --focus-ring: rgb(124 58 237 / 22%);
  --success-bg: #e4f6ed;
  --success-text: #167a4f;
  --danger-bg: #fbe7ea;
  --danger-text: #b3243a;
  --radius-xs: 7px;
  --radius-sm: 10px;
  --radius-md: 14px;
  --radius-lg: 20px;
  --radius-pill: 999px;
  --shadow-sm: 0 1px 3px rgb(15 23 42 / 6%);
  --shadow-md: 0 8px 24px rgb(15 23 42 / 8%);
  --shadow-lg: 0 24px 60px rgb(15 23 42 / 16%);
  --transition: 150ms ease;
}
@media (prefers-color-scheme: dark) {
  :root {
    --color-canvas: #0f1115;
    --color-sidebar: #14161c;
    --color-surface: #181b22;
    --color-inset: #12141a;
    --color-field: #11131a;
    --surface-hover: #242a3a;
    --border-subtle: #24272f;
    --border: #2b2f39;
    --border-strong: #383d4a;
    --text-primary: #eef0f4;
    --text-secondary: #c4c9d4;
    --text-muted: #8b91a1;
    --accent: #a78bfa;
    --accent-strong: #c4b5fd;
    --accent-soft-bg: #2b2450;
    --accent-soft-text: #d8cbff;
    --focus-ring: rgb(167 139 250 / 25%);
    --success-bg: #1c3a2c;
    --success-text: #9fdcbb;
    --danger-bg: #3c1e24;
    --danger-text: #ffb0bc;
    --shadow-sm: 0 1px 3px rgb(0 0 0 / 30%);
    --shadow-md: 0 8px 24px rgb(0 0 0 / 35%);
    --shadow-lg: 0 24px 60px rgb(0 0 0 / 45%);
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100vh;
  color: var(--text-primary);
  background: var(--color-canvas);
  font-family: Inter, ui-sans-serif, system-ui, "Segoe UI", sans-serif;
  font-size: 14px;
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}
h1, h2, h3 { line-height: 1.25; letter-spacing: -0.01em; }
h1 { font-size: 1.6rem; margin: 0; }
h3 { font-size: 0.78rem; margin: 1.9rem 0 0.75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.06em; font-weight: 700; }
p { color: var(--text-secondary); }
small { color: var(--text-muted); }
code { background: var(--color-inset); border-radius: 4px; padding: 0.1rem 0.4rem; font-size: 0.85em; }
a { color: var(--accent); }

.app-shell { display: grid; grid-template-columns: 236px 1fr; min-height: 100vh; }
aside {
  display: flex; flex-direction: column; gap: 1.5rem;
  padding: 1.4rem 1rem; background: var(--color-sidebar);
  border-right: 1px solid var(--border-subtle);
  position: sticky; top: 0; height: 100vh; overflow-y: auto;
}
.brand { display: flex; align-items: center; gap: 0.6rem; padding: 0 0.4rem; }
.brand-mark {
  display: grid; place-items: center; width: 32px; height: 32px; border-radius: 9px;
  background: linear-gradient(135deg, #8b5cf6, #4f46e5 55%, #06b6d4);
  color: #fff; font-weight: 700; font-size: 0.9rem; box-shadow: var(--shadow-sm); flex-shrink: 0;
}
.brand-name { font-weight: 700; font-size: 1.02rem; letter-spacing: -0.01em; }

.nav-groups { display: flex; flex-direction: column; gap: 1.1rem; overflow-y: auto; }
.nav-group-label {
  margin: 0 0 0.3rem 0.6rem; color: var(--text-muted); font-size: 0.68rem;
  font-weight: 700; text-transform: uppercase; letter-spacing: 0.07em;
}
nav { display: grid; gap: 1px; }
nav a {
  display: flex; align-items: center; gap: 0.6rem; padding: 0.5rem 0.65rem; border-radius: var(--radius-xs);
  color: var(--text-muted); font-size: 0.86rem; font-weight: 500; text-decoration: none;
  border-left: 2px solid transparent;
  transition: background-color var(--transition), color var(--transition);
}
nav a .icon { width: 16px; height: 16px; flex-shrink: 0; opacity: 0.85; }
nav a:hover { color: var(--text-primary); background: var(--surface-hover); }
nav a.active { color: var(--accent); background: var(--accent-soft-bg); border-left-color: var(--accent); font-weight: 600; }

.sidebar-foot { margin-top: auto; display: grid; gap: 0.4rem; padding-top: 0.9rem; border-top: 1px solid var(--border-subtle); }
.sidebar-user { padding: 0 0.5rem; font-size: 0.8rem; color: var(--text-muted); overflow-wrap: anywhere; }
.sidebar-foot form { margin: 0; }
.sidebar-foot button {
  width: 100%; text-align: left; padding: 0.5rem 0.65rem; border-radius: var(--radius-xs);
  color: var(--text-muted); background: transparent; border: 0; font: inherit; cursor: pointer;
  transition: background-color var(--transition), color var(--transition);
}
.sidebar-foot button:hover { color: var(--text-primary); background: var(--surface-hover); }

.content { min-width: 0; max-width: 62rem; width: 100%; margin: 0 auto; padding: 2.4rem 2.5rem 4rem; }
.content > header { display: flex; align-items: center; gap: 1rem; margin-bottom: 1.6rem; }
.content > header .header-icon {
  display: grid; place-items: center; width: 46px; height: 46px; border-radius: var(--radius-md);
  background: var(--accent-soft-bg); color: var(--accent-strong); flex-shrink: 0;
}
.content > header .header-icon .icon { width: 22px; height: 22px; }
.content > header .heading { display: grid; gap: 0.2rem; min-width: 0; }
.content > header .eyebrow {
  margin: 0; color: var(--text-muted); font-size: 0.72rem;
  font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase;
}

.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(11rem, 1fr)); gap: 0.85rem; margin: 0 0 1.25rem; }
.card {
  display: grid; gap: 0.35rem; padding: 1.05rem 1.15rem; border: 1px solid var(--border);
  border-radius: var(--radius-md); background: var(--color-surface); box-shadow: var(--shadow-sm);
  color: var(--text-muted); font-size: 0.78rem;
  transition: box-shadow var(--transition), transform var(--transition);
}
.card:hover { box-shadow: var(--shadow-md); transform: translateY(-1px); }
.card strong { font-size: 1.35rem; color: var(--text-primary); font-weight: 700; letter-spacing: -0.01em; }

.icon { width: 1em; height: 1em; display: block; }

.card.card-icon { display: flex; flex-direction: row; align-items: center; gap: 0.8rem; }
.card-icon-badge {
  display: grid; place-items: center; width: 34px; height: 34px; border-radius: var(--radius-sm);
  background: var(--color-inset); color: var(--accent-strong); flex-shrink: 0;
}
.card-icon-badge .icon { width: 18px; height: 18px; }
.card-label {
  display: block; font-size: 0.72rem; color: var(--text-muted); font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.04em; margin-bottom: 0.15rem;
}
.card.card-icon strong { font-size: 1.1rem; }

.stat-tile {
  display: flex; align-items: center; gap: 0.9rem; padding: 1.05rem 1.15rem;
  border: 1px solid var(--border); border-radius: var(--radius-md); background: var(--color-surface);
  box-shadow: var(--shadow-sm); transition: box-shadow var(--transition), transform var(--transition);
}
.stat-tile:hover { box-shadow: var(--shadow-md); transform: translateY(-1px); }
.stat-tile-icon {
  display: grid; place-items: center; width: 34px; height: 34px; border-radius: var(--radius-sm);
  background: var(--color-inset); color: var(--text-muted); flex-shrink: 0;
}
.stat-tile-icon .icon { width: 18px; height: 18px; }
.stat-tile-body { display: grid; gap: 0.15rem; min-width: 0; }
.stat-tile-label {
  font-size: 0.72rem; color: var(--text-muted); font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.04em;
}
.stat-tile-value {
  font-size: 1.15rem; color: var(--text-primary); font-weight: 700; letter-spacing: -0.01em;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.gauge-ring { width: 56px; height: 56px; flex-shrink: 0; transform: rotate(-90deg); }
.gauge-track { fill: none; stroke: var(--border); stroke-width: 3.2; }
.gauge-value { fill: none; stroke-width: 3.2; stroke-linecap: round; transition: stroke-dasharray 500ms ease; }
.gauge-value.gauge-accent { stroke: var(--accent-strong); }
.gauge-value.gauge-warn { stroke: #f59e0b; }
.gauge-value.gauge-danger { stroke: var(--danger-text); }

.bar-track { width: 100%; min-width: 5rem; height: 6px; border-radius: var(--radius-pill); background: var(--color-inset); overflow: hidden; }
.bar-value { height: 100%; border-radius: var(--radius-pill); transition: width 500ms ease; }
.bar-value.bar-accent { background: var(--accent-strong); }
.bar-value.bar-warn { background: #f59e0b; }
.bar-value.bar-danger { background: var(--danger-text); }
td .bar-track { margin-top: 0.4rem; max-width: 11rem; }

table {
  width: 100%; border-collapse: collapse; margin: 0 0 1.25rem;
  border: 1px solid var(--border); background: var(--color-surface);
  display: block; overflow-x: auto;
}
thead { background: var(--color-inset); }
th {
  text-align: left; padding: 0.6rem 0.85rem; font-size: 0.7rem; font-weight: 700;
  color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.04em;
  border-bottom: 1px solid var(--border); white-space: nowrap;
}
td {
  padding: 0.6rem 0.85rem; border-bottom: 1px solid var(--border-subtle);
  color: var(--text-secondary); font-size: 0.84rem; vertical-align: top;
}
tbody tr:last-child td { border-bottom: 0; }
tbody tr:hover { background: var(--surface-hover); }
td small { display: block; margin-top: 0.15rem; }

.badge {
  display: inline-block; padding: 0.15rem 0.6rem; border-radius: var(--radius-pill);
  font-size: 0.72rem; font-weight: 600; background: var(--color-inset); color: var(--text-muted);
}
.badge.on { background: var(--success-bg); color: var(--success-text); }

.error {
  color: var(--danger-text); background: var(--danger-bg);
  padding: 0.6rem 0.9rem; border-radius: var(--radius-sm); font-size: 0.85rem; margin: 0 0 1rem;
}

form { display: grid; gap: 0.85rem; margin: 0 0 1.25rem; max-width: 28rem; }
form label { display: grid; gap: 0.35rem; font-size: 0.8rem; font-weight: 600; color: var(--text-secondary); }
input, select {
  width: 100%; padding: 0.55rem 0.7rem; border: 1px solid var(--border-strong);
  border-radius: var(--radius-sm); background: var(--color-field); color: var(--text-primary);
  font: inherit; outline: none; transition: border-color var(--transition), box-shadow var(--transition);
}
input:hover, select:hover { border-color: var(--text-muted); }
input:focus, select:focus { border-color: var(--accent); box-shadow: 0 0 0 3px var(--focus-ring); }
button { font: inherit; cursor: pointer; }
form button[type="submit"] {
  justify-self: start; padding: 0.55rem 1.15rem; border: 0; border-radius: var(--radius-sm);
  background: var(--accent-strong); color: #fff; font-weight: 600; box-shadow: var(--shadow-sm);
  transition: filter var(--transition);
}
form button[type="submit"]:hover { filter: brightness(1.08); }
.section-actions { display: flex; align-items: center; justify-content: space-between; gap: 1rem; margin: 1.9rem 0 0.75rem; }
.section-actions h3 { margin: 0; }
.button-link {
  display: inline-flex; align-items: center; justify-content: center; min-height: 34px; padding: 0.4rem 0.8rem;
  border: 1px solid var(--border); border-radius: var(--radius-sm); background: var(--color-surface);
  color: var(--text-secondary); font-size: 0.78rem; font-weight: 600; text-decoration: none; box-shadow: var(--shadow-sm);
}
.button-link:hover { color: var(--accent); border-color: var(--accent); }
.inline-form {
  grid-template-columns: minmax(9rem, 1fr) minmax(7rem, 0.45fr) auto; align-items: end;
  max-width: 36rem; padding: 1rem; border: 1px solid var(--border); border-radius: var(--radius-md);
  background: var(--color-surface); box-shadow: var(--shadow-sm);
}
.inline-form button[type="submit"] { min-height: 40px; white-space: nowrap; }
.row-action-form { display: inline; margin: 0; }
.row-action-form button[type="submit"] {
  min-height: 32px; padding: 0.35rem 0.75rem; white-space: nowrap; font-size: 0.78rem;
}
.notice { padding: 0.65rem 0.9rem; border-radius: var(--radius-sm); background: var(--accent-soft-bg); color: var(--accent-soft-text); }
.notice.success { background: var(--success-bg); color: var(--success-text); }
@media (max-width: 38rem) { .inline-form { grid-template-columns: 1fr; } }

pre { background: var(--color-inset); border: 1px solid var(--border); border-radius: var(--radius-md); padding: 1rem; overflow-x: auto; }

.auth-shell {
  position: relative; isolation: isolate; min-height: 100vh; display: grid; place-items: center;
  padding: 2rem 1.5rem; overflow: hidden;
  background:
    radial-gradient(circle at 16% 12%, var(--accent-soft-bg), transparent 34rem),
    radial-gradient(circle at 88% 86%, rgb(6 182 212 / 10%), transparent 30rem),
    var(--color-canvas);
}
.auth-shell::before, .auth-shell::after {
  content: ""; position: absolute; z-index: -1; border: 1px solid var(--border-subtle);
  border-radius: 50%; opacity: 0.65;
}
.auth-shell::before { width: 28rem; height: 28rem; top: -17rem; right: -8rem; }
.auth-shell::after { width: 22rem; height: 22rem; bottom: -14rem; left: -6rem; }
.auth-wrap { width: min(26rem, 100%); }
.auth-brand {
  display: flex; align-items: center; justify-content: center; gap: 0.65rem;
  margin-bottom: 1.25rem; color: var(--text-primary);
}
.auth-brand .brand-mark { width: 38px; height: 38px; border-radius: 11px; font-size: 1rem; }
.auth-brand .brand-name { font-size: 1.08rem; }
.auth-brand-product { color: var(--text-muted); font-size: 0.78rem; font-weight: 500; }
.auth-brand-product::before { content: "·"; margin-right: 0.65rem; }
.auth-card {
  width: 100%; padding: 2.25rem; border: 1px solid var(--border);
  border-radius: var(--radius-lg); background: color-mix(in srgb, var(--color-surface) 96%, transparent);
  box-shadow: var(--shadow-lg); backdrop-filter: blur(12px); text-align: left;
}
.auth-kicker {
  margin: 0 0 0.5rem; color: var(--accent); font-size: 0.7rem; font-weight: 750;
  letter-spacing: 0.09em; text-transform: uppercase;
}
.auth-card h1 { font-size: 1.7rem; margin-bottom: 0.55rem; }
.auth-subtitle { margin: 0; font-size: 0.9rem; line-height: 1.55; }
.auth-card form { max-width: none; margin: 1.75rem 0 0; gap: 1rem; }
.auth-card form label { gap: 0.45rem; font-size: 0.78rem; }
.auth-card input { min-height: 44px; padding: 0.68rem 0.8rem; }
.auth-card .error { margin: 1.25rem 0 -0.35rem; border: 1px solid color-mix(in srgb, var(--danger-text) 24%, transparent); }
.auth-card button[type="submit"] {
  width: 100%; min-height: 44px; justify-self: stretch; margin-top: 0.3rem; text-align: center;
  background: linear-gradient(135deg, #7c3aed, #5b4de5); box-shadow: 0 8px 18px rgb(109 40 217 / 20%);
}
.auth-card button[type="submit"]:active { transform: translateY(1px); }
.auth-footnote { margin: 1rem 0 0; text-align: center; color: var(--text-muted); font-size: 0.75rem; }
@media (max-width: 30rem) {
  .auth-shell { padding: 1.25rem 1rem; align-items: center; }
  .auth-card { padding: 1.6rem 1.35rem; }
  .auth-card h1 { font-size: 1.45rem; }
}
"#;

struct NavItem {
    href: &'static str,
    label: &'static str,
    icon: &'static str,
}

struct NavGroup {
    label: &'static str,
    items: &'static [NavItem],
}

const NAV: &[NavGroup] = &[
    NavGroup {
        label: "Principal",
        items: &[
            NavItem {
                href: "/",
                label: "Painel",
                icon: "dashboard",
            },
            NavItem {
                href: "/software",
                label: "Software",
                icon: "software",
            },
            NavItem {
                href: "/backup",
                label: "Backup",
                icon: "backup",
            },
            NavItem {
                href: "/snapshots",
                label: "Snapshots",
                icon: "snapshots",
            },
        ],
    },
    NavGroup {
        label: "Sistema",
        items: &[
            NavItem {
                href: "/hardware",
                label: "Hardware e Kernel",
                icon: "hardware",
            },
            NavItem {
                href: "/armazenamento",
                label: "Armazenamento",
                icon: "storage",
            },
            NavItem {
                href: "/rede",
                label: "Rede e Firewall",
                icon: "network",
            },
            NavItem {
                href: "/servicos",
                label: "Serviços",
                icon: "services",
            },
            NavItem {
                href: "/usuarios",
                label: "Usuários",
                icon: "users",
            },
            NavItem {
                href: "/logs",
                label: "Logs",
                icon: "logs",
            },
            NavItem {
                href: "/monitor",
                label: "Monitor",
                icon: "monitor",
            },
            NavItem {
                href: "/data-hora",
                label: "Data e Hora",
                icon: "datetime",
            },
        ],
    },
];

fn brand_mark() -> &'static str {
    r#"<span class="brand-mark">V</span>"#
}

pub fn page(title: &str, active_href: &str, username: &str, body: &str) -> String {
    let nav_groups: String = NAV
        .iter()
        .map(|group| {
            let items: String = group
                .items
                .iter()
                .map(|item| {
                    let class = if item.href == active_href {
                        " class=\"active\""
                    } else {
                        ""
                    };
                    format!(
                        r#"<a href="{}"{}>{}{}</a>"#,
                        item.href,
                        class,
                        crate::pages::widgets::icon(item.icon),
                        item.label
                    )
                })
                .collect();
            format!(
                r#"<div><p class="nav-group-label">{}</p><nav>{items}</nav></div>"#,
                group.label
            )
        })
        .collect();

    let page_icon = NAV
        .iter()
        .flat_map(|group| group.items)
        .find(|item| item.href == active_href)
        .map(|item| item.icon)
        .unwrap_or("dashboard");

    format!(
        r#"<!doctype html>
<html lang="pt-br">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · Vega</title>
<style>{STYLE}</style>
</head>
<body>
<div class="app-shell">
<aside>
<div class="brand">{}<span class="brand-name">Vega</span></div>
<div class="nav-groups">{nav_groups}</div>
<div class="sidebar-foot">
<p class="sidebar-user">{username}</p>
<form method="post" action="/logout"><button type="submit">Sair</button></form>
</div>
</aside>
<div class="content">
<header><div class="header-icon">{}</div><div class="heading"><p class="eyebrow">Vega</p><h1>{title}</h1></div></header>
{body}
</div>
</div>
</body>
</html>"#,
        brand_mark(),
        crate::pages::widgets::icon(page_icon),
    )
}

pub fn login_page(error: Option<&str>) -> String {
    let error_html = error
        .map(|message| format!(r#"<p class="error" role="alert">{message}</p>"#))
        .unwrap_or_default();

    format!(
        r#"<!doctype html>
<html lang="pt-br">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Entrar · Vega</title>
<style>{STYLE}</style>
</head>
<body>
<div class="auth-shell">
<main class="auth-wrap">
<div class="auth-brand">{}<span class="brand-name">Vega</span><span class="auth-brand-product">Administração</span></div>
<div class="auth-card">
<p class="auth-kicker">Área administrativa</p>
<h1>Boas-vindas</h1>
<p class="auth-subtitle">Entre com sua conta do sistema para administrar esta máquina com segurança.</p>
{error_html}
<form method="post" action="/login">
<label for="username">Usuário</label>
<input id="username" type="text" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" autofocus required>
<label for="password">Senha</label>
<input id="password" type="password" name="password" autocomplete="current-password" required>
<button type="submit">Entrar no Vega</button>
</form>
</div>
<p class="auth-footnote">Acesso protegido pela autenticação do sistema</p>
</main>
</div>
</body>
</html>"#,
        brand_mark()
    )
}
