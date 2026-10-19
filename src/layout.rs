use crate::auth::LoginLang;
use crate::host::HostIdentity;
use std::sync::OnceLock;

const STYLE_TEMPLATE: &str = r#"
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
  :root:not([data-theme="light"]) {
@@DARK@@
  }
}
:root[data-theme="dark"] {
@@DARK@@
  color-scheme: dark;
}
:root[data-theme="light"] { color-scheme: light; }
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

.app-shell { display: grid; grid-template-columns: 240px minmax(0, 1fr); min-height: 100vh; }
/* The sidebar keeps the dark surface in both themes, like the login panel. */
aside {
  display: flex; flex-direction: column; gap: 1.25rem; padding: 1.4rem 1rem;
  background: #14161c; color: #c4c9d4; border-right: 1px solid #24272f;
  position: sticky; top: 0; height: 100vh; overflow-y: auto;
}
.brand { display: flex; align-items: center; gap: 0.65rem; padding: 0 0.4rem; }
.brand-logo { width: 34px; height: 34px; object-fit: contain; flex-shrink: 0; }
.brand-text { display: grid; line-height: 1.2; }
.brand-name { font-weight: 700; font-size: 0.9rem; letter-spacing: 0.06em; color: #eef0f4; }
.brand-sub { font-size: 0.7rem; color: #8b91a1; }
.host-chip {
  display: grid; gap: 0.1rem; padding: 0.7rem 0.8rem; border-radius: var(--radius-sm);
  background: rgb(255 255 255 / 5%); border: 1px solid rgb(255 255 255 / 8%);
}
.host-chip strong { font-size: 0.88rem; color: #eef0f4; overflow-wrap: anywhere; }
.host-chip small { font-size: 0.74rem; color: #8b91a1; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; overflow-wrap: anywhere; }

.nav-groups { display: flex; flex-direction: column; gap: 1rem; overflow-y: auto; }
.nav-group-label {
  margin: 0 0 0.3rem 0.65rem; color: #6b7184; font-size: 0.66rem;
  font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em;
}
nav { display: grid; gap: 2px; }
nav a {
  display: flex; align-items: center; gap: 0.6rem; padding: 0.55rem 0.65rem; border-radius: var(--radius-sm);
  color: #c4c9d4; font-size: 0.85rem; font-weight: 500; text-decoration: none;
  transition: background-color var(--transition), color var(--transition);
}
nav a .icon { width: 16px; height: 16px; flex-shrink: 0; opacity: 0.9; }
nav a:hover { color: #eef0f4; background: rgb(255 255 255 / 6%); }
nav a.active { color: #eef0f4; background: rgb(167 139 250 / 18%); font-weight: 600; }
nav a.active .icon { color: #c4b5fd; opacity: 1; }

.sidebar-foot { margin-top: auto; display: grid; gap: 0.6rem; padding-top: 0.9rem; border-top: 1px solid #24272f; }
.sidebar-user { display: flex; align-items: center; gap: 0.6rem; margin: 0; padding: 0.3rem 0.4rem; min-width: 0; }
.sidebar-avatar {
  display: grid; place-items: center; width: 30px; height: 30px; border-radius: 999px; flex-shrink: 0;
  background: #2b2450; color: #d8cbff; font-size: 0.75rem; font-weight: 700; text-transform: uppercase;
}
.sidebar-user-text { display: grid; min-width: 0; line-height: 1.25; }
.sidebar-user-text strong { font-size: 0.84rem; color: #eef0f4; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.sidebar-user-text small { font-size: 0.7rem; color: #8b91a1; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.sidebar-tools { display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; }
.sidebar-foot form { margin: 0; max-width: none; }
.sidebar-foot .logout {
  display: inline-flex; align-items: center; gap: 0.4rem; padding: 0.45rem 0.7rem; border-radius: var(--radius-sm);
  color: #8b91a1; background: transparent; border: 1px solid transparent; font: inherit; font-size: 0.8rem; cursor: pointer;
  transition: background-color var(--transition), color var(--transition);
}
.sidebar-foot .logout:hover { color: #eef0f4; background: rgb(255 255 255 / 6%); }
aside .theme-switch { background: rgb(255 255 255 / 5%); border-color: rgb(255 255 255 / 8%); }
aside .theme-switch button { color: #8b91a1; }
aside .theme-switch button:hover { color: #eef0f4; }
aside .theme-switch button[aria-pressed="true"] { background: rgb(255 255 255 / 10%); color: #c4b5fd; box-shadow: none; }

.content { min-width: 0; max-width: 74rem; width: 100%; margin: 0 auto; padding: 1.9rem 2.25rem 4rem; }
.content > header { display: flex; align-items: flex-end; justify-content: space-between; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.4rem; }
.content > header .heading { display: grid; gap: 0.25rem; min-width: 0; }
.content > header h1 { margin: 0; font-size: 1.6rem; letter-spacing: -0.02em; }
.content > header .subtitle { margin: 0; color: var(--text-secondary); font-size: 0.86rem; }
.header-actions { display: flex; align-items: center; gap: 0.6rem; flex-wrap: wrap; }
.header-actions form { margin: 0; max-width: none; display: inline; }
.button, .header-actions button, .row-actions button, .dialog-actions button, .dialog-actions .button-link {
  display: inline-flex; align-items: center; justify-content: center; gap: 0.4rem; min-height: 38px; padding: 0 0.9rem;
  border: 1px solid var(--border); border-radius: var(--radius-sm); background: var(--color-surface); color: var(--text-secondary);
  font: inherit; font-size: 0.82rem; font-weight: 600; cursor: pointer; text-decoration: none; white-space: nowrap;
  transition: border-color var(--transition), color var(--transition), background-color var(--transition);
}
.button:hover, .header-actions button:hover, .row-actions button:hover { color: var(--accent); border-color: var(--accent); }
.button.primary, .header-actions button.primary, .dialog-actions button[type="submit"] {
  border: 0; background: var(--accent-strong); color: #fff; box-shadow: 0 6px 16px rgb(109 40 217 / 20%);
}
.button.primary:hover, .header-actions button.primary:hover, .dialog-actions button[type="submit"]:hover { color: #fff; filter: brightness(1.08); }
.row-actions { display: flex; justify-content: flex-end; gap: 0.35rem; flex-wrap: wrap; }
.row-actions form { display: inline; margin: 0; max-width: none; }
.row-actions button { min-height: 32px; padding: 0 0.7rem; font-size: 0.76rem; }

/* Panels: a white card with its own header, used by the overview and lists. */
.grid-2 { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0.9rem; margin: 0 0 0.9rem; }
.grid-4 { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 0.9rem; margin: 0 0 0.9rem; }
.panel { padding: 1.1rem 1.25rem; border: 1px solid var(--border); border-radius: var(--radius-lg); background: var(--color-surface); box-shadow: var(--shadow-sm); min-width: 0; }
.panel-head { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; margin: 0 0 0.6rem; }
.panel-head h3 { margin: 0; font-size: 0.95rem; }
.panel-head a { font-size: 0.8rem; font-weight: 600; }
.tile { display: grid; gap: 0.5rem; padding: 1.1rem 1.25rem; border: 1px solid var(--border); border-radius: var(--radius-lg); background: var(--color-surface); box-shadow: var(--shadow-sm); min-width: 0; }
.tile-label { font-size: 0.74rem; font-weight: 600; color: var(--text-muted); }
.tile-value { font-size: 1.75rem; font-weight: 700; letter-spacing: -0.02em; color: var(--text-primary); line-height: 1.1; overflow-wrap: anywhere; }
.tile-value small { font-size: 0.95rem; font-weight: 500; color: var(--text-muted); }
.tile-value.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 1.3rem; }
.tile-foot { font-size: 0.74rem; color: var(--text-muted); }
.kv { display: grid; }
.kv-row { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; padding: 0.55rem 0; border-top: 1px solid var(--border-subtle); font-size: 0.84rem; }
.kv-row:first-child { border-top: 0; }
.kv-row .k { display: inline-flex; align-items: center; gap: 0.6rem; color: var(--text-primary); min-width: 0; }
.kv-row .v { color: var(--text-secondary); font-size: 0.8rem; text-align: right; }
.dot { width: 8px; height: 8px; border-radius: 999px; background: var(--success-text); flex-shrink: 0; }
.dot.off { background: var(--danger-text); }
.dot.warn { background: #d97706; }
.activity { display: grid; grid-template-columns: 4rem minmax(0, 1fr) auto; font-size: 0.84rem; }
.activity > span { padding: 0.5rem 0; border-top: 1px solid var(--border-subtle); }
.activity .t { color: var(--text-muted); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.78rem; }
.activity .who { color: var(--text-muted); text-align: right; white-space: nowrap; }
.empty { margin: 0; padding: 1.25rem; border: 1px dashed var(--border); border-radius: var(--radius-md); color: var(--text-muted); font-size: 0.84rem; text-align: center; }

/* Notices: one component, three levels, technical detail collapsed. */
.notice { display: grid; gap: 0.35rem; padding: 0.75rem 0.95rem; border-radius: var(--radius-sm); background: var(--accent-soft-bg); color: var(--accent-soft-text); font-size: 0.86rem; margin: 0 0 1rem; }
.notice.success { background: var(--success-bg); color: var(--success-text); }
.notice.warn { background: #fdf1dc; color: #8a4b00; }
.notice.error { background: var(--danger-bg); color: var(--danger-text); }
.notice details { font-size: 0.76rem; }
.notice summary { cursor: pointer; font-weight: 600; }
.notice code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.72rem; overflow-wrap: anywhere; }
:root[data-theme="dark"] .notice.warn { background: #3a2a10; color: #f5c06b; }
@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) .notice.warn { background: #3a2a10; color: #f5c06b; } }

/* Confirmation dialog: a page that looks like a modal over the shell. */
.dialog { width: min(30rem, 100%); margin: 2rem auto; padding: 1.6rem 1.75rem; border: 1px solid var(--border); border-radius: var(--radius-lg); background: var(--color-surface); box-shadow: var(--shadow-lg); display: grid; gap: 1.1rem; }
.dialog-icon { display: grid; place-items: center; width: 42px; height: 42px; border-radius: var(--radius-md); background: var(--accent-soft-bg); color: var(--accent-soft-text); }
.dialog-icon .icon { width: 20px; height: 20px; }
.dialog h2 { margin: 0 0 0.3rem; font-size: 1.15rem; letter-spacing: -0.01em; }
.dialog-summary { margin: 0; color: var(--text-secondary); font-size: 0.86rem; line-height: 1.5; }
.dialog form { max-width: none; margin: 0; gap: 0.9rem; }
.dialog-meta { margin: 0; color: var(--text-muted); font-size: 0.76rem; }
.dialog-meta code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.72rem; }
.dialog-actions { display: flex; justify-content: flex-end; gap: 0.6rem; }

@media (max-width: 60rem) {
  .grid-4 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .grid-2 { grid-template-columns: 1fr; }
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

.theme-switch { display: inline-flex; gap: 2px; padding: 3px; border-radius: 999px; background: var(--color-inset); border: 1px solid var(--border-subtle); }
.theme-switch button {
  width: 32px; height: 28px; display: inline-flex; align-items: center; justify-content: center; border: 0; border-radius: 999px;
  background: transparent; color: var(--text-muted); cursor: pointer; transition: background-color var(--transition), color var(--transition);
}
.theme-switch button:hover { color: var(--text-primary); }
.theme-switch button[aria-pressed="true"] { background: var(--color-surface); color: var(--accent); box-shadow: var(--shadow-sm); }
.sidebar-foot .theme-switch { justify-self: start; margin: 0 0.3rem 0.2rem; }
.auth-top { display: flex; justify-content: flex-end; align-items: center; gap: 0.75rem; flex-wrap: wrap; }

/* Login: machine panel on the left, form on the right. The panel keeps the
   dark surface in both themes; the form side follows the theme tokens. */
.auth-shell { min-height: 100vh; display: grid; grid-template-columns: minmax(20rem, 38%) minmax(0, 1fr); background: var(--color-canvas); }
.auth-panel {
  display: flex; flex-direction: column; justify-content: space-between; gap: 2rem; padding: 3rem;
  background: #14161c; color: #eef0f4; border-right: 1px solid #24272f;
  background-image: linear-gradient(rgb(255 255 255 / 3.5%) 1px, transparent 1px), linear-gradient(90deg, rgb(255 255 255 / 3.5%) 1px, transparent 1px);
  background-size: 48px 48px;
}
.auth-brand { display: flex; align-items: center; gap: 0.85rem; font-weight: 700; font-size: 1.25rem; letter-spacing: 0.06em; }
.auth-brand img { width: 48px; height: 48px; object-fit: contain; }
.auth-host { display: flex; flex-direction: column; gap: 1.75rem; }
.auth-kicker { margin: 0 0 0.6rem; color: #a78bfa; font-size: 0.7rem; font-weight: 700; letter-spacing: 0.09em; text-transform: uppercase; }
.auth-host h2 { margin: 0; font-size: clamp(2rem, 4vw, 3rem); line-height: 1.05; letter-spacing: -0.02em; color: #eef0f4; overflow-wrap: anywhere; }
.auth-ip { margin: 0.5rem 0 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 1.3rem; font-weight: 500; color: #eef0f4; overflow-wrap: anywhere; }
.auth-edition { margin: 0.4rem 0 0; color: #c4c9d4; font-size: 0.95rem; }
.host-cards { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0.75rem; }
.host-card { display: flex; flex-direction: column; gap: 0.35rem; padding: 0.85rem 1rem; border-radius: var(--radius-md); background: rgb(255 255 255 / 5%); border: 1px solid rgb(255 255 255 / 8%); }
.host-card small { color: #8b91a1; font-size: 0.75rem; }
.host-card strong { display: inline-flex; align-items: center; gap: 0.5rem; font-size: 0.9rem; font-weight: 600; color: #eef0f4; overflow-wrap: anywhere; }
.host-dot { width: 8px; height: 8px; border-radius: 999px; background: #9fdcbb; flex-shrink: 0; }
.host-dot.off { background: #ffb0bc; }
.auth-foot { display: flex; align-items: center; gap: 0.6rem; margin: 0; color: #8b91a1; font-size: 0.8rem; }
.auth-main { display: flex; flex-direction: column; justify-content: space-between; gap: 2rem; padding: 2.5rem 3rem; min-width: 0; }
.auth-lang { display: flex; justify-content: flex-end; align-items: center; gap: 0.5rem; margin: 0; max-width: none; }
.auth-lang label { display: inline-flex; align-items: center; gap: 0.5rem; font-size: 0.8rem; }
.auth-lang select { width: auto; min-height: 40px; padding: 0.45rem 2rem 0.45rem 0.75rem; }
.auth-lang button[type="submit"] { min-height: 40px; padding: 0.45rem 0.8rem; }
.auth-card { width: min(26rem, 100%); margin: 0 auto; display: flex; flex-direction: column; gap: 1.75rem; }
.auth-card h1 { margin: 0; font-size: 2.1rem; line-height: 1.1; letter-spacing: -0.02em; overflow-wrap: anywhere; }
.auth-subtitle { margin: 0.6rem 0 0; font-size: 0.95rem; line-height: 1.55; color: var(--text-secondary); }
.auth-subtitle code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.82rem; padding: 0.1rem 0.4rem; border-radius: 6px; background: var(--accent-soft-bg); color: var(--accent-soft-text); }
.auth-card form { max-width: none; margin: 0; gap: 1rem; }
.auth-card .error { margin: 0; border: 1px solid color-mix(in srgb, var(--danger-text) 24%, transparent); }
.field { display: grid; gap: 0.4rem; }
.field label { font-size: 0.8rem; font-weight: 600; color: var(--text-secondary); }
.field-input { position: relative; display: flex; align-items: center; }
.field-input > svg { position: absolute; left: 0.9rem; color: var(--text-muted); pointer-events: none; }
.field-input input { min-height: 48px; padding: 0.7rem 0.9rem 0.7rem 2.65rem; border-radius: 12px; font-size: 0.95rem; }
.field-input input.has-peek { padding-right: 3rem; }
.peek {
  position: absolute; right: 0.3rem; width: 40px; height: 40px; display: inline-flex; align-items: center; justify-content: center;
  border: 0; border-radius: 10px; background: transparent; color: var(--text-muted);
}
.peek:hover { color: var(--accent); background: var(--surface-hover); }
.auth-card button[type="submit"] {
  width: 100%; min-height: 50px; justify-self: stretch; margin-top: 0.4rem; text-align: center; border-radius: 12px;
  font-size: 0.95rem; box-shadow: 0 8px 24px rgb(109 40 217 / 22%);
}
.auth-card button[type="submit"]:active { transform: translateY(1px); }
.auth-notes { display: grid; gap: 0.6rem; padding-top: 0.5rem; border-top: 1px solid var(--border-subtle); }
.auth-notes p { margin: 0; color: var(--text-muted); font-size: 0.8rem; line-height: 1.5; }
.auth-notes code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.75rem; padding: 0.1rem 0.4rem; border-radius: 6px; background: var(--color-inset); color: var(--text-secondary); }
.auth-footnote { margin: 0; text-align: center; color: var(--text-muted); font-size: 0.75rem; }
@media (max-width: 52rem) {
  .auth-shell { grid-template-columns: 1fr; }
  .auth-panel { padding: 3.5rem 1.5rem 1.75rem; border-right: 0; border-radius: 0 0 28px 28px; gap: 1.25rem; }
  .auth-host { gap: 1rem; }
  .host-cards { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .auth-main { padding: 1.75rem 1rem 1.25rem; }
  .auth-lang { justify-content: flex-start; }
  .auth-card h1 { font-size: 1.6rem; }
  .field-input input { font-size: 1rem; }
}
"#;

/// The dark tokens, applied by the system preference unless the visitor chose
/// light, and always when the visitor chose dark.
const DARK_TOKENS: &str = r#"    --color-canvas: #0f1115;
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
    --shadow-lg: 0 24px 60px rgb(0 0 0 / 45%);"#;

fn style() -> &'static str {
    static STYLE: OnceLock<String> = OnceLock::new();
    STYLE.get_or_init(|| STYLE_TEMPLATE.replace("@@DARK@@", DARK_TOKENS))
}

/// Runs before the stylesheet applies so a chosen theme never flashes.
const THEME_BOOT: &str = r#"<script>(function(){try{var t=localStorage.getItem("vega-theme");if(t==="dark"||t==="light"){document.documentElement.setAttribute("data-theme",t);}}catch(e){}})();</script>"#;

/// Wires every theme switch on the page; the choice lives in the browser.
const THEME_WIRE: &str = r#"<script>
(function(){
  function apply(value){
    try{ if(value==="system"){localStorage.removeItem("vega-theme");}else{localStorage.setItem("vega-theme",value);} }catch(e){}
    if(value==="system"){document.documentElement.removeAttribute("data-theme");}else{document.documentElement.setAttribute("data-theme",value);}
    document.querySelectorAll("[data-theme-choice]").forEach(function(b){b.setAttribute("aria-pressed",b.getAttribute("data-theme-choice")===value?"true":"false");});
  }
  var current=document.documentElement.getAttribute("data-theme")||"system";
  document.querySelectorAll("[data-theme-choice]").forEach(function(b){
    b.setAttribute("aria-pressed",b.getAttribute("data-theme-choice")===current?"true":"false");
    b.addEventListener("click",function(){apply(b.getAttribute("data-theme-choice"));});
  });
})();
</script>"#;

/// Three-way theme switch: system (default), light, dark.
fn theme_switch(lang: LoginLang) -> String {
    let t = |pt: &'static str, en: &'static str, es: &'static str| lang.text(pt, en, es);
    format!(
        r#"<div class="theme-switch" role="group" aria-label="{label}">
<button type="button" data-theme-choice="system" aria-pressed="false" title="{system}" aria-label="{system}"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="2" y="4" width="20" height="13" rx="2"></rect><path d="M8 21h8M12 17v4"></path></svg></button>
<button type="button" data-theme-choice="light" aria-pressed="false" title="{light}" aria-label="{light}"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"></circle><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"></path></svg></button>
<button type="button" data-theme-choice="dark" aria-pressed="false" title="{dark}" aria-label="{dark}"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"></path></svg></button>
</div>"#,
        label = t("Tema", "Theme", "Tema"),
        system = t("Tema do sistema", "System theme", "Tema del sistema"),
        light = t("Tema claro", "Light theme", "Tema claro"),
        dark = t("Tema escuro", "Dark theme", "Tema oscuro"),
    )
}

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
                label: "Visão geral",
                icon: "dashboard",
            },
            NavItem {
                href: "/software",
                label: "Software",
                icon: "software",
            },
        ],
    },
    NavGroup {
        label: "Sistema",
        items: &[
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
                href: "/rede",
                label: "Rede e Firewall",
                icon: "network",
            },
            NavItem {
                href: "/data-hora",
                label: "Data e Hora",
                icon: "datetime",
            },
            NavItem {
                href: "/hardware",
                label: "Hardware e Kernel",
                icon: "hardware",
            },
        ],
    },
    NavGroup {
        label: "Dados",
        items: &[
            NavItem {
                href: "/armazenamento",
                label: "Armazenamento",
                icon: "storage",
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
        label: "Diagnóstico",
        items: &[
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
                href: "/terminal",
                label: "Terminal",
                icon: "terminal",
            },
        ],
    },
];

pub fn page(title: &str, active_href: &str, user: &crate::auth::CurrentUser, body: &str) -> String {
    page_with(title, active_href, user, "", "", body)
}

/// The shell with an optional context line under the title and primary
/// actions on the right of the header (already-rendered HTML).
pub fn page_with(
    title: &str,
    active_href: &str,
    user: &crate::auth::CurrentUser,
    subtitle: &str,
    actions: &str,
    body: &str,
) -> String {
    let username = crate::pages::html_escape(&user.name);
    let address = crate::pages::html_escape(&user.address);
    let initial = crate::pages::html_escape(
        &user
            .name
            .chars()
            .next()
            .map(|c| c.to_string())
            .unwrap_or_default(),
    );
    let host = crate::host::identity();
    let hostname = crate::pages::html_escape(&host.hostname);
    let host_address = crate::pages::html_escape(&host.addresses.join(" · "));
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
    let subtitle_html = if subtitle.is_empty() {
        String::new()
    } else {
        format!(r#"<p class="subtitle">{subtitle}</p>"#)
    };
    let actions_html = if actions.is_empty() {
        String::new()
    } else {
        format!(r#"<div class="header-actions">{actions}</div>"#)
    };

    format!(
        r#"<!doctype html>
<html lang="pt-br">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · {hostname} · Vega</title>
{THEME_BOOT}
<style>{style}</style>
</head>
<body>
<div class="app-shell">
<aside>
<div class="brand"><img class="brand-logo" src="/assets/lyra-logo.png" alt=""><span class="brand-text"><span class="brand-name">LYRA OS</span><span class="brand-sub">Vega · painel</span></span></div>
<div class="host-chip"><strong>{hostname}</strong><small>{host_address}</small></div>
<div class="nav-groups">{nav_groups}</div>
<div class="sidebar-foot">
<p class="sidebar-user"><span class="sidebar-avatar" aria-hidden="true">{initial}</span><span class="sidebar-user-text"><strong>{username}</strong><small>{address}</small></span></p>
<div class="sidebar-tools">
{theme_switch}
<form method="post" action="/logout"><button type="submit" class="logout">{ICON_LOGOUT}Sair</button></form>
</div>
</div>
</aside>
<div class="content">
<header><div class="heading"><h1>{title}</h1>{subtitle_html}</div>{actions_html}</header>
{body}
</div>
</div>
{THEME_WIRE}
</body>
</html>"#,
        theme_switch = theme_switch(LoginLang::Pt),
        style = style(),
    )
}

const ICON_LOGOUT: &str = r#"<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"></path></svg>"#;

const LYRA_LOGO: &[u8] = include_bytes!("../assets/lyra-logo-256.png");

/// The Lyra OS logo, public because the login page shows it.
pub async fn lyra_logo() -> axum::response::Response {
    use axum::http::{HeaderValue, StatusCode, header};
    use axum::response::IntoResponse;
    let mut response = (StatusCode::OK, LYRA_LOGO).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("image/png"));
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=86400"),
    );
    response
}

fn escape(input: &str) -> String {
    crate::pages::html_escape(input)
}

const ICON_USER: &str = r#"<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="8" r="4"></circle><path d="M4 21a8 8 0 0 1 16 0"></path></svg>"#;
const ICON_LOCK: &str = r#"<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="11" width="18" height="11" rx="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>"#;
const ICON_EYE: &str = r#"<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"></path><circle cx="12" cy="12" r="3"></circle></svg>"#;

/// The login page: the machine on the left (name, addresses, edition and two
/// facts read without the daemon), the form on the right. `host` is read per
/// request so the page always names the machine that serves it.
pub fn login_page(error: Option<&str>, lang: LoginLang, host: &HostIdentity) -> String {
    let t = |pt: &'static str, en: &'static str, es: &'static str| lang.text(pt, en, es);
    let error_html = error
        .map(|message| format!(r#"<p class="error" role="alert">{}</p>"#, escape(message)))
        .unwrap_or_default();
    let hostname = escape(&host.hostname);
    let addresses = if host.addresses.is_empty() {
        String::new()
    } else {
        format!(
            r#"<p class="auth-ip">{}</p>"#,
            host.addresses
                .iter()
                .map(|address| escape(address))
                .collect::<Vec<_>>()
                .join(" · ")
        )
    };
    let edition = if host.edition.is_empty() {
        escape(host.arch)
    } else {
        format!("{} · {}", escape(&host.edition), escape(host.arch))
    };
    let secure_boot = match host.secure_boot {
        Some(true) => format!(
            r#"<div class="host-card"><small>Secure Boot</small><strong><span class="host-dot" aria-hidden="true"></span>{}</strong></div>"#,
            t("Ativo", "Enabled", "Activo")
        ),
        Some(false) => format!(
            r#"<div class="host-card"><small>Secure Boot</small><strong><span class="host-dot off" aria-hidden="true"></span>{}</strong></div>"#,
            t("Inativo", "Disabled", "Inactivo")
        ),
        None => String::new(),
    };
    let kernel = if host.kernel.is_empty() {
        String::new()
    } else {
        format!(
            r#"<div class="host-card"><small>Kernel</small><strong>{}</strong></div>"#,
            escape(&host.kernel)
        )
    };
    let option = |code: &str, label: &str| {
        format!(
            r#"<option value="{code}"{}>{label}</option>"#,
            if code == lang.code() { " selected" } else { "" }
        )
    };
    let options = [
        option("pt-BR", "Português (Brasil)"),
        option("en-US", "English (US)"),
        option("es-ES", "Español (España)"),
    ]
    .concat();

    format!(
        r#"<!doctype html>
<html lang="{lang_code}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} {hostname} · Vega</title>
{THEME_BOOT}
<style>{style}</style>
</head>
<body>
<div class="auth-shell">
<aside class="auth-panel">
<div class="auth-brand"><img src="/assets/lyra-logo.png" alt="Lyra OS"><span>LYRA OS</span></div>
<div class="auth-host">
<div>
<p class="auth-kicker">{this_machine}</p>
<h2>{hostname}</h2>
{addresses}
<p class="auth-edition">{edition}</p>
</div>
<div class="host-cards">{secure_boot}{kernel}</div>
</div>
<p class="auth-foot">{ICON_LOCK}<span>{security_line}</span></p>
</aside>
<main class="auth-main">
<div class="auth-top">
{theme_switch}
<form class="auth-lang" method="get" action="/login">
<label>{language}<select name="lang">{options}</select></label>
<button type="submit">OK</button>
</form>
</div>
<div class="auth-card">
<div>
<h1>{title} {hostname}</h1>
<p class="auth-subtitle">{subtitle_before} <code>wheel</code> {subtitle_after}</p>
</div>
{error_html}
<form method="post" action="/login">
<input type="hidden" name="lang" value="{lang_code}">
<div class="field">
<label for="username">{user}</label>
<div class="field-input">{ICON_USER}<input id="username" type="text" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" autofocus required></div>
</div>
<div class="field">
<label for="password">{password}</label>
<div class="field-input">{ICON_LOCK}<input id="password" class="has-peek" type="password" name="password" autocomplete="current-password" required><button type="button" class="peek" data-peek aria-label="{show_hide}">{ICON_EYE}</button></div>
</div>
<button type="submit">{enter}</button>
</form>
<div class="auth-notes">
<p>{note_pam}</p>
<p>{note_console_before} <code>vega</code> {note_console_after}</p>
</div>
</div>
<p class="auth-footnote">Vega {version} · Lyra OS · <a href="https://lyraos.com.br/docs/server.html">{docs}</a></p>
</main>
</div>
<script>
document.querySelectorAll("[data-peek]").forEach(function (button) {{
  button.addEventListener("click", function () {{
    var input = document.getElementById("password");
    input.type = input.type === "password" ? "text" : "password";
    input.focus();
  }});
}});
</script>
{THEME_WIRE}
</body>
</html>"#,
        lang_code = lang.code(),
        theme_switch = theme_switch(lang),
        style = style(),
        version = env!("CARGO_PKG_VERSION"),
        title = t("Entrar em", "Sign in to", "Entrar en"),
        this_machine = t("Esta máquina", "This machine", "Esta máquina"),
        security_line = t(
            "Conexão TLS · autenticação pelo PAM do sistema · somente administradores",
            "TLS connection · system PAM authentication · administrators only",
            "Conexión TLS · autenticación PAM del sistema · solo administradores"
        ),
        language = t("Idioma", "Language", "Idioma"),
        subtitle_before = t(
            "Use sua conta do sistema. Só membros do grupo",
            "Use your system account. Only members of the",
            "Use su cuenta del sistema. Solo los miembros del grupo"
        ),
        subtitle_after = t(
            "podem administrar esta máquina.",
            "group can administer this machine.",
            "pueden administrar esta máquina."
        ),
        user = t("Usuário", "Username", "Usuario"),
        password = t("Senha", "Password", "Contraseña"),
        show_hide = t(
            "Mostrar ou ocultar a senha",
            "Show or hide the password",
            "Mostrar u ocultar la contraseña"
        ),
        enter = t("Entrar", "Sign in", "Entrar"),
        note_pam = t(
            "A senha é verificada pelo PAM e nunca fica guardada no navegador. Depois de entrar, cada ação administrativa pede a senha de novo.",
            "The password is checked by PAM and never stored in the browser. After signing in, every administrative action asks for it again.",
            "La contraseña la verifica PAM y nunca se guarda en el navegador. Tras entrar, cada acción administrativa vuelve a pedirla."
        ),
        note_console_before = t(
            "Sem acesso? Use o console:",
            "No access? Use the console:",
            "¿Sin acceso? Use la consola:"
        ),
        note_console_after = t("no terminal.", "in a terminal.", "en una terminal."),
        docs = t(
            "Documentação do Server",
            "Server documentation",
            "Documentación del Server"
        ),
    )
}
