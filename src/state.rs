use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::FromRef;
use axum_extra::extract::cookie::Key;
use lyra_vega_dbus::VegaDbus;
use tokio::sync::Semaphore;

use crate::auth::Authenticator;

pub const SESSION_COOKIE: &str = "vega_web_session";

#[derive(Clone, Default)]
pub struct TerminalGrants(Arc<Mutex<HashMap<String, Instant>>>);

impl TerminalGrants {
    pub fn grant(&self, session: String, until: Instant) {
        self.0.lock().unwrap().insert(session, until);
    }

    pub fn valid(&self, session: &str, now: Instant) -> bool {
        let mut grants = self.0.lock().unwrap();
        grants.retain(|_, until| *until > now);
        grants.get(session).is_some_and(|until| *until > now)
    }

    pub fn consume(&self, session: &str, now: Instant) -> bool {
        let mut grants = self.0.lock().unwrap();
        grants.retain(|_, until| *until > now);
        grants.remove(session).is_some_and(|until| until > now)
    }
}

#[derive(Clone, Copy)]
pub struct SessionPolicy {
    pub idle_timeout: Duration,
    pub absolute_timeout: Duration,
    pub global_limit: usize,
    pub per_user_limit: usize,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(30 * 60),
            absolute_timeout: Duration::from_secs(12 * 60 * 60),
            global_limit: 1024,
            per_user_limit: 10,
        }
    }
}

pub struct Session {
    pub username: String,
    created_at: Instant,
    last_seen: Instant,
}

impl Session {
    pub fn new(username: String, now: Instant) -> Self {
        Self {
            username,
            created_at: now,
            last_seen: now,
        }
    }

    fn expired(&self, now: Instant, policy: SessionPolicy) -> bool {
        now.duration_since(self.created_at) >= policy.absolute_timeout
            || now.duration_since(self.last_seen) >= policy.idle_timeout
    }
}

struct Sessions {
    values: HashMap<String, Session>,
    policy: SessionPolicy,
}

#[derive(Clone)]
pub struct SessionStore(Arc<Mutex<Sessions>>);

impl SessionStore {
    pub fn new(policy: SessionPolicy) -> Self {
        Self(Arc::new(Mutex::new(Sessions {
            values: HashMap::new(),
            policy,
        })))
    }

    pub fn insert(&self, token: String, session: Session) {
        let mut store = self.0.lock().unwrap();
        let now = session.created_at;
        remove_expired(&mut store, now);
        while store
            .values
            .values()
            .filter(|value| value.username == session.username)
            .count()
            >= store.policy.per_user_limit
        {
            remove_oldest(&mut store, Some(&session.username));
        }
        while store.values.len() >= store.policy.global_limit {
            remove_oldest(&mut store, None);
        }
        store.values.insert(token, session);
    }

    pub fn username_for(&self, token: &str, now: Instant) -> Option<String> {
        let mut store = self.0.lock().unwrap();
        remove_expired(&mut store, now);
        let session = store.values.get_mut(token)?;
        session.last_seen = now;
        Some(session.username.clone())
    }

    pub fn remove(&self, token: &str) {
        self.0.lock().unwrap().values.remove(token);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.0.lock().unwrap().values.len()
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new(SessionPolicy::default())
    }
}

fn remove_expired(store: &mut Sessions, now: Instant) {
    let policy = store.policy;
    store.values.retain(|_, value| !value.expired(now, policy));
}

fn remove_oldest(store: &mut Sessions, username: Option<&str>) {
    let oldest = store
        .values
        .iter()
        .filter(|(_, value)| username.is_none_or(|name| value.username == name))
        .min_by_key(|(_, value)| value.last_seen)
        .map(|(token, _)| token.clone());
    if let Some(token) = oldest {
        store.values.remove(&token);
    }
}

#[derive(Clone, Copy)]
pub struct LoginPolicy {
    pub attempts: u32,
    pub recovery: Duration,
    pub base_delay: Duration,
    pub max_delay: Duration,
}

impl Default for LoginPolicy {
    fn default() -> Self {
        Self {
            attempts: 5,
            recovery: Duration::from_secs(15 * 60),
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(30),
        }
    }
}

#[derive(Clone, Copy)]
struct Attempt {
    failures: u32,
    last_failure: Instant,
    blocked_until: Instant,
}

#[derive(Clone)]
pub struct LoginLimiter {
    attempts: Arc<Mutex<HashMap<String, Attempt>>>,
    policy: LoginPolicy,
}

impl LoginLimiter {
    pub fn new(policy: LoginPolicy) -> Self {
        Self {
            attempts: Arc::new(Mutex::new(HashMap::new())),
            policy,
        }
    }

    pub fn check(&self, ip: &str, username: &str, now: Instant) -> Option<Duration> {
        let mut attempts = self.attempts.lock().unwrap();
        attempts.retain(|_, value| now.duration_since(value.last_failure) < self.policy.recovery);
        [
            format!("ip:{ip}"),
            format!("user:{}", username.to_lowercase()),
        ]
        .into_iter()
        .filter_map(|key| attempts.get(&key))
        .filter(|value| value.blocked_until > now)
        .map(|value| value.blocked_until.duration_since(now))
        .max()
    }

    pub fn failure(&self, ip: &str, username: &str, now: Instant) -> Duration {
        let mut attempts = self.attempts.lock().unwrap();
        let mut delay = Duration::ZERO;
        for key in [
            format!("ip:{ip}"),
            format!("user:{}", username.to_lowercase()),
        ] {
            let value = attempts.entry(key).or_insert(Attempt {
                failures: 0,
                last_failure: now,
                blocked_until: now,
            });
            if now.duration_since(value.last_failure) >= self.policy.recovery {
                value.failures = 0;
            }
            value.failures += 1;
            value.last_failure = now;
            let multiplier = value.failures.min(16);
            let progressive = self.policy.base_delay.saturating_mul(multiplier);
            delay = delay.max(progressive.min(self.policy.max_delay));
            if value.failures >= self.policy.attempts {
                value.blocked_until = now + delay;
            }
        }
        delay
    }

    pub fn success(&self, ip: &str, username: &str) {
        let mut attempts = self.attempts.lock().unwrap();
        attempts.remove(&format!("ip:{ip}"));
        attempts.remove(&format!("user:{}", username.to_lowercase()));
    }
}

#[derive(Clone)]
pub struct AppState {
    pub dbus: VegaDbus,
    pub sessions: SessionStore,
    pub cookie_key: Key,
    pub authenticator: Arc<dyn Authenticator>,
    pub login_limiter: LoginLimiter,
    pub pam_slots: Arc<Semaphore>,
    pub terminal_grants: TerminalGrants,
    pub terminal_slots: Arc<Semaphore>,
}

impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.cookie_key.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sessions_expire_and_obey_limits() {
        let now = Instant::now();
        let store = SessionStore::new(SessionPolicy {
            idle_timeout: Duration::from_secs(5),
            absolute_timeout: Duration::from_secs(20),
            global_limit: 2,
            per_user_limit: 1,
        });
        store.insert("a".into(), Session::new("alice".into(), now));
        store.insert(
            "b".into(),
            Session::new("alice".into(), now + Duration::from_secs(1)),
        );
        assert_eq!(store.len(), 1);
        assert!(
            store
                .username_for("a", now + Duration::from_secs(1))
                .is_none()
        );
        assert_eq!(
            store
                .username_for("b", now + Duration::from_secs(2))
                .as_deref(),
            Some("alice")
        );
        assert!(
            store
                .username_for("b", now + Duration::from_secs(8))
                .is_none()
        );
        store.insert("c".into(), Session::new("bob".into(), now));
        store.remove("c");
        assert_eq!(store.len(), 0);

        let absolute = SessionStore::new(SessionPolicy {
            idle_timeout: Duration::from_secs(100),
            absolute_timeout: Duration::from_secs(5),
            global_limit: 2,
            per_user_limit: 2,
        });
        absolute.insert("token".into(), Session::new("alice".into(), now));
        assert!(
            absolute
                .username_for("token", now + Duration::from_secs(6))
                .is_none()
        );
    }

    #[test]
    fn limiter_isolates_origins_and_recovers() {
        let now = Instant::now();
        let limiter = LoginLimiter::new(LoginPolicy {
            attempts: 2,
            recovery: Duration::from_secs(10),
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(5),
        });
        limiter.failure("10.0.0.1", "alice", now);
        limiter.failure("10.0.0.1", "alice", now);
        assert!(limiter.check("10.0.0.1", "alice", now).is_some());
        assert!(limiter.check("10.0.0.2", "bob", now).is_none());
        assert!(
            limiter
                .check("10.0.0.1", "alice", now + Duration::from_secs(11))
                .is_none()
        );
        limiter.success("10.0.0.1", "alice");
        assert!(limiter.check("10.0.0.1", "alice", now).is_none());
    }
}
