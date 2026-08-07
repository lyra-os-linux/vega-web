use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::FromRef;
use axum_extra::extract::cookie::Key;
use lyra_vega_dbus::VegaDbus;

pub const SESSION_COOKIE: &str = "vega_web_session";

pub struct Session {
    pub username: String,
}

#[derive(Clone, Default)]
pub struct SessionStore(Arc<Mutex<HashMap<String, Session>>>);

impl SessionStore {
    pub fn insert(&self, token: String, session: Session) {
        self.0.lock().unwrap().insert(token, session);
    }

    pub fn username_for(&self, token: &str) -> Option<String> {
        self.0
            .lock()
            .unwrap()
            .get(token)
            .map(|session| session.username.clone())
    }

    pub fn remove(&self, token: &str) {
        self.0.lock().unwrap().remove(token);
    }
}

#[derive(Clone)]
pub struct AppState {
    pub dbus: VegaDbus,
    pub sessions: SessionStore,
    pub cookie_key: Key,
    pub pam_service: String,
}

impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.cookie_key.clone()
    }
}
