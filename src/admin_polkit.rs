//! A root authentication agent for exactly one owned worker and one action.
//! Only the root PAM broker uses this module; HTTPS cannot answer challenges.
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use zbus::message::Header;
use zbus::zvariant::OwnedValue;
use zeroize::Zeroizing;

pub const PATH: &str = "/org/lyraos/VegaWeb/AuthenticationAgent";
const AUTHORITY_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
const AUTHORITY: &str = "org.freedesktop.PolicyKit1.Authority";
pub type Subject = (String, HashMap<String, OwnedValue>);
type Identity = (String, HashMap<String, OwnedValue>);

pub struct Agent {
    connection: zbus::Connection,
    owner: zbus::names::OwnedUniqueName,
    uid: u32,
    action: &'static str,
    audit: String,
    consumed: AtomicBool,
}

fn denied() -> zbus::fdo::Error {
    zbus::fdo::Error::AccessDenied("administrative authentication rejected".into())
}

impl Agent {
    fn is_authority(&self, header: &Header<'_>) -> bool {
        header.sender().is_some_and(|sender| sender == &self.owner)
    }
}

#[zbus::interface(name = "org.freedesktop.PolicyKit1.AuthenticationAgent")]
impl Agent {
    #[allow(clippy::too_many_arguments)] // The public Polkit interface.
    async fn begin_authentication(
        &self,
        action_id: String,
        _message: String,
        _icon_name: String,
        _details: HashMap<String, String>,
        cookie: String,
        identities: Vec<Identity>,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<()> {
        let cookie = Zeroizing::new(cookie);
        if !self.is_authority(&header) || action_id != self.action {
            return Err(denied());
        }
        let identity = identities
            .into_iter()
            .find(|(kind, details)| {
                kind == "unix-user"
                    && details
                        .get("uid")
                        .is_some_and(|uid| u32::try_from(uid) == Ok(self.uid))
            })
            .ok_or_else(denied)?;
        if self.consumed.swap(true, Ordering::SeqCst) {
            return Err(denied());
        }
        // PAM already authenticated this exact account before the one-use
        // commit. Only root can supply the response to Polkit. The agent is
        // registered for an owned, unreaped child, never a whole user session.
        let authority = zbus::Proxy::new(
            &self.connection,
            self.owner.clone(),
            AUTHORITY_PATH,
            AUTHORITY,
        )
        .await
        .map_err(|_| denied())?;
        authority
            .call::<_, _, ()>(
                "AuthenticationAgentResponse2",
                &(self.uid, cookie.as_str(), identity),
            )
            .await
            .map_err(|_| denied())?;
        eprintln!(
            "vega-web-admin: id={} uid={} action={} phase=polkit-authenticated",
            self.audit, self.uid, self.action
        );
        Ok(())
    }

    async fn cancel_authentication(
        &self,
        cookie: String,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<()> {
        let _cookie = Zeroizing::new(cookie);
        if !self.is_authority(&header) {
            return Err(denied());
        }
        self.consumed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

pub async fn register(
    pid: u32,
    uid: u32,
    action: &'static str,
    audit: &str,
) -> Result<(zbus::Connection, Subject), Box<dyn std::error::Error>> {
    // The parent retains the child until after unregistering, so even a child
    // that exits early cannot have its PID recycled into another process.
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let (_, fields) = stat.rsplit_once(')').ok_or("invalid worker stat")?;
    let start: u64 = fields
        .split_whitespace()
        .nth(19)
        .ok_or("worker start missing")?
        .parse()?;
    let subject = (
        "unix-process".to_owned(),
        HashMap::from([
            ("pid".into(), OwnedValue::from(pid)),
            ("uid".into(), OwnedValue::from(i32::try_from(uid)?)),
            ("start-time".into(), OwnedValue::from(start)),
        ]),
    );
    let connection = zbus::Connection::system().await?;
    let bus = zbus::fdo::DBusProxy::new(&connection).await?;
    let owner = bus
        .get_name_owner("org.freedesktop.PolicyKit1".try_into()?)
        .await?;
    let agent = Agent {
        connection: connection.clone(),
        owner: owner.clone(),
        uid,
        action,
        audit: audit.to_owned(),
        consumed: AtomicBool::new(false),
    };
    connection.object_server().at(PATH, agent).await?;
    let authority = zbus::Proxy::new(&connection, owner, AUTHORITY_PATH, AUTHORITY).await?;
    authority
        .call::<_, _, ()>("RegisterAuthenticationAgent", &(&subject, "C", PATH))
        .await?;
    Ok((connection, subject))
}

pub async fn unregister(connection: &zbus::Connection, subject: &Subject) {
    if let Ok(authority) = zbus::Proxy::new(
        connection,
        "org.freedesktop.PolicyKit1",
        AUTHORITY_PATH,
        AUTHORITY,
    )
    .await
    {
        let _ = authority
            .call::<_, _, ()>("UnregisterAuthenticationAgent", &(subject, PATH))
            .await;
    }
    let _ = connection.object_server().remove::<Agent, _>(PATH).await;
}
