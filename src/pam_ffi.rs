//! Ligações mínimas e manuais com libpam (sem bindgen): só as poucas
//! funções necessárias para autenticar usuário/senha e checar a validade
//! da conta, na convenção Linux-PAM (não Solaris-PAM) de `pam_message`.
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::ptr;
use zeroize::Zeroizing;

const PAM_SUCCESS: c_int = 0;
const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_PROMPT_ECHO_ON: c_int = 2;
const PAM_ERROR_MSG: c_int = 3;
const PAM_TEXT_INFO: c_int = 4;
const PAM_CONV_ERR: c_int = 19;
const PAM_SILENT: c_int = 0x8000;
const PAM_DISALLOW_NULL_AUTHTOK: c_int = 0x0001;

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

type ConvFn = unsafe extern "C" fn(
    num_msg: c_int,
    msg: *mut *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata_ptr: *mut c_void,
) -> c_int;

#[repr(C)]
struct PamConv {
    conv: Option<ConvFn>,
    appdata_ptr: *mut c_void,
}

#[repr(C)]
struct PamHandle {
    _private: [u8; 0],
}

unsafe extern "C" {
    fn pam_start(
        service_name: *const c_char,
        user: *const c_char,
        pam_conversation: *const PamConv,
        pamh: *mut *mut PamHandle,
    ) -> c_int;
    fn pam_end(pamh: *mut PamHandle, pam_status: c_int) -> c_int;
    fn pam_authenticate(pamh: *mut PamHandle, flags: c_int) -> c_int;
    fn pam_acct_mgmt(pamh: *mut PamHandle, flags: c_int) -> c_int;
    fn pam_get_item(pamh: *const PamHandle, item_type: c_int, item: *mut *const c_void) -> c_int;
    fn pam_strerror(pamh: *mut PamHandle, errnum: c_int) -> *const c_char;
}

struct ConvData {
    username: CString,
    password: Zeroizing<CString>,
}

/// Callback de conversa do PAM: não interativo, responde diretamente com a
/// senha (para prompts que escondem o eco) ou o usuário (para os raros
/// prompts que pedem o login de novo). Mensagens informativas/erro não
/// precisam de resposta.
unsafe extern "C" fn conversation(
    num_msg: c_int,
    msg: *mut *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata_ptr: *mut c_void,
) -> c_int {
    if num_msg <= 0 || num_msg > 32 || msg.is_null() || resp.is_null() || appdata_ptr.is_null() {
        return PAM_CONV_ERR;
    }
    let data = unsafe { &*(appdata_ptr as *const ConvData) };
    let count = num_msg as usize;

    let out = unsafe { libc::calloc(count, size_of::<PamResponse>()) } as *mut PamResponse;
    if out.is_null() {
        return PAM_CONV_ERR;
    }

    for i in 0..count {
        if unsafe { *msg.add(i) }.is_null() {
            free_responses(out, i);
            return PAM_CONV_ERR;
        }
        let message = unsafe { &**msg.add(i) };
        let reply: Option<&CStr> = match message.msg_style {
            PAM_PROMPT_ECHO_OFF => Some(data.password.as_c_str()),
            PAM_PROMPT_ECHO_ON => Some(data.username.as_c_str()),
            PAM_ERROR_MSG | PAM_TEXT_INFO => None,
            _ => {
                free_responses(out, i);
                return PAM_CONV_ERR;
            }
        };
        let entry = unsafe { &mut *out.add(i) };
        entry.resp_retcode = 0;
        entry.resp = match reply {
            Some(text) => unsafe { libc::strdup(text.as_ptr()) },
            None => ptr::null_mut(),
        };
        if reply.is_some() && entry.resp.is_null() {
            free_responses(out, i + 1);
            return PAM_CONV_ERR;
        }
    }

    unsafe {
        *resp = out;
    }
    PAM_SUCCESS
}

fn free_responses(out: *mut PamResponse, filled: usize) {
    for i in 0..filled {
        let entry = unsafe { &*out.add(i) };
        if !entry.resp.is_null() {
            unsafe { libc::free(entry.resp as *mut c_void) };
        }
    }
    unsafe { libc::free(out as *mut c_void) };
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthError(pub String);

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for AuthError {}

/// A PAM handle scoped to one authentication/operation. The conversation data
/// outlives pam_end, including on an early return from a failed account check.
pub struct AuthenticatedAccount {
    handle: *mut PamHandle,
    data: Box<ConvData>,
    status: c_int,
}

impl AuthenticatedAccount {
    pub fn authenticate(service: &str, username: &str, password: &str) -> Result<Self, AuthError> {
        let service = CString::new(service).map_err(|_| AuthError("invalid PAM service".into()))?;
        let data = Box::new(ConvData {
            username: CString::new(username).map_err(|_| AuthError("invalid username".into()))?,
            password: Zeroizing::new(
                CString::new(password).map_err(|_| AuthError("invalid password".into()))?,
            ),
        });
        let conversation = PamConv {
            conv: Some(conversation),
            appdata_ptr: (&*data as *const ConvData).cast_mut().cast(),
        };
        let mut handle = ptr::null_mut();
        let status = unsafe {
            pam_start(
                service.as_ptr(),
                data.username.as_ptr(),
                &conversation,
                &mut handle,
            )
        };
        if status != PAM_SUCCESS || handle.is_null() {
            if !handle.is_null() {
                unsafe {
                    pam_end(handle, status);
                }
            }
            return Err(AuthError(format!("pam_start failed ({status})")));
        }
        let mut account = Self {
            handle,
            data,
            status,
        };
        account.status =
            unsafe { pam_authenticate(handle, PAM_SILENT | PAM_DISALLOW_NULL_AUTHTOK) };
        if account.status != PAM_SUCCESS {
            return Err(AuthError(pam_error_message(handle, account.status)));
        }
        account.check_account()?;
        Ok(account)
    }

    /// Recheck expiry/policy immediately before consuming administrative work.
    /// A PAM stack remapping the requested identity is refused explicitly.
    pub fn check_account(&mut self) -> Result<(), AuthError> {
        self.status = unsafe { pam_acct_mgmt(self.handle, PAM_SILENT | PAM_DISALLOW_NULL_AUTHTOK) };
        if self.status != PAM_SUCCESS {
            return Err(AuthError(pam_error_message(self.handle, self.status)));
        }
        let mut user: *const c_void = ptr::null();
        const PAM_USER: c_int = 2;
        self.status = unsafe { pam_get_item(self.handle, PAM_USER, &mut user) };
        if self.status != PAM_SUCCESS
            || user.is_null()
            || unsafe { CStr::from_ptr(user.cast()) } != self.data.username.as_c_str()
        {
            return Err(AuthError("PAM identity changed".into()));
        }
        Ok(())
    }
}

impl Drop for AuthenticatedAccount {
    fn drop(&mut self) {
        unsafe {
            pam_end(self.handle, self.status);
        }
    }
}

/// The login helper needs only the result; the administration helper retains
/// the bounded handle to recheck the account before a committed operation.
#[allow(dead_code)] // The shared module is also compiled by the admin binary.
pub fn authenticate(service: &str, username: &str, password: &str) -> Result<(), AuthError> {
    AuthenticatedAccount::authenticate(service, username, password).map(drop)
}

fn pam_error_message(handle: *mut PamHandle, code: c_int) -> String {
    let ptr = unsafe { pam_strerror(handle, code) };
    if ptr.is_null() {
        return format!("erro PAM {code}");
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}
