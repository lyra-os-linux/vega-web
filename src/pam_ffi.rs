//! Ligações mínimas e manuais com libpam (sem bindgen): só as poucas
//! funções necessárias para autenticar usuário/senha e checar a validade
//! da conta, na convenção Linux-PAM (não Solaris-PAM) de `pam_message`.
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::ptr;

const PAM_SUCCESS: c_int = 0;
const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_PROMPT_ECHO_ON: c_int = 2;
const PAM_ERROR_MSG: c_int = 3;
const PAM_TEXT_INFO: c_int = 4;
const PAM_CONV_ERR: c_int = 19;
const PAM_SILENT: c_int = 0x8000;

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
    fn pam_strerror(pamh: *mut PamHandle, errnum: c_int) -> *const c_char;
}

struct ConvData {
    username: CString,
    password: CString,
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
    if num_msg <= 0 || msg.is_null() || appdata_ptr.is_null() {
        return PAM_CONV_ERR;
    }
    let data = unsafe { &*(appdata_ptr as *const ConvData) };
    let count = num_msg as usize;

    let out = unsafe { libc::calloc(count, size_of::<PamResponse>()) } as *mut PamResponse;
    if out.is_null() {
        return PAM_CONV_ERR;
    }

    for i in 0..count {
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

/// Autentica `username`/`password` contra o serviço PAM informado
/// (ver `/etc/pam.d/<service>`), checando também se a conta está válida
/// (não expirada/bloqueada). Não abre sessão PAM: o vega-web só usa isto
/// como portão de login, não para assumir a identidade do usuário no
/// sistema (isso é trabalho da Fase 2, feito por um helper separado).
pub fn authenticate(service: &str, username: &str, password: &str) -> Result<(), AuthError> {
    let service = CString::new(service).map_err(|_| AuthError("serviço PAM inválido".into()))?;
    let user = CString::new(username).map_err(|_| AuthError("nome de usuário inválido".into()))?;
    let data = Box::new(ConvData {
        username: user.clone(),
        password: CString::new(password).map_err(|_| AuthError("senha inválida".into()))?,
    });
    let data_ptr = Box::into_raw(data);

    let conv = PamConv {
        conv: Some(conversation),
        appdata_ptr: data_ptr as *mut c_void,
    };

    let mut handle: *mut PamHandle = ptr::null_mut();
    let start_rc = unsafe { pam_start(service.as_ptr(), user.as_ptr(), &conv, &mut handle) };

    // Sempre reconstitui a Box para desalocar, mesmo em caminhos de erro.
    let _owned_data = unsafe { Box::from_raw(data_ptr) };

    if start_rc != PAM_SUCCESS || handle.is_null() {
        return Err(AuthError(format!("pam_start falhou (código {start_rc})")));
    }

    let auth_rc = unsafe { pam_authenticate(handle, PAM_SILENT) };
    let acct_rc = if auth_rc == PAM_SUCCESS {
        unsafe { pam_acct_mgmt(handle, PAM_SILENT) }
    } else {
        auth_rc
    };

    let result = if auth_rc == PAM_SUCCESS && acct_rc == PAM_SUCCESS {
        Ok(())
    } else {
        let failing_rc = if auth_rc != PAM_SUCCESS {
            auth_rc
        } else {
            acct_rc
        };
        Err(AuthError(pam_error_message(handle, failing_rc)))
    };

    unsafe {
        pam_end(handle, if result.is_ok() { PAM_SUCCESS } else { auth_rc });
    }

    result
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
