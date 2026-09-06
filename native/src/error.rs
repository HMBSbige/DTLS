use std::borrow::Cow;
use std::cell::RefCell;
use std::ffi::c_char;

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DtlsResult {
    Ok = 0,
    WouldBlock = 1,
    CertificateError = -1,
    InvalidInput = -2,
    DtlsError = -3,
    BufferTooSmall = -4,
    Panic = -99,
}

#[derive(Debug, Clone)]
pub(crate) struct DtlsError {
    pub(crate) code: DtlsResult,
    pub(crate) message: Cow<'static, str>,
}

impl DtlsError {
    pub(crate) fn new(code: DtlsResult, message: impl Into<Cow<'static, str>>) -> Self {
        Self { code, message: message.into() }
    }
}

impl From<dimpl::Error> for DtlsError {
    fn from(error: dimpl::Error) -> Self {
        let code = match error {
            dimpl::Error::CertificateError(_) => DtlsResult::CertificateError,
            _ => DtlsResult::DtlsError,
        };
        Self::new(code, error.to_string())
    }
}

thread_local! {
    static LAST_ERROR: RefCell<String> = const { RefCell::new(String::new()) };
}

pub(crate) fn set_last_error(message: impl Into<String>) {
    LAST_ERROR.with_borrow_mut(|error| *error = message.into());
}

/// 复制当前线程的最近一次错误，以 NUL 结尾；缓冲区不足时截断消息。
/// 返回写入的字节数（不含 NUL）；指针为空或长度小于等于零时返回 -1。
///
/// # Safety
///
/// `buf` 非空且 `buf_len` 为正时，缓冲区的前 `buf_len` 字节必须可写，调用期间不得有其他访问。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dtls_last_error_message(buf: *mut c_char, buf_len: i32) -> i32 {
    if buf.is_null() || buf_len <= 0 {
        return -1;
    }
    let buf = unsafe { std::slice::from_raw_parts_mut(buf.cast(), buf_len as usize) };
    LAST_ERROR.with_borrow(|message| {
        let copy_len = message.len().min(buf.len() - 1);
        buf[..copy_len].copy_from_slice(&message.as_bytes()[..copy_len]);
        buf[copy_len] = 0;
        copy_len as i32
    })
}
