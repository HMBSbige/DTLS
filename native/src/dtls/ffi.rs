use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Instant;

use super::session::{DtlsSession, SessionInput, SessionStatus};
use crate::error::{DtlsError, DtlsResult, set_last_error};

const MAX_BUFFER_SIZE: usize = 1024 * 1024;

#[repr(C)]
pub(crate) struct DtlsOpStatus {
    pub(crate) timeout_ms: i64,
    pub(crate) is_handshaking: u8,
    pub(crate) is_local_closed: u8,
    pub(crate) is_peer_closed: u8,
}

impl Default for DtlsOpStatus {
    fn default() -> Self {
        Self {
            timeout_ms: -1,
            is_handshaking: 0,
            is_local_closed: 0,
            is_peer_closed: 0,
        }
    }
}

impl From<SessionStatus> for DtlsOpStatus {
    fn from(status: SessionStatus) -> Self {
        Self {
            timeout_ms: status.next_timeout.map_or(-1, |timeout| timeout.saturating_duration_since(Instant::now()).as_millis() as i64),
            is_handshaking: u8::from(status.is_handshaking),
            is_local_closed: u8::from(status.is_local_closed),
            is_peer_closed: u8::from(status.is_peer_closed),
        }
    }
}

#[repr(C)]
pub(crate) struct DtlsConnectionSnapshot {
    pub(crate) protocol: u16,
}

#[repr(C)]
pub(crate) struct DtlsCallResult {
    pub(crate) code: DtlsResult,
    pub(crate) bytes_written: usize,
    pub(crate) bytes_read: usize,
    pub(crate) status: DtlsOpStatus,
}

impl DtlsCallResult {
    fn ok(bytes_written: usize, bytes_read: usize) -> Self {
        Self {
            code: DtlsResult::Ok,
            bytes_written,
            bytes_read,
            status: DtlsOpStatus::default(),
        }
    }
}

impl From<DtlsError> for DtlsCallResult {
    fn from(error: DtlsError) -> Self {
        set_last_error(error.message.into_owned());
        Self { code: error.code, ..Self::ok(0, 0) }
    }
}

#[repr(C)]
pub(crate) struct DtlsSessionNewConfig {
    pub(crate) cert_der: *const u8,
    pub(crate) cert_len: usize,
    pub(crate) key_der: *const u8,
    pub(crate) key_len: usize,
    pub(crate) is_client: u8,
    pub(crate) min_version: u32,
    pub(crate) max_version: u32,
    pub(crate) require_client_certificate: u8,
}

fn call(action: impl FnOnce() -> Result<DtlsCallResult, DtlsError>) -> DtlsCallResult {
    match catch_unwind(AssertUnwindSafe(action)) {
        Ok(result) => result.unwrap_or_else(Into::into),
        Err(panic) => {
            let message = panic
                .downcast::<String>()
                .map(|message| *message)
                .or_else(|panic| panic.downcast::<&str>().map(|message| message.to_string()))
                .unwrap_or_else(|_| "unknown panic".into());
            DtlsError::new(DtlsResult::Panic, message).into()
        }
    }
}

fn null_pointer() -> DtlsError {
    DtlsError::new(DtlsResult::InvalidInput, "null pointer")
}

fn validate_buffer(pointer: *const u8, length: usize) -> Result<(), DtlsError> {
    if length > 0 && pointer.is_null() {
        return Err(null_pointer());
    }
    if length > isize::MAX as usize {
        return Err(DtlsError::new(DtlsResult::InvalidInput, "buffer length exceeds addressable memory"));
    }
    Ok(())
}

/// # Safety
///
/// 非空缓冲区的前 `length` 字节必须可读，且在返回的切片有效期间不得修改。
unsafe fn input_slice<'a>(pointer: *const u8, length: usize) -> Result<&'a [u8], DtlsError> {
    validate_buffer(pointer, length)?;
    Ok(if length == 0 { &[] } else { unsafe { std::slice::from_raw_parts(pointer, length) } })
}

/// # Safety
///
/// 非空缓冲区的前 `length` 字节必须可写，且在返回的切片有效期间不得有其他访问。
unsafe fn output_slice<'a>(pointer: *mut u8, length: usize) -> Result<&'a mut [u8], DtlsError> {
    validate_buffer(pointer, length)?;
    Ok(if length == 0 { &mut [] } else { unsafe { std::slice::from_raw_parts_mut(pointer, length) } })
}

/// # Safety
///
/// 遵循 `input_slice` 的安全要求；长度超过输入上限时不会访问缓冲区。
unsafe fn datagram_slice<'a>(pointer: *const u8, length: usize) -> Result<&'a [u8], DtlsError> {
    if length > MAX_BUFFER_SIZE {
        return Err(DtlsError::new(DtlsResult::InvalidInput, format!("input length {length} exceeds maximum {MAX_BUFFER_SIZE}")));
    }
    unsafe { input_slice(pointer, length) }
}

/// # Safety
///
/// `session` 可为空；非空时必须指向有效会话，且调用期间只能由本函数访问。
unsafe fn with_session(session: *mut DtlsSession, action: impl FnOnce(&mut DtlsSession) -> Result<DtlsCallResult, DtlsError>) -> Result<DtlsCallResult, DtlsError> {
    let session = unsafe { session.as_mut() }.ok_or_else(null_pointer)?;
    let mut result = action(session).unwrap_or_else(Into::into);
    result.status = session.status().into();
    Ok(result)
}

/// # Safety
///
/// `session` 遵循 `with_session` 的安全要求，输出缓冲区遵循 `output_slice` 的安全要求，且不得与会话重叠。
/// 输入和输出缓冲区可以重叠，但 `action` 返回前必须结束对输入的借用。
unsafe fn with_output(session: *mut DtlsSession, output: *mut u8, capacity: usize, action: impl FnOnce(&mut DtlsSession) -> Result<(), DtlsError>) -> Result<DtlsCallResult, DtlsError> {
    validate_buffer(output, capacity)?;
    unsafe {
        with_session(session, |session| {
            // 先检查会话是否已失败，避免输入检查覆盖原来的错误。
            session.ensure_active()?;
            action(session)?;
            // 处理完输入后再借用输出缓冲区，允许两者重叠。
            let buffer = output_slice(output, capacity)?;
            Ok(DtlsCallResult::ok(session.write_outgoing(buffer)?, 0))
        })
    }
}

fn version_from_native(version: u32) -> Result<Option<dimpl::ProtocolVersion>, DtlsError> {
    match version {
        0 => Ok(None),
        1 => Ok(Some(dimpl::ProtocolVersion::DTLS1_2)),
        2 => Ok(Some(dimpl::ProtocolVersion::DTLS1_3)),
        _ => Err(DtlsError::new(DtlsResult::InvalidInput, "unsupported DTLS version")),
    }
}

fn protocol_to_native(version: Option<dimpl::ProtocolVersion>) -> u16 {
    match version {
        Some(dimpl::ProtocolVersion::DTLS1_2) => 1,
        Some(dimpl::ProtocolVersion::DTLS1_3) => 2,
        _ => 0,
    }
}

/// # Safety
///
/// `config` 必须可读，非空证书和密钥缓冲区必须在各自声明的长度内可读。
/// `out_session` 必须可写，且不得与其他参数指向的内存重叠。
/// 输出缓冲区的前 `out_pkts_cap` 字节必须可写，可以与证书、密钥缓冲区重叠。
/// 调用期间，其他线程不得访问这些内存。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dtls_session_new(config: *const DtlsSessionNewConfig, out_session: *mut *mut DtlsSession, out_pkts: *mut u8, out_pkts_cap: usize) -> DtlsCallResult {
    call(|| {
        let out_session = unsafe { out_session.as_mut() }.ok_or_else(null_pointer)?;
        *out_session = std::ptr::null_mut();
        let config = unsafe { config.as_ref() }.ok_or_else(null_pointer)?;
        validate_buffer(out_pkts, out_pkts_cap)?;
        let mut session = DtlsSession::new(
            unsafe { input_slice(config.cert_der, config.cert_len)? },
            unsafe { input_slice(config.key_der, config.key_len)? },
            config.is_client != 0,
            version_from_native(config.min_version)?,
            version_from_native(config.max_version)?,
            config.require_client_certificate != 0,
        )?;
        let result = unsafe { with_output(&mut session, out_pkts, out_pkts_cap, |session| session.process(SessionInput::Timeout))? };
        if result.code == DtlsResult::Ok {
            *out_session = Box::into_raw(Box::new(session));
        }
        Ok(result)
    })
}

/// # Safety
///
/// `session` 必须指向有效会话，且调用期间只能由本函数访问。
/// 非空输入、输出缓冲区必须在各自声明的长度内可读、可写。
/// 两个缓冲区可以重叠，但不得与会话重叠；调用期间，其他线程不得访问它们。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dtls_session_feed(session: *mut DtlsSession, input: *const u8, input_len: usize, out_pkts: *mut u8, out_pkts_cap: usize) -> DtlsCallResult {
    call(|| unsafe { with_output(session, out_pkts, out_pkts_cap, |session| session.process(SessionInput::Packet(datagram_slice(input, input_len)?))) })
}

/// # Safety
///
/// `session` 必须指向有效会话，且调用期间只能由本函数访问。
/// 非空输出缓冲区的前 `out_pkts_cap` 字节必须可写，不得与会话重叠，调用期间不得有其他访问。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dtls_session_handle_timeout(session: *mut DtlsSession, out_pkts: *mut u8, out_pkts_cap: usize) -> DtlsCallResult {
    call(|| unsafe { with_output(session, out_pkts, out_pkts_cap, |session| session.process(SessionInput::Timeout)) })
}

/// # Safety
///
/// 遵循 `dtls_session_feed` 的安全要求，其中 `data`、`data_len` 对应输入缓冲区。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dtls_session_send(session: *mut DtlsSession, data: *const u8, data_len: usize, out_pkts: *mut u8, out_pkts_cap: usize) -> DtlsCallResult {
    call(|| unsafe {
        with_output(session, out_pkts, out_pkts_cap, |session| {
            session.process(SessionInput::ApplicationData(datagram_slice(data, data_len)?))
        })
    })
}

/// # Safety
///
/// `session` 必须指向有效会话，且调用期间只能由本函数访问。
/// 非空缓冲区的前 `buf_len` 字节必须可写，不得与会话重叠，调用期间不得有其他访问。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dtls_session_recv(session: *mut DtlsSession, buf: *mut u8, buf_len: usize) -> DtlsCallResult {
    call(|| {
        validate_buffer(buf, buf_len)?;
        unsafe {
            with_session(session, |session| {
                let length = session.receive(output_slice(buf, buf_len)?)?;
                let mut result = DtlsCallResult::ok(0, length.unwrap_or_default());
                if length.is_none() {
                    result.code = DtlsResult::WouldBlock;
                }
                Ok(result)
            })
        }
    })
}

/// # Safety
///
/// `session` 必须指向有效会话，调用期间不得修改。
/// `out` 必须可写，不得与会话重叠，调用期间不得有其他访问。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dtls_session_connection_snapshot(session: *const DtlsSession, out: *mut DtlsConnectionSnapshot) -> DtlsCallResult {
    call(|| {
        let session = unsafe { session.as_ref() }.ok_or_else(null_pointer)?;
        let out = unsafe { out.as_mut() }.ok_or_else(null_pointer)?;
        let mut result = match session.protocol_version() {
            Ok(version) => {
                out.protocol = protocol_to_native(version);
                DtlsCallResult::ok(0, 0)
            }
            Err(error) => error.into(),
        };
        result.status = session.status().into();
        Ok(result)
    })
}

/// 复制对端的 DER 叶子证书；缓冲区指针为空或长度为零时，只返回所需长度。
///
/// # Safety
///
/// `session` 必须指向有效会话，调用期间不得修改。
/// 复制证书时，缓冲区的前 `buf_len` 字节必须可写，不得与会话重叠，调用期间不得有其他访问。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dtls_session_copy_peer_cert(session: *const DtlsSession, buf: *mut u8, buf_len: usize) -> DtlsCallResult {
    call(|| {
        let session = unsafe { session.as_ref() }.ok_or_else(null_pointer)?;
        let copy = || {
            let certificate = session.peer_certificate()?;
            if !buf.is_null() && buf_len > 0 {
                if buf_len < certificate.len() {
                    return Err(DtlsError::new(DtlsResult::BufferTooSmall, "output buffer too small"));
                }
                let output = unsafe { output_slice(buf, buf_len)? };
                output[..certificate.len()].copy_from_slice(certificate);
            }
            Ok(DtlsCallResult::ok(0, certificate.len()))
        };
        let mut result = copy().unwrap_or_else(Into::into);
        result.status = session.status().into();
        Ok(result)
    })
}

/// # Safety
///
/// 遵循 `dtls_session_handle_timeout` 的安全要求。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dtls_session_close(session: *mut DtlsSession, out_pkts: *mut u8, out_pkts_cap: usize) -> DtlsCallResult {
    call(|| unsafe { with_output(session, out_pkts, out_pkts_cap, |session| session.process(SessionInput::Close)) })
}

/// # Safety
///
/// `ptr` 可为空；非空时必须由 `dtls_session_new` 返回，且尚未释放。
/// 调用期间不得有其他访问，释放后不得再访问该会话。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dtls_session_free(ptr: *mut DtlsSession) {
    if !ptr.is_null() {
        unsafe { drop(Box::from_raw(ptr)) };
    }
}
