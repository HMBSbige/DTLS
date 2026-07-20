#![allow(clippy::missing_safety_doc)]

use super::session::DtlsSession;
use crate::error::{DtlsResult, set_last_error};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

// 限制单次 FFI 输入，避免按不可信长度过量分配。
const MAX_BUFFER_SIZE: usize = 1024 * 1024;

/// .NET `SslProtocols.Tls12` 的整数值。
const SSL_PROTOCOLS_TLS12: u32 = 0x0C00;
/// .NET `SslProtocols.Tls13` 的整数值。
const SSL_PROTOCOLS_TLS13: u32 = 0x3000;

#[repr(C)]
pub(crate) struct DtlsOpStatus {
    pub(crate) timeout_ms: i64,
    pub(crate) is_handshaking: u8,
    pub(crate) is_local_closed: u8,
    pub(crate) is_peer_closed: u8,
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
    fn err(code: DtlsResult) -> Self {
        Self {
            code,
            bytes_written: 0,
            bytes_read: 0,
            status: DtlsOpStatus {
                timeout_ms: -1,
                is_handshaking: 0,
                is_local_closed: 0,
                is_peer_closed: 0,
            },
        }
    }

    fn err_with(code: DtlsResult, status: DtlsOpStatus) -> Self {
        Self {
            code,
            bytes_written: 0,
            bytes_read: 0,
            status,
        }
    }
}

fn catch_unwind_call_result(f: impl FnOnce() -> DtlsCallResult) -> DtlsCallResult {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or_else(|e| {
        let msg = e
            .downcast::<String>()
            .map(|s| *s)
            .or_else(|e| e.downcast::<&str>().map(|s| s.to_string()))
            .unwrap_or_else(|_| "unknown panic".into());
        set_last_error(msg);
        DtlsCallResult::err(DtlsResult::Panic)
    })
}

/// # Safety
///
/// 当 `len > 0` 时，`ptr` 必须在 `len` 字节范围内可读写且满足对齐要求。
unsafe fn raw_mut_slice<'a>(ptr: *mut u8, len: usize) -> &'a mut [u8] {
    if len == 0 { &mut [] } else { unsafe { std::slice::from_raw_parts_mut(ptr, len) } }
}

/// # Safety
///
/// 当 `len > 0` 时，`ptr` 必须在 `len` 字节范围内可读且满足对齐要求。
unsafe fn raw_slice<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if len == 0 { &[] } else { unsafe { std::slice::from_raw_parts(ptr, len) } }
}

fn write_outgoing_to_buffer(s: &mut DtlsSession, buf: &mut [u8]) -> Result<usize, ()> {
    let mut offset = 0usize;
    while let Some(pkt) = s.outgoing_pkts.front() {
        if pkt.len() > u16::MAX as usize {
            s.outgoing_pkts.pop_front();
            continue;
        }
        let frame_len = 2 + pkt.len();
        if offset + frame_len > buf.len() {
            if offset == 0 {
                return Err(());
            }
            break;
        }
        let pkt = s.outgoing_pkts.pop_front().unwrap();
        let len_bytes = (pkt.len() as u16).to_le_bytes();
        buf[offset..offset + 2].copy_from_slice(&len_bytes);
        buf[offset + 2..offset + 2 + pkt.len()].copy_from_slice(&pkt);
        offset += frame_len;
    }
    Ok(offset)
}

fn protocol_version_to_ssl_protocols(ver: dimpl::ProtocolVersion) -> u16 {
    match ver {
        dimpl::ProtocolVersion::DTLS1_2 => SSL_PROTOCOLS_TLS12 as u16,
        dimpl::ProtocolVersion::DTLS1_3 => SSL_PROTOCOLS_TLS13 as u16,
        _ => 0,
    }
}

// dimpl 0.7.x 的 HandshakePending 可重试；其他公开错误均为连接级 fatal。
fn record_dimpl_error(s: &mut DtlsSession, e: &dimpl::Error) -> DtlsCallResult {
    let code = match e {
        dimpl::Error::CertificateError(_) => DtlsResult::CertificateError,
        _ => DtlsResult::DtlsError,
    };
    let message = e.to_string();
    if !matches!(e, dimpl::Error::HandshakePending) {
        s.fatal_error = Some((code, message.clone()));
    }
    set_last_error(message);
    DtlsCallResult::err_with(code, make_status(s))
}

fn drain_output(s: &mut DtlsSession) -> Result<(), DtlsCallResult> {
    if let Err(e) = s.dtls.handle_timeout(Instant::now()) {
        return Err(record_dimpl_error(s, &e));
    }
    s.next_timeout = None;
    loop {
        match s.dtls.poll_output(&mut s.poll_buf) {
            dimpl::Output::Packet(data) => s.outgoing_pkts.push_back(data.to_vec()),
            dimpl::Output::BufferTooSmall { needed } => s.poll_buf.resize(needed, 0),
            dimpl::Output::Connected => {
                s.handshake_complete = true;
                if s.protocol_version == 0
                    && let Some(ver) = s.dtls.protocol_version()
                {
                    s.protocol_version = protocol_version_to_ssl_protocols(ver);
                }
            }
            dimpl::Output::ApplicationData(data) => s.app_data.push_back(data.to_vec()),
            dimpl::Output::PeerCert(der) => s.peer_cert = Some(der.to_vec()),
            dimpl::Output::Timeout(t) => {
                s.next_timeout = Some(t);
                break;
            }
            dimpl::Output::KeyingMaterial(..) => {}
            dimpl::Output::CloseNotify => {
                s.peer_closed = true;
            }
            _ => {}
        }
    }
    // 仅在排空至 Timeout 后，dimpl 的关闭状态才一致。
    s.local_closed |= s.dtls.is_closed();
    Ok(())
}

fn make_status(s: &DtlsSession) -> DtlsOpStatus {
    let is_terminal = s.local_closed || s.fatal_error.is_some();
    DtlsOpStatus {
        timeout_ms: if is_terminal {
            -1
        } else {
            s.next_timeout.map_or(-1, |t| t.saturating_duration_since(Instant::now()).as_millis() as i64)
        },
        is_handshaking: u8::from(!s.handshake_complete && !is_terminal),
        is_local_closed: u8::from(s.local_closed),
        is_peer_closed: u8::from(s.peer_closed),
    }
}

fn fatal_error_result(s: &DtlsSession) -> Option<DtlsCallResult> {
    let (code, message) = s.fatal_error.as_ref()?;
    set_last_error(message.clone());
    Some(DtlsCallResult::err_with(*code, make_status(s)))
}

/// 所有驱动 `Dtls` 状态机的入口必须使用此守卫。
///
/// # Safety
///
/// `session` 须为空或指向有效的 `DtlsSession`，且在本次调用期间保持有效、无其他别名；
/// `out_pkts`/`out_pkts_cap` 须满足 `raw_mut_slice` 的要求。
unsafe fn with_open_session(session: *mut DtlsSession, out_pkts: *mut u8, out_pkts_cap: usize, f: impl FnOnce(&mut DtlsSession) -> DtlsCallResult) -> DtlsCallResult {
    if session.is_null() || (out_pkts_cap > 0 && out_pkts.is_null()) {
        set_last_error("null pointer");
        return DtlsCallResult::err(DtlsResult::InvalidInput);
    }
    let s = unsafe { &mut *session };
    match fatal_error_result(s) {
        Some(result) => result,
        None => f(s),
    }
}

fn flush(s: &mut DtlsSession, out_pkts: &mut [u8]) -> DtlsCallResult {
    if let Err(r) = drain_output(s) {
        return r;
    }
    match write_outgoing_to_buffer(s, out_pkts) {
        Ok(n) => DtlsCallResult {
            code: DtlsResult::Ok,
            bytes_written: n,
            bytes_read: 0,
            status: make_status(s),
        },
        Err(()) => {
            set_last_error("output buffer too small");
            DtlsCallResult::err_with(DtlsResult::BufferTooSmall, make_status(s))
        }
    }
}

#[repr(C)]
pub(crate) struct DtlsSessionNewConfig {
    pub(crate) cert_der: *const u8,
    pub(crate) cert_len: usize,
    pub(crate) key_der: *const u8,
    pub(crate) key_len: usize,
    pub(crate) is_client: u8,
    pub(crate) version: u32,
    pub(crate) require_client_certificate: u8,
}

fn create_session(cert_der: &[u8], key_der: &[u8], is_client: bool, version: u32, require_client_certificate: bool) -> Result<DtlsSession, DtlsCallResult> {
    if cert_der.is_empty() != key_der.is_empty() {
        set_last_error("cert and key must be provided together");
        return Err(DtlsCallResult::err(DtlsResult::InvalidInput));
    }

    let cert = if !cert_der.is_empty() {
        dimpl::DtlsCertificate {
            certificate: cert_der.to_vec(),
            private_key: key_der.to_vec(),
        }
    } else {
        match dimpl::certificate::generate_self_signed_certificate() {
            Ok(c) => c,
            Err(e) => {
                set_last_error(e.to_string());
                return Err(DtlsCallResult::err(DtlsResult::CertificateError));
            }
        }
    };

    let version = match version {
        SSL_PROTOCOLS_TLS12 | SSL_PROTOCOLS_TLS13 => version,
        _ => 0,
    };
    let cfg = Arc::new(dimpl::Config::builder().require_client_certificate(require_client_certificate).build().expect("valid config"));
    let now = Instant::now();
    let mut dtls = match version {
        SSL_PROTOCOLS_TLS12 => dimpl::Dtls::new_12(cfg, cert, now),
        SSL_PROTOCOLS_TLS13 => dimpl::Dtls::new_13(cfg, cert, now),
        _ => dimpl::Dtls::new_auto(cfg, cert, now),
    };
    dtls.set_active(is_client);

    Ok(DtlsSession {
        dtls,
        handshake_complete: false,
        local_closed: false,
        peer_closed: false,
        app_data: VecDeque::new(),
        outgoing_pkts: VecDeque::new(),
        peer_cert: None,
        next_timeout: None,
        poll_buf: vec![0u8; 65536],
        protocol_version: version as u16,
        fatal_error: None,
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dtls_session_new(config: *const DtlsSessionNewConfig, out_session: *mut *mut DtlsSession, out_pkts: *mut u8, out_pkts_cap: usize) -> DtlsCallResult {
    catch_unwind_call_result(|| {
        if out_session.is_null() {
            set_last_error("null pointer");
            return DtlsCallResult::err(DtlsResult::InvalidInput);
        }
        // 防御式处理：任何失败路径都先将 out_session 置空，避免调用方误用脏指针。
        unsafe {
            *out_session = std::ptr::null_mut();
        }
        if config.is_null() || (out_pkts_cap > 0 && out_pkts.is_null()) {
            set_last_error("null pointer");
            return DtlsCallResult::err(DtlsResult::InvalidInput);
        }
        let c = unsafe { &*config };
        if (c.cert_len > 0 && c.cert_der.is_null()) || (c.key_len > 0 && c.key_der.is_null()) {
            set_last_error("null cert/key pointer with non-zero length");
            return DtlsCallResult::err(DtlsResult::InvalidInput);
        }
        let cert = unsafe { raw_slice(c.cert_der, c.cert_len) };
        let key = unsafe { raw_slice(c.key_der, c.key_len) };
        let out_buf = unsafe { raw_mut_slice(out_pkts, out_pkts_cap) };
        let mut s = match create_session(cert, key, c.is_client != 0, c.version, c.require_client_certificate != 0) {
            Ok(s) => s,
            Err(r) => return r,
        };
        let r = flush(&mut s, out_buf);
        if r.code != DtlsResult::Ok {
            return r;
        }
        unsafe {
            *out_session = Box::into_raw(Box::new(s));
        }
        r
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dtls_session_feed(session: *mut DtlsSession, input: *const u8, input_len: usize, out_pkts: *mut u8, out_pkts_cap: usize) -> DtlsCallResult {
    catch_unwind_call_result(|| {
        let body = |s: &mut DtlsSession| {
            // 先从原始指针复制输入，避免调用方传入输入/输出重叠缓冲区时产生别名 UB。
            let input_copy = if input_len > 0 {
                if input.is_null() {
                    set_last_error("null input pointer with non-zero length");
                    return DtlsCallResult::err_with(DtlsResult::InvalidInput, make_status(s));
                }
                if input_len > MAX_BUFFER_SIZE {
                    set_last_error(format!("input_len {} exceeds maximum {}", input_len, MAX_BUFFER_SIZE));
                    return DtlsCallResult::err_with(DtlsResult::InvalidInput, make_status(s));
                }
                let mut v = vec![0u8; input_len];
                unsafe { std::ptr::copy_nonoverlapping(input, v.as_mut_ptr(), input_len) };
                Some(v)
            } else {
                None
            };
            let out_buf = unsafe { raw_mut_slice(out_pkts, out_pkts_cap) };
            if let Some(ref data) = input_copy
                && let Err(e) = s.dtls.handle_packet(data)
            {
                return record_dimpl_error(s, &e);
            }
            flush(s, out_buf)
        };
        unsafe { with_open_session(session, out_pkts, out_pkts_cap, body) }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dtls_session_handle_timeout(session: *mut DtlsSession, out_pkts: *mut u8, out_pkts_cap: usize) -> DtlsCallResult {
    catch_unwind_call_result(|| {
        let body = |s: &mut DtlsSession| flush(s, unsafe { raw_mut_slice(out_pkts, out_pkts_cap) });
        unsafe { with_open_session(session, out_pkts, out_pkts_cap, body) }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dtls_session_send(session: *mut DtlsSession, data: *const u8, data_len: usize, out_pkts: *mut u8, out_pkts_cap: usize) -> DtlsCallResult {
    catch_unwind_call_result(|| {
        let body = |s: &mut DtlsSession| {
            // 先从原始指针复制输入，避免调用方传入数据/输出重叠缓冲区时产生别名 UB。
            let data_copy = if data_len > 0 {
                if data.is_null() {
                    set_last_error("null data pointer with non-zero length");
                    return DtlsCallResult::err_with(DtlsResult::InvalidInput, make_status(s));
                }
                if data_len > MAX_BUFFER_SIZE {
                    set_last_error(format!("data_len {} exceeds maximum {}", data_len, MAX_BUFFER_SIZE));
                    return DtlsCallResult::err_with(DtlsResult::InvalidInput, make_status(s));
                }
                let mut v = vec![0u8; data_len];
                unsafe { std::ptr::copy_nonoverlapping(data, v.as_mut_ptr(), data_len) };
                Some(v)
            } else {
                None
            };
            let out_buf = unsafe { raw_mut_slice(out_pkts, out_pkts_cap) };
            if let Some(ref payload) = data_copy
                && let Err(e) = s.dtls.send_application_data(payload)
            {
                return record_dimpl_error(s, &e);
            }
            flush(s, out_buf)
        };
        unsafe { with_open_session(session, out_pkts, out_pkts_cap, body) }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dtls_session_recv(session: *mut DtlsSession, buf: *mut u8, buf_len: usize) -> DtlsCallResult {
    catch_unwind_call_result(|| {
        if session.is_null() || (buf_len > 0 && buf.is_null()) {
            set_last_error("null pointer");
            return DtlsCallResult::err(DtlsResult::InvalidInput);
        }
        let s = unsafe { &mut *session };
        let buf = unsafe { raw_mut_slice(buf, buf_len) };
        match s.app_data.pop_front() {
            Some(data) if data.len() <= buf.len() => {
                buf[..data.len()].copy_from_slice(&data);
                DtlsCallResult {
                    code: DtlsResult::Ok,
                    bytes_written: 0,
                    bytes_read: data.len(),
                    status: make_status(s),
                }
            }
            Some(data) => {
                s.app_data.push_front(data);
                set_last_error("output buffer too small for datagram");
                DtlsCallResult::err_with(DtlsResult::BufferTooSmall, make_status(s))
            }
            None => DtlsCallResult {
                code: DtlsResult::WouldBlock,
                bytes_written: 0,
                bytes_read: 0,
                status: make_status(s),
            },
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dtls_session_connection_snapshot(session: *const DtlsSession, out: *mut DtlsConnectionSnapshot) -> DtlsCallResult {
    catch_unwind_call_result(|| {
        if session.is_null() || out.is_null() {
            set_last_error("null pointer");
            return DtlsCallResult::err(DtlsResult::InvalidInput);
        }
        let s = unsafe { &*session };
        if !s.handshake_complete {
            set_last_error("handshake not complete");
            return DtlsCallResult::err_with(DtlsResult::DtlsError, make_status(s));
        }
        let out = unsafe { &mut *out };
        out.protocol = s.protocol_version;
        DtlsCallResult {
            code: DtlsResult::Ok,
            bytes_written: 0,
            bytes_read: 0,
            status: make_status(s),
        }
    })
}

/// 查询或复制对端叶证书（DER）；空指针或零长度缓冲区仅返回所需长度。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dtls_session_copy_peer_cert(session: *const DtlsSession, buf: *mut u8, buf_len: usize) -> DtlsCallResult {
    catch_unwind_call_result(|| {
        if session.is_null() {
            set_last_error("null pointer");
            return DtlsCallResult::err(DtlsResult::InvalidInput);
        }
        let s = unsafe { &*session };
        if !s.handshake_complete {
            set_last_error("handshake not complete");
            return DtlsCallResult::err_with(DtlsResult::DtlsError, make_status(s));
        }
        let cert = match s.peer_cert.as_ref() {
            Some(c) => c,
            None => {
                return DtlsCallResult {
                    code: DtlsResult::Ok,
                    bytes_written: 0,
                    bytes_read: 0,
                    status: make_status(s),
                };
            }
        };
        if buf.is_null() || buf_len == 0 {
            return DtlsCallResult {
                code: DtlsResult::Ok,
                bytes_written: 0,
                bytes_read: cert.len(),
                status: make_status(s),
            };
        }
        if buf_len < cert.len() {
            set_last_error("output buffer too small");
            return DtlsCallResult::err_with(DtlsResult::BufferTooSmall, make_status(s));
        }
        let out = unsafe { raw_mut_slice(buf, buf_len) };
        out[..cert.len()].copy_from_slice(cert);
        DtlsCallResult {
            code: DtlsResult::Ok,
            bytes_written: 0,
            bytes_read: cert.len(),
            status: make_status(s),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dtls_session_close(session: *mut DtlsSession, out_pkts: *mut u8, out_pkts_cap: usize) -> DtlsCallResult {
    catch_unwind_call_result(|| {
        let body = |s: &mut DtlsSession| {
            let out_buf = unsafe { raw_mut_slice(out_pkts, out_pkts_cap) };
            if !s.local_closed {
                match s.dtls.close() {
                    Ok(()) => {
                        s.local_closed = true;
                    }
                    Err(dimpl::Error::HandshakePending) => {
                        // 版本未决时不得 flush，否则待重传的握手 flight 会被误作 close_notify。
                        // 保留状态，握手完成后可重试 CloseAsync。
                        return DtlsCallResult {
                            code: DtlsResult::Ok,
                            bytes_written: 0,
                            bytes_read: 0,
                            status: make_status(s),
                        };
                    }
                    Err(e) => return record_dimpl_error(s, &e),
                }
            }
            flush(s, out_buf)
        };
        unsafe { with_open_session(session, out_pkts, out_pkts_cap, body) }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dtls_session_free(ptr: *mut DtlsSession) {
    if !ptr.is_null() {
        unsafe {
            drop(Box::from_raw(ptr));
        }
    }
}
