#![allow(clippy::missing_safety_doc)]

use super::session::DtlsSession;
use crate::error::{DtlsResult, set_last_error};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

// ── C ABI structures ─────────────────────────────────────

/// Status filled by every FFI operation.
#[repr(C)]
pub(crate) struct DtlsOpStatus {
    pub(crate) timeout_ms: i64,
    pub(crate) is_handshaking: u8,
}

/// Single-call snapshot of connection info (cert pointer lifetime = session).
#[repr(C)]
pub(crate) struct DtlsConnectionSnapshot {
    pub(crate) protocol: u16,
    pub(crate) peer_cert_ptr: *const u8,
    pub(crate) peer_cert_len: usize,
    pub(crate) peer_chain_ptr: *const u8,
    pub(crate) peer_chain_len: usize,
}

/// Unified result returned by every v2 FFI operation.
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
            status: DtlsOpStatus { timeout_ms: -1, is_handshaking: 0 },
        }
    }
}

fn catch_unwind_call_result(f: impl FnOnce() -> DtlsCallResult) -> DtlsCallResult {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Result::Ok(r) => r,
        Result::Err(e) => {
            let msg = e
                .downcast::<String>()
                .map(|s| *s)
                .or_else(|e| e.downcast::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|_| "unknown panic".into());
            set_last_error(msg);
            DtlsCallResult::err(DtlsResult::Panic)
        }
    }
}

// ── Internal helpers ─────────────────────────────────────

/// Safely convert a raw pointer + length into a mutable slice.
///
/// # Safety
///
/// When `len > 0`, `ptr` must be valid for `len` bytes and properly aligned.
unsafe fn raw_mut_slice<'a>(ptr: *mut u8, len: usize) -> &'a mut [u8] {
    if len == 0 { &mut [] } else { unsafe { std::slice::from_raw_parts_mut(ptr, len) } }
}

/// Safely convert a raw pointer + length into an immutable slice.
///
/// # Safety
///
/// When `len > 0`, `ptr` must be valid for `len` bytes and properly aligned.
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

fn detect_protocol_version(dtls: &dimpl::Dtls) -> u16 {
    let dbg = format!("{:?}", dtls);
    if dbg.contains("12") { 0x0303 } else { 0x0304 }
}

fn map_dimpl_error(e: &dimpl::Error) -> DtlsResult {
    match e {
        dimpl::Error::CertificateError(_) => DtlsResult::CertificateError,
        _ => DtlsResult::DtlsError,
    }
}

fn drain_output(s: &mut DtlsSession) -> Result<(), dimpl::Error> {
    s.dtls.handle_timeout(Instant::now())?;
    s.next_timeout = None;
    loop {
        match s.dtls.poll_output(&mut s.poll_buf) {
            dimpl::Output::Packet(data) => s.outgoing_pkts.push_back(data.to_vec()),
            dimpl::Output::Connected => {
                s.handshake_complete = true;
                s.protocol_version = detect_protocol_version(&s.dtls);
            }
            dimpl::Output::ApplicationData(data) => s.app_data.push_back(data.to_vec()),
            dimpl::Output::PeerCert(der) => {
                let der = der.to_vec();
                if !s.peer_certs.is_empty() {
                    let len_bytes = (der.len() as u16).to_le_bytes();
                    s.peer_chain_framed.extend_from_slice(&len_bytes);
                    s.peer_chain_framed.extend_from_slice(&der);
                }
                s.peer_certs.push(der);
            }
            dimpl::Output::Timeout(t) => {
                s.next_timeout = Some(t);
                break;
            }
            dimpl::Output::KeyingMaterial(..) => {}
        }
    }
    Ok(())
}

fn make_status(s: &DtlsSession) -> DtlsOpStatus {
    let now = Instant::now();
    DtlsOpStatus {
        timeout_ms: s.next_timeout.map_or(-1, |t| t.saturating_duration_since(now).as_millis() as i64),
        is_handshaking: u8::from(!s.handshake_complete),
    }
}

fn flush(s: &mut DtlsSession, out_pkts: &mut [u8]) -> DtlsCallResult {
    if let Err(e) = drain_output(s) {
        let code = map_dimpl_error(&e);
        set_last_error(e.to_string());
        return DtlsCallResult::err(code);
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
            DtlsCallResult::err(DtlsResult::BufferTooSmall)
        }
    }
}

// ── FFI exports ──────────────────────────────────────────

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

    let cfg = Arc::new(dimpl::Config::builder().require_client_certificate(require_client_certificate).build().expect("valid config"));
    let now = Instant::now();
    let (mut dtls, protocol_version) = match version {
        0x0C00 => (dimpl::Dtls::new_12(cfg, cert, now), 0x0303u16),
        0x3000 => (dimpl::Dtls::new_13(cfg, cert, now), 0x0304u16),
        _ => (dimpl::Dtls::new_auto(cfg, cert, now), 0u16),
    };
    dtls.set_active(is_client);

    Ok(DtlsSession {
        dtls,
        handshake_complete: false,
        app_data: VecDeque::new(),
        outgoing_pkts: VecDeque::new(),
        peer_certs: Vec::new(),
        peer_chain_framed: Vec::new(),
        next_timeout: None,
        poll_buf: vec![0u8; 65536],
        protocol_version,
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dtls_session_new(config: *const DtlsSessionNewConfig, out_session: *mut *mut DtlsSession, out_pkts: *mut u8, out_pkts_cap: usize) -> DtlsCallResult {
    catch_unwind_call_result(|| {
        if config.is_null() || out_session.is_null() || (out_pkts_cap > 0 && out_pkts.is_null()) {
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
        if session.is_null() || (out_pkts_cap > 0 && out_pkts.is_null()) {
            set_last_error("null pointer");
            return DtlsCallResult::err(DtlsResult::InvalidInput);
        }
        // Copy input first via raw pointer to avoid aliasing UB when
        // the caller passes overlapping input/output buffers.
        let input_copy = if input_len > 0 {
            if input.is_null() {
                set_last_error("null input pointer with non-zero length");
                return DtlsCallResult::err(DtlsResult::InvalidInput);
            }
            let mut v = vec![0u8; input_len];
            unsafe { std::ptr::copy_nonoverlapping(input, v.as_mut_ptr(), input_len) };
            Some(v)
        } else {
            None
        };
        let s = unsafe { &mut *session };
        let out_buf = unsafe { raw_mut_slice(out_pkts, out_pkts_cap) };
        if let Some(ref data) = input_copy
            && let Err(e) = s.dtls.handle_packet(data)
        {
            let code = map_dimpl_error(&e);
            set_last_error(e.to_string());
            return DtlsCallResult::err(code);
        }
        flush(s, out_buf)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dtls_session_handle_timeout(session: *mut DtlsSession, out_pkts: *mut u8, out_pkts_cap: usize) -> DtlsCallResult {
    catch_unwind_call_result(|| {
        if session.is_null() || (out_pkts_cap > 0 && out_pkts.is_null()) {
            set_last_error("null pointer");
            return DtlsCallResult::err(DtlsResult::InvalidInput);
        }
        flush(unsafe { &mut *session }, unsafe { raw_mut_slice(out_pkts, out_pkts_cap) })
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dtls_session_send(session: *mut DtlsSession, data: *const u8, data_len: usize, out_pkts: *mut u8, out_pkts_cap: usize) -> DtlsCallResult {
    catch_unwind_call_result(|| {
        if session.is_null() || (out_pkts_cap > 0 && out_pkts.is_null()) {
            set_last_error("null pointer");
            return DtlsCallResult::err(DtlsResult::InvalidInput);
        }
        // Copy input first via raw pointer to avoid aliasing UB when
        // the caller passes overlapping data/output buffers.
        let data_copy = if data_len > 0 {
            if data.is_null() {
                set_last_error("null data pointer with non-zero length");
                return DtlsCallResult::err(DtlsResult::InvalidInput);
            }
            let mut v = vec![0u8; data_len];
            unsafe { std::ptr::copy_nonoverlapping(data, v.as_mut_ptr(), data_len) };
            Some(v)
        } else {
            None
        };
        let s = unsafe { &mut *session };
        let out_buf = unsafe { raw_mut_slice(out_pkts, out_pkts_cap) };
        if let Some(ref payload) = data_copy
            && let Err(e) = s.dtls.send_application_data(payload)
        {
            let code = map_dimpl_error(&e);
            set_last_error(e.to_string());
            return DtlsCallResult::err(code);
        }
        flush(s, out_buf)
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
                DtlsCallResult::err(DtlsResult::BufferTooSmall)
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
            return DtlsCallResult::err(DtlsResult::DtlsError);
        }
        let (cert_ptr, cert_len) = s.peer_certs.first().map_or((std::ptr::null(), 0), |c| (c.as_ptr(), c.len()));
        let out = unsafe { &mut *out };
        out.protocol = s.protocol_version;
        out.peer_cert_ptr = cert_ptr;
        out.peer_cert_len = cert_len;
        out.peer_chain_ptr = if s.peer_chain_framed.is_empty() { std::ptr::null() } else { s.peer_chain_framed.as_ptr() };
        out.peer_chain_len = s.peer_chain_framed.len();
        DtlsCallResult {
            code: DtlsResult::Ok,
            bytes_written: 0,
            bytes_read: 0,
            status: make_status(s),
        }
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
