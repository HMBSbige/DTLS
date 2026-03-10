#![allow(clippy::missing_safety_doc)]

use std::cell::RefCell;
use std::ffi::c_char;

/// `DtlsCallResult.code` 使用的结果码。
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

thread_local! {
    static LAST_ERROR: RefCell<String> = const { RefCell::new(String::new()) };
}

/// 为当前线程保存最近一次错误消息。
pub(crate) fn set_last_error(msg: impl Into<String>) {
    LAST_ERROR.with_borrow_mut(|e| *e = msg.into());
}

/// 将最近一次错误消息拷贝到调用方提供的缓冲区。
///
/// 返回实际写入字节数（不含末尾 NUL，长度不足时会截断）；失败时返回 -1。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dtls_last_error_message(buf: *mut c_char, buf_len: i32) -> i32 {
    if buf.is_null() || buf_len <= 0 {
        return -1;
    }
    let buf = unsafe { std::slice::from_raw_parts_mut(buf as *mut u8, buf_len as usize) };
    LAST_ERROR.with_borrow(|msg| {
        let copy_len = msg.len().min(buf.len() - 1);
        buf[..copy_len].copy_from_slice(&msg.as_bytes()[..copy_len]);
        buf[copy_len] = 0;
        copy_len as i32
    })
}
