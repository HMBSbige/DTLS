use std::collections::VecDeque;
use std::time::Instant;

pub(crate) struct DtlsSession {
    pub(crate) dtls: dimpl::Dtls,
    pub(crate) handshake_complete: bool,
    pub(crate) app_data: VecDeque<Vec<u8>>,
    pub(crate) outgoing_pkts: VecDeque<Vec<u8>>,
    pub(crate) peer_certs: Vec<Vec<u8>>,
    pub(crate) peer_chain_framed: Vec<u8>,
    pub(crate) next_timeout: Option<Instant>,
    pub(crate) poll_buf: Vec<u8>,
    pub(crate) protocol_version: u16,
}
