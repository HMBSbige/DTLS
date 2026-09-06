#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use crate::error::{DtlsError, DtlsResult};

pub(super) enum SessionInput<'a> {
    Packet(&'a [u8]),
    ApplicationData(&'a [u8]),
    Timeout,
    Close,
}

pub(super) struct SessionStatus {
    pub(super) next_timeout: Option<Instant>,
    pub(super) is_handshaking: bool,
    pub(super) is_local_closed: bool,
    pub(super) is_peer_closed: bool,
}

pub(crate) struct DtlsSession {
    dtls: dimpl::Dtls,
    handshake_complete: bool,
    local_closed: bool,
    peer_closed: bool,
    app_data: VecDeque<Vec<u8>>,
    outgoing_packets: VecDeque<Vec<u8>>,
    peer_cert: Option<Vec<u8>>,
    next_timeout: Option<Instant>,
    poll_buffer: Vec<u8>,
    protocol_version: Option<dimpl::ProtocolVersion>,
    fatal_error: Option<DtlsError>,
}

impl DtlsSession {
    pub(super) fn new(
        cert_der: &[u8],
        key_der: &[u8],
        is_client: bool,
        min_version: Option<dimpl::ProtocolVersion>,
        max_version: Option<dimpl::ProtocolVersion>,
        require_client_certificate: bool,
    ) -> Result<Self, DtlsError> {
        use dimpl::ProtocolVersion;

        let create_dtls = match (min_version.unwrap_or(ProtocolVersion::DTLS1_2), max_version.unwrap_or(ProtocolVersion::DTLS1_3)) {
            (ProtocolVersion::DTLS1_2, ProtocolVersion::DTLS1_2) => dimpl::Dtls::new_12,
            (ProtocolVersion::DTLS1_3, ProtocolVersion::DTLS1_3) => dimpl::Dtls::new_13,
            (ProtocolVersion::DTLS1_2, ProtocolVersion::DTLS1_3) => dimpl::Dtls::new_auto,
            _ => return Err(DtlsError::new(DtlsResult::InvalidInput, "invalid DTLS version range")),
        };

        if cert_der.is_empty() != key_der.is_empty() {
            return Err(DtlsError::new(DtlsResult::InvalidInput, "cert and key must be provided together"));
        }

        let certificate = if cert_der.is_empty() {
            dimpl::certificate::generate_self_signed_certificate().map_err(|error| DtlsError::new(DtlsResult::CertificateError, error.to_string()))?
        } else {
            dimpl::DtlsCertificate {
                certificate: cert_der.to_vec(),
                private_key: key_der.to_vec(),
            }
        };
        let config = Arc::new(dimpl::Config::builder().require_client_certificate(require_client_certificate).build()?);
        let now = Instant::now();
        let mut dtls = create_dtls(config, certificate, now);
        dtls.set_active(is_client);

        Ok(Self {
            dtls,
            handshake_complete: false,
            local_closed: false,
            peer_closed: false,
            app_data: VecDeque::new(),
            outgoing_packets: VecDeque::new(),
            peer_cert: None,
            next_timeout: None,
            poll_buffer: vec![0; 65536],
            protocol_version: None,
            fatal_error: None,
        })
    }

    pub(super) fn status(&self) -> SessionStatus {
        let is_terminal = self.local_closed || self.fatal_error.is_some();
        SessionStatus {
            next_timeout: self.next_timeout.filter(|_| !is_terminal),
            is_handshaking: !self.handshake_complete && !is_terminal,
            is_local_closed: self.local_closed,
            is_peer_closed: self.peer_closed,
        }
    }

    pub(super) fn ensure_active(&self) -> Result<(), DtlsError> {
        match &self.fatal_error {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }

    pub(super) fn process(&mut self, input: SessionInput<'_>) -> Result<(), DtlsError> {
        self.ensure_active()?;
        let result = match input {
            SessionInput::Packet(data) if !data.is_empty() => self.dtls.handle_packet(data),
            SessionInput::ApplicationData(data) if !data.is_empty() => self.dtls.send_application_data(data),
            SessionInput::Close if !self.local_closed => {
                let result = self.dtls.close();
                self.local_closed = result.is_ok();
                result
            }
            _ => Ok(()),
        };
        self.record_result(result)?;
        self.drain_output()
    }

    pub(super) fn write_outgoing(&mut self, buffer: &mut [u8]) -> Result<usize, DtlsError> {
        let mut written = 0;
        while let Some(packet) = self.outgoing_packets.front() {
            let Ok(length) = u16::try_from(packet.len()) else {
                self.outgoing_packets.pop_front();
                continue;
            };
            let frame_length = 2 + packet.len();
            if frame_length > buffer.len() - written {
                if written == 0 {
                    return Err(DtlsError::new(DtlsResult::BufferTooSmall, "output buffer too small"));
                }
                break;
            }
            let frame = &mut buffer[written..written + frame_length];
            frame[..2].copy_from_slice(&length.to_le_bytes());
            frame[2..].copy_from_slice(packet);
            written += frame_length;
            self.outgoing_packets.pop_front();
        }
        Ok(written)
    }

    pub(super) fn receive(&mut self, buffer: &mut [u8]) -> Result<Option<usize>, DtlsError> {
        let Some(data) = self.app_data.front() else {
            return Ok(None);
        };
        if data.len() > buffer.len() {
            return Err(DtlsError::new(DtlsResult::BufferTooSmall, "output buffer too small for datagram"));
        }
        let length = data.len();
        buffer[..length].copy_from_slice(data);
        self.app_data.pop_front();
        Ok(Some(length))
    }

    pub(super) fn protocol_version(&self) -> Result<Option<dimpl::ProtocolVersion>, DtlsError> {
        self.ensure_connected()?;
        Ok(self.protocol_version)
    }

    pub(super) fn peer_certificate(&self) -> Result<&[u8], DtlsError> {
        self.ensure_connected()?;
        Ok(self.peer_cert.as_deref().unwrap_or_default())
    }

    fn ensure_connected(&self) -> Result<(), DtlsError> {
        if self.handshake_complete {
            Ok(())
        } else {
            Err(DtlsError::new(DtlsResult::DtlsError, "handshake not complete"))
        }
    }

    fn record_result(&mut self, result: Result<(), dimpl::Error>) -> Result<(), DtlsError> {
        result.map_err(|error| {
            let error = DtlsError::from(error);
            self.fatal_error = Some(error.clone());
            error
        })
    }

    fn drain_output(&mut self) -> Result<(), DtlsError> {
        let result = self.dtls.handle_timeout(Instant::now());
        self.record_result(result)?;
        self.next_timeout = None;
        loop {
            match self.dtls.poll_output(&mut self.poll_buffer) {
                dimpl::Output::Packet(data) => self.outgoing_packets.push_back(data.to_vec()),
                dimpl::Output::BufferTooSmall { needed } => self.poll_buffer.resize(needed, 0),
                dimpl::Output::Connected => {
                    self.handshake_complete = true;
                    self.protocol_version = self.protocol_version.or_else(|| self.dtls.protocol_version());
                }
                dimpl::Output::ApplicationData(data) => self.app_data.push_back(data.to_vec()),
                dimpl::Output::PeerCert(der) => self.peer_cert = Some(der.to_vec()),
                dimpl::Output::Timeout(timeout) => {
                    self.next_timeout = Some(timeout);
                    break;
                }
                dimpl::Output::CloseNotify => self.peer_closed = true,
                _ => {}
            }
        }
        // dimpl 要等到 poll_output 返回 Timeout 后才更新关闭状态。
        self.local_closed |= self.dtls.is_closed();
        Ok(())
    }
}
