use std::io;
use std::path::PathBuf;

use serde::Serialize;

/// Stable application error codes returned to CLI and MCP clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    PtUnavailable,
    PermissionDenied,
    UnsupportedPerf,
    UnsupportedPtConfig,
    InvalidArgument,
    SessionBusy,
    Busy,
    NotReady,
    NotFound,
    DetailNotReady,
    DecodeFailed,
    MissingImage,
    LimitExceeded,
    Incomparable,
    Cancelled,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PtUnavailable => "PT_UNAVAILABLE",
            Self::PermissionDenied => "PERMISSION_DENIED",
            Self::UnsupportedPerf => "UNSUPPORTED_PERF",
            Self::UnsupportedPtConfig => "UNSUPPORTED_PT_CONFIG",
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::SessionBusy => "SESSION_BUSY",
            Self::Busy => "BUSY",
            Self::NotReady => "NOT_READY",
            Self::NotFound => "NOT_FOUND",
            Self::DetailNotReady => "DETAIL_NOT_READY",
            Self::DecodeFailed => "DECODE_FAILED",
            Self::MissingImage => "MISSING_IMAGE",
            Self::LimitExceeded => "LIMIT_EXCEEDED",
            Self::Incomparable => "INCOMPARABLE",
            Self::Cancelled => "CANCELLED",
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Application error with a stable code, reason, and optional next action.
#[derive(Debug, Clone, thiserror::Error, Serialize)]
#[error("{code}: {reason}")]
pub struct Error {
    pub code: ErrorCode,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_action: Option<String>,
}

impl Error {
    pub fn new(code: ErrorCode, reason: impl Into<String>) -> Self {
        Self {
            code,
            reason: reason.into(),
            next_action: None,
        }
    }

    pub fn with_next(mut self, next: impl Into<String>) -> Self {
        self.next_action = Some(next.into());
        self
    }

    pub fn invalid_argument(reason: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidArgument, reason)
    }

    pub fn not_found(reason: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, reason)
    }

    pub fn busy(reason: impl Into<String>) -> Self {
        Self::new(ErrorCode::Busy, reason)
    }

    pub fn limit(reason: impl Into<String>) -> Self {
        Self::new(ErrorCode::LimitExceeded, reason)
    }

    pub fn decode_failed(reason: impl Into<String>) -> Self {
        Self::new(ErrorCode::DecodeFailed, reason)
    }

    pub fn cancelled(reason: impl Into<String>) -> Self {
        Self::new(ErrorCode::Cancelled, reason)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        match err.kind() {
            io::ErrorKind::NotFound => Self::not_found(err.to_string()),
            io::ErrorKind::PermissionDenied => {
                Self::new(ErrorCode::PermissionDenied, err.to_string())
                    .with_next("Check file permissions and perf_event_paranoid")
            }
            io::ErrorKind::WouldBlock => Self::busy(err.to_string()),
            _ => Self::new(ErrorCode::DecodeFailed, err.to_string()),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn io_ctx(err: io::Error, path: impl Into<PathBuf>, what: &str) -> Error {
    Error::new(
        match err.kind() {
            io::ErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
            io::ErrorKind::NotFound => ErrorCode::NotFound,
            _ => ErrorCode::LimitExceeded,
        },
        format!("{what} {}: {err}", path.into().display()),
    )
}
