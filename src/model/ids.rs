use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Error, Result};

macro_rules! typed_id {
    ($name:ident, $prefix:literal) => {
        #[derive(Clone, Debug, Eq, JsonSchema)]
        pub struct $name(String);

        impl $name {
            pub const PREFIX: &'static str = $prefix;

            pub fn generate() -> Self {
                Self(format!("{}_{}", $prefix, random_hex(8)))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn from_raw(raw: impl Into<String>) -> Result<Self> {
                let raw = raw.into();
                if raw.is_empty() || raw.contains('/') || raw.contains('\0') {
                    return Err(Error::invalid_argument(format!(
                        "invalid {} {raw}",
                        stringify!($name)
                    )));
                }
                Ok(Self(raw))
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.0 == other.0
            }
        }

        impl Hash for $name {
            fn hash<H: Hasher>(&self, state: &mut H) {
                self.0.hash(state);
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(
                &self,
                serializer: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(
                deserializer: D,
            ) -> std::result::Result<Self, D::Error> {
                let s = String::deserialize(deserializer)?;
                Self::from_raw(s).map_err(serde::de::Error::custom)
            }
        }

        impl FromStr for $name {
            type Err = Error;
            fn from_str(s: &str) -> Result<Self> {
                Self::from_raw(s)
            }
        }
    };
}

typed_id!(SessionId, "sess");
typed_id!(SnapshotId, "s");
typed_id!(AnalysisId, "a");
typed_id!(ReportId, "r");
typed_id!(JobId, "j");
typed_id!(ThreadId, "t");
typed_id!(RequestId, "req");

/// Local row number inside one analysis. Never compared across analyses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LocalId(pub u32);

impl LocalId {
    pub const fn new(v: u32) -> Self {
        Self(v)
    }
}

/// Namespaced identity serialized as `{analysis}:{kind}{local}`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NamespacedId {
    pub analysis: AnalysisId,
    pub kind: IdKind,
    pub local: LocalId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IdKind {
    Event,
    Span,
    Function,
    Location,
    Gap,
}

impl IdKind {
    fn tag(self) -> &'static str {
        match self {
            Self::Event => "e",
            Self::Span => "sp",
            Self::Function => "f",
            Self::Location => "l",
            Self::Gap => "g",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "e" => Some(Self::Event),
            "sp" => Some(Self::Span),
            "f" => Some(Self::Function),
            "l" => Some(Self::Location),
            "g" => Some(Self::Gap),
            _ => None,
        }
    }
}

impl NamespacedId {
    pub fn new(analysis: AnalysisId, kind: IdKind, local: LocalId) -> Self {
        Self {
            analysis,
            kind,
            local,
        }
    }

    pub fn render(&self) -> String {
        format!("{}:{}{}", self.analysis, self.kind.tag(), self.local.0)
    }
}

impl fmt::Display for NamespacedId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

impl Serialize for NamespacedId {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.render())
    }
}

impl<'de> Deserialize<'de> for NamespacedId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        parse_namespaced(&s).map_err(serde::de::Error::custom)
    }
}

pub fn parse_namespaced(s: &str) -> Result<NamespacedId> {
    let (analysis, rest) = s
        .rsplit_once(':')
        .ok_or_else(|| Error::invalid_argument(format!("expected namespaced id, got {s}")))?;
    let kind_len = if rest.starts_with("sp") { 2 } else { 1 };
    let (kind_s, num) = rest.split_at(kind_len);
    let kind = IdKind::parse(kind_s)
        .ok_or_else(|| Error::invalid_argument(format!("unknown id kind in {s}")))?;
    let local = num
        .parse::<u32>()
        .map(LocalId)
        .map_err(|_| Error::invalid_argument(format!("invalid local id in {s}")))?;
    Ok(NamespacedId {
        analysis: AnalysisId::from_raw(analysis)?,
        kind,
        local,
    })
}

pub fn random_hex(n_bytes: usize) -> String {
    let mut buf = vec![0u8; n_bytes];
    if getrandom::fill(&mut buf).is_err() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        buf = format!("{nanos:032x}").into_bytes();
        buf.truncate(n_bytes.max(8));
    }
    hex::encode(&buf[..n_bytes.min(buf.len())])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespaced_roundtrip() {
        let id = NamespacedId::new(
            AnalysisId::from_raw("a_1").unwrap(),
            IdKind::Event,
            LocalId(7),
        );
        let s = id.render();
        assert_eq!(s, "a_1:e7");
        let parsed = parse_namespaced(&s).unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn span_kind_uses_two_char_tag() {
        let id = NamespacedId::new(
            AnalysisId::from_raw("a_1").unwrap(),
            IdKind::Span,
            LocalId(3),
        );
        assert_eq!(id.render(), "a_1:sp3");
        assert_eq!(parse_namespaced("a_1:sp3").unwrap(), id);
    }
}
