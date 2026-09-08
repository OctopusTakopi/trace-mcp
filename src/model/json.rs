use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Decimal-string counts so MCP JSON never switches number/string by magnitude.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Count(pub u64);

impl Serialize for Count {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for Count {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse::<u64>()
            .map(Count)
            .map_err(serde::de::Error::custom)
    }
}

/// Virtual or file addresses serialized as hex strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Address(pub u64);

impl Serialize for Address {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("0x{:x}", self.0))
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        parse_address(&s)
            .map(Address)
            .map_err(serde::de::Error::custom)
    }
}

pub fn parse_address(s: &str) -> Result<u64, String> {
    let t = s.trim();
    let hex = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    u64::from_str_radix(hex, 16).map_err(|e| e.to_string())
}

/// Absolute perf/TSC values as strings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AbsTime(pub String);
