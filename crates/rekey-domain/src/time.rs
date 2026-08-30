use serde::{Deserialize, Serialize};

/// Milliseconds since the Unix epoch. The domain never reads a clock itself;
/// runtimes inject values through this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Timestamp(i64);

impl Timestamp {
    pub const fn from_unix_ms(ms: i64) -> Self {
        Self(ms)
    }

    pub const fn as_unix_ms(&self) -> i64 {
        self.0
    }

    pub const fn saturating_add_ms(&self, ms: i64) -> Self {
        Self(self.0.saturating_add(ms))
    }
}
