use std::collections::HashSet;
use std::convert::TryInto;

use coarsetime::{Clock, Duration, UnixTimeStamp};
use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use rand::RngCore;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::common::VerificationOptions;
use crate::error::*;
use crate::serde_additions;

pub const DEFAULT_TIME_TOLERANCE_SECS: u64 = 900;

/// Type representing the fact that no application-defined claims is necessary.
#[derive(Copy, Clone, Default, Debug, Serialize, Deserialize)]
pub struct NoCustomClaims {}

/// Depending on applications, the `audiences` property may be either a set or a
/// string. We support both.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Audiences {
    AsSet(HashSet<String>),
    AsString(String),
}

impl Audiences {
    /// Return `true` if the audiences are represented as a set.
    pub fn is_set(&self) -> bool {
        matches!(self, Audiences::AsSet(_))
    }

    /// Return `true` if the audiences are represented as a string.
    pub fn is_string(&self) -> bool {
        matches!(self, Audiences::AsString(_))
    }

    /// Return `true` if the audiences include any of the `allowed_audiences`
    /// entries
    pub fn contains(&self, allowed_audiences: &HashSet<String>) -> bool {
        match self {
            Audiences::AsString(audience) => allowed_audiences.contains(audience),
            Audiences::AsSet(audiences) => {
                audiences.intersection(allowed_audiences).next().is_some()
            }
        }
    }

    /// Get the audiences as a set
    pub fn into_set(self) -> HashSet<String> {
        match self {
            Audiences::AsSet(audiences_set) => audiences_set,
            Audiences::AsString(audiences) => {
                let mut audiences_set = HashSet::new();
                if !audiences.is_empty() {
                    audiences_set.insert(audiences);
                }
                audiences_set
            }
        }
    }

    /// Get the audiences as a string.
    /// If it was originally serialized as a set, it can be only converted to a
    /// string if it contains at most one element.
    pub fn into_string(self) -> Result<String, Error> {
        match self {
            Audiences::AsString(audiences_str) => Ok(audiences_str),
            Audiences::AsSet(audiences) => {
                if audiences.len() > 1 {
                    bail!(JWTError::TooManyAudiences);
                }
                Ok(audiences
                    .iter()
                    .next()
                    .map(|x| x.to_string())
                    .unwrap_or_default())
            }
        }
    }
}

impl TryInto<String> for Audiences {
    type Error = Error;

    fn try_into(self) -> Result<String, Error> {
        self.into_string()
    }
}

impl From<Audiences> for HashSet<String> {
    fn from(audiences: Audiences) -> HashSet<String> {
        audiences.into_set()
    }
}

impl<T: ToString> From<T> for Audiences {
    fn from(audience: T) -> Self {
        Audiences::AsString(audience.to_string())
    }
}

/// A set of JWT claims.
///
/// The `CustomClaims` parameter can be set to `NoCustomClaims` if only standard
/// claims are used, or to a user-defined type that must be `serde`-serializable
/// if custom claims are required.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JWTClaims<CustomClaims> {

    /// Custom (application-defined) claims
    #[serde(flatten)]
    pub custom: CustomClaims,
}

pub struct Claims;

impl Claims {
    /// Create a new set of claims, without custom data, expiring in
    /// `valid_for`.
    pub fn create(valid_for: Duration) -> JWTClaims<NoCustomClaims> {
        let now = Some(Clock::now_since_epoch());
        JWTClaims {
            custom: NoCustomClaims {},
        }
    }

    /// Create a new set of claims, with custom data, expiring in `valid_for`.
    pub fn with_custom_claims<CustomClaims: Serialize + DeserializeOwned>(
        custom_claims: CustomClaims,
    ) -> JWTClaims<CustomClaims> {
        JWTClaims {
            custom: custom_claims,
        }
    }
}
