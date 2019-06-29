use chrono::{DateTime, Duration, Utc};
use serde_derive::*;

use crate::ValidationError;

/// Time-related validation options.
#[derive(Debug, Clone, Copy)]
pub struct TimeOptions {
    /// Leeway to use during validation.
    pub leeway: Duration,
    /// Current time to check against. If not set, the current time will be set to `Utc::now()`.
    pub current_time: Option<DateTime<Utc>>,
}

impl Default for TimeOptions {
    fn default() -> Self {
        Self {
            leeway: Duration::seconds(60),
            current_time: None,
        }
    }
}

/// A structure with no fields that can be used as a type parameter to `Claims`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Empty {}

/// Claims encoded in a token.
///
/// Claims are comprised of a "standard" part (`exp`, `nbf` and `iat` claims as per [JWT spec]),
/// and custom fields. `iss`, `sub` and `aud` claims are not in the standard part
/// due to a variety of data types they can be reasonably represented by.
///
/// [JWT spec]: https://tools.ietf.org/html/rfc7519#section-4.1
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Claims<T> {
    /// Expiration date of the token.
    #[serde(
        rename = "exp",
        default,
        skip_serializing_if = "Option::is_none",
        with = "self::serde_timestamp"
    )]
    pub expiration_date: Option<DateTime<Utc>>,

    /// Minimum date at which token is valid.
    #[serde(
        rename = "nbf",
        default,
        skip_serializing_if = "Option::is_none",
        with = "self::serde_timestamp"
    )]
    pub not_before: Option<DateTime<Utc>>,

    /// Date of token issuance.
    #[serde(
        rename = "iat",
        default,
        skip_serializing_if = "Option::is_none",
        with = "self::serde_timestamp"
    )]
    pub issued_at: Option<DateTime<Utc>>,

    /// Custom claims.
    #[serde(flatten)]
    pub custom: T,
}

impl Claims<Empty> {
    /// Creates an empty claims instance.
    pub fn empty() -> Self {
        Self {
            expiration_date: None,
            not_before: None,
            issued_at: None,
            custom: Empty {},
        }
    }
}

impl<T> Claims<T> {
    /// Creates a new instance with the provided custom claims.
    pub fn new(custom_claims: T) -> Self {
        Self {
            expiration_date: None,
            not_before: None,
            issued_at: None,
            custom: custom_claims,
        }
    }

    /// Sets `expiration_date` claim so that the token has the specified `duration`.
    pub fn set_duration(self, duration: Duration) -> Self {
        Self {
            expiration_date: Some(Utc::now() + duration),
            ..self
        }
    }

    /// Atomically sets `issued_at` and `expiration_date` claims: first to the current time,
    /// and the second to match the specified `duration` of the token.
    pub fn set_duration_and_issuance(self, duration: Duration) -> Self {
        let issued_at = Utc::now();
        Self {
            expiration_date: Some(issued_at + duration),
            issued_at: Some(issued_at),
            ..self
        }
    }

    /// Sets the `nbf` claim.
    pub fn set_not_before(self, moment: DateTime<Utc>) -> Self {
        Self {
            not_before: Some(moment),
            ..self
        }
    }

    /// Validates the expiration claim.
    ///
    /// This method will return an error if the claims do not feature an expiration date,
    /// or if it is in the past (subject to the provided `options`).
    pub fn validate_expiration(&self, options: TimeOptions) -> Result<&Self, ValidationError> {
        if let Some(expiration) = self.expiration_date {
            let current_time = options.current_time.unwrap_or_else(Utc::now);
            if current_time > expiration + options.leeway {
                Err(ValidationError::Expired)
            } else {
                Ok(self)
            }
        } else {
            Err(ValidationError::NoClaim)
        }
    }

    /// Validates the maturity date (`nbf` claim).
    ///
    /// This method will return an error if the claims do not feature a maturity date,
    /// or if it is in the future (subject to the provided `options`).
    pub fn validate_maturity(&self, options: TimeOptions) -> Result<&Self, ValidationError> {
        if let Some(not_before) = self.not_before {
            let current_time = options.current_time.unwrap_or_else(Utc::now);
            if current_time < not_before - options.leeway {
                Err(ValidationError::NotMature)
            } else {
                Ok(self)
            }
        } else {
            Err(ValidationError::NoClaim)
        }
    }
}

mod serde_timestamp {
    use chrono::{offset::TimeZone, DateTime, Utc};
    use serde::{
        de::{Error as DeError, Visitor},
        Deserializer, Serializer,
    };

    use std::{convert::TryFrom, fmt};

    struct TimestampVisitor;

    impl<'de> Visitor<'de> for TimestampVisitor {
        type Value = DateTime<Utc>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("UTC timestamp")
        }

        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            Ok(Utc.timestamp(value, 0))
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            let value = i64::try_from(value).map_err(DeError::custom)?;
            Ok(Utc.timestamp(value, 0))
        }
    }

    pub fn serialize<S: Serializer>(
        time: &Option<DateTime<Utc>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        // `unwrap` is safe due to `skip_serializing_if` option
        serializer.serialize_i64(time.unwrap().timestamp())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<DateTime<Utc>>, D::Error> {
        deserializer.deserialize_i64(TimestampVisitor).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;

    #[test]
    fn empty_claims_can_be_serialized() {
        let mut claims = Claims::empty();
        assert!(serde_json::to_string(&claims).is_ok());
        assert!(serde_cbor::to_vec(&claims).is_ok());
        claims.expiration_date = Some(Utc::now());
        assert!(serde_json::to_string(&claims).is_ok());
        assert!(serde_cbor::to_vec(&claims).is_ok());
        claims.not_before = Some(Utc::now());
        assert!(serde_json::to_string(&claims).is_ok());
        assert!(serde_cbor::to_vec(&claims).is_ok());
    }

    #[test]
    fn expired_claim() {
        let mut claims = Claims::empty();
        assert_matches!(
            claims
                .validate_expiration(TimeOptions::default())
                .unwrap_err(),
            ValidationError::NoClaim
        );

        claims.expiration_date = Some(Utc::now() - Duration::hours(1));
        assert_matches!(
            claims
                .validate_expiration(TimeOptions::default())
                .unwrap_err(),
            ValidationError::Expired
        );

        claims.expiration_date = Some(Utc::now() - Duration::seconds(10));
        // With the default leeway, this claim is still valid.
        assert!(claims.validate_expiration(TimeOptions::default()).is_ok());
        // If we set leeway lower, then the claim will be considered expired.
        assert_matches!(
            claims
                .validate_expiration(TimeOptions {
                    leeway: Duration::seconds(5),
                    ..Default::default()
                })
                .unwrap_err(),
            ValidationError::Expired
        );
    }

    #[test]
    fn immature_claim() {
        let mut claims = Claims::empty();
        assert_matches!(
            claims
                .validate_maturity(TimeOptions::default())
                .unwrap_err(),
            ValidationError::NoClaim
        );

        claims.not_before = Some(Utc::now() + Duration::hours(1));
        assert_matches!(
            claims
                .validate_maturity(TimeOptions::default())
                .unwrap_err(),
            ValidationError::NotMature
        );

        claims.not_before = Some(Utc::now() + Duration::seconds(10));
        // With the default leeway, this claim is still valid.
        assert!(claims.validate_maturity(TimeOptions::default()).is_ok());
        // If we set leeway lower, then the claim will be considered expired.
        assert_matches!(
            claims
                .validate_maturity(TimeOptions {
                    leeway: Duration::seconds(5),
                    ..Default::default()
                })
                .unwrap_err(),
            ValidationError::NotMature
        );
    }
}
