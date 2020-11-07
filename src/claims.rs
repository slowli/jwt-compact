use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::ValidationError;

/// Time-related validation options.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct TimeOptions<F = fn() -> DateTime<Utc>> {
    /// Leeway to use during validation.
    pub leeway: Duration,
    /// Source of the current timestamps.
    pub clock_fn: F,
}

impl<F: Fn() -> DateTime<Utc>> TimeOptions<F> {
    /// Creates options based on the specified time leeway and clock function.
    pub fn new(leeway: Duration, clock_fn: F) -> Self {
        Self { leeway, clock_fn }
    }
}

impl TimeOptions {
    /// Creates options based on the specified time leeway. The clock source is [`Utc::now()`].
    #[cfg(feature = "clock")]
    #[cfg_attr(docsrs, doc(cfg(feature = "clock")))]
    pub fn from_leeway(leeway: Duration) -> Self {
        Self {
            leeway,
            clock_fn: Utc::now,
        }
    }
}

#[cfg(feature = "clock")]
impl Default for TimeOptions {
    fn default() -> Self {
        Self::from_leeway(Duration::seconds(60))
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
#[non_exhaustive]
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
    #[cfg(feature = "clock")]
    #[cfg_attr(docsrs, doc(cfg(feature = "clock")))]
    pub fn set_duration(self, duration: Duration) -> Self {
        Self {
            expiration_date: Some(Utc::now() + duration),
            ..self
        }
    }

    /// Atomically sets `issued_at` and `expiration_date` claims: first to the current time,
    /// and the second to match the specified `duration` of the token.
    #[cfg(feature = "clock")]
    #[cfg_attr(docsrs, doc(cfg(feature = "clock")))]
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
    pub fn validate_expiration<F>(&self, options: &TimeOptions<F>) -> Result<&Self, ValidationError>
    where
        F: Fn() -> DateTime<Utc>,
    {
        self.expiration_date
            .map_or(Err(ValidationError::NoClaim), |expiration| {
                if (options.clock_fn)() > expiration + options.leeway {
                    Err(ValidationError::Expired)
                } else {
                    Ok(self)
                }
            })
    }

    /// Validates the maturity date (`nbf` claim).
    ///
    /// This method will return an error if the claims do not feature a maturity date,
    /// or if it is in the future (subject to the provided `options`).
    pub fn validate_maturity<F>(&self, options: &TimeOptions<F>) -> Result<&Self, ValidationError>
    where
        F: Fn() -> DateTime<Utc>,
    {
        self.not_before
            .map_or(Err(ValidationError::NoClaim), |not_before| {
                if (options.clock_fn)() < not_before - options.leeway {
                    Err(ValidationError::NotMature)
                } else {
                    Ok(self)
                }
            })
    }
}

mod serde_timestamp {
    use chrono::{offset::TimeZone, DateTime, Utc};
    use serde::{
        de::{Error as DeError, Visitor},
        Deserializer, Serializer,
    };

    use core::{convert::TryFrom, fmt};

    struct TimestampVisitor;

    impl<'de> Visitor<'de> for TimestampVisitor {
        type Value = DateTime<Utc>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
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

#[cfg(all(test, feature = "clock"))]
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
        let time_options = TimeOptions::default();
        assert_matches!(
            claims.validate_expiration(&time_options).unwrap_err(),
            ValidationError::NoClaim
        );

        claims.expiration_date = Some(Utc::now() - Duration::hours(1));
        assert_matches!(
            claims.validate_expiration(&time_options).unwrap_err(),
            ValidationError::Expired
        );

        claims.expiration_date = Some(Utc::now() - Duration::seconds(10));
        // With the default leeway, this claim is still valid.
        assert!(claims.validate_expiration(&time_options).is_ok());
        // If we set leeway lower, then the claim will be considered expired.
        assert_matches!(
            claims
                .validate_expiration(&TimeOptions::from_leeway(Duration::seconds(5)))
                .unwrap_err(),
            ValidationError::Expired
        );
        // Same if we set the current time in the past.
        let expiration_date = claims.expiration_date.unwrap();
        assert!(claims
            .validate_expiration(&TimeOptions::new(Duration::seconds(3), move || {
                expiration_date
            }))
            .is_ok());
    }

    #[test]
    fn immature_claim() {
        let mut claims = Claims::empty();
        let time_options = TimeOptions::default();
        assert_matches!(
            claims.validate_maturity(&time_options).unwrap_err(),
            ValidationError::NoClaim
        );

        claims.not_before = Some(Utc::now() + Duration::hours(1));
        assert_matches!(
            claims.validate_maturity(&time_options).unwrap_err(),
            ValidationError::NotMature
        );

        claims.not_before = Some(Utc::now() + Duration::seconds(10));
        // With the default leeway, this claim is still valid.
        assert!(claims.validate_maturity(&time_options).is_ok());
        // If we set leeway lower, then the claim will be considered expired.
        assert_matches!(
            claims
                .validate_maturity(&TimeOptions::from_leeway(Duration::seconds(5)))
                .unwrap_err(),
            ValidationError::NotMature
        );
    }
}
