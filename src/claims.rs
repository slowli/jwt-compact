use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::{Claim, ValidationError};

/// Time-related options for token creation and validation.
///
/// If the `clock` crate feature is on (and it's on by default), `TimeOptions` can be created
/// using the `Default` impl or [`Self::from_leeway()`]. If the feature is off,
/// you can still create options using [a generic constructor](Self::new).
///
/// # Examples
///
/// ```
/// # use chrono::{Duration, Utc};
/// # use jwt_compact::TimeOptions;
/// // Default options.
/// let default_options = TimeOptions::default();
/// let options_with_custom_leeway =
///     TimeOptions::from_leeway(Duration::try_seconds(5).unwrap());
/// // Options that have a fixed time. Can be useful for testing.
/// let clock_time = Utc::now();
/// let options_with_stopped_clock =
///     TimeOptions::new(Duration::try_seconds(10).unwrap(), move || clock_time);
/// ```
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

/// Creates options with a default leeway (60 seconds) and the [`Utc::now()`] clock.
///
/// This impl is supported on **crate feature `clock`** only.
#[cfg(feature = "clock")]
impl Default for TimeOptions {
    fn default() -> Self {
        Self::from_leeway(Duration::try_seconds(60).unwrap())
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Claims<T> {
    /// Expiration time of the token.
    #[serde(
        rename = "exp",
        default,
        skip_serializing_if = "Option::is_none",
        with = "self::serde_timestamp"
    )]
    pub expiration: Option<DateTime<Utc>>,

    /// Minimum time at which token is valid.
    #[serde(
        rename = "nbf",
        default,
        skip_serializing_if = "Option::is_none",
        with = "self::serde_timestamp"
    )]
    pub not_before: Option<DateTime<Utc>>,

    /// Time of token issuance.
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
            expiration: None,
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
            expiration: None,
            not_before: None,
            issued_at: None,
            custom: custom_claims,
        }
    }

    /// Sets the `expiration` claim so that the token has the specified `duration`.
    /// The current timestamp is taken from `options`.
    #[must_use]
    pub fn set_duration<F>(self, options: &TimeOptions<F>, duration: Duration) -> Self
    where
        F: Fn() -> DateTime<Utc>,
    {
        Self {
            expiration: Some((options.clock_fn)() + duration),
            ..self
        }
    }

    /// Atomically sets `issued_at` and `expiration` claims: first to the current time
    /// (taken from `options`), and the second to match the specified `duration` of the token.
    #[must_use]
    pub fn set_duration_and_issuance<F>(self, options: &TimeOptions<F>, duration: Duration) -> Self
    where
        F: Fn() -> DateTime<Utc>,
    {
        let issued_at = (options.clock_fn)();
        Self {
            expiration: Some(issued_at + duration),
            issued_at: Some(issued_at),
            ..self
        }
    }

    /// Sets the `nbf` claim.
    #[must_use]
    pub fn set_not_before(self, moment: DateTime<Utc>) -> Self {
        Self {
            not_before: Some(moment),
            ..self
        }
    }

    /// Validates the expiration claim.
    ///
    /// This method will return an error if the claims do not feature an expiration time,
    /// or if it is in the past (subject to the provided `options`).
    pub fn validate_expiration<F>(&self, options: &TimeOptions<F>) -> Result<&Self, ValidationError>
    where
        F: Fn() -> DateTime<Utc>,
    {
        self.expiration.map_or(
            Err(ValidationError::NoClaim(Claim::Expiration)),
            |expiration| {
                let expiration_with_leeway = expiration
                    .checked_add_signed(options.leeway)
                    .unwrap_or(DateTime::<Utc>::MAX_UTC);
                if (options.clock_fn)() > expiration_with_leeway {
                    Err(ValidationError::Expired)
                } else {
                    Ok(self)
                }
            },
        )
    }

    /// Validates the maturity time (`nbf` claim).
    ///
    /// This method will return an error if the claims do not feature a maturity time,
    /// or if it is in the future (subject to the provided `options`).
    pub fn validate_maturity<F>(&self, options: &TimeOptions<F>) -> Result<&Self, ValidationError>
    where
        F: Fn() -> DateTime<Utc>,
    {
        self.not_before.map_or(
            Err(ValidationError::NoClaim(Claim::NotBefore)),
            |not_before| {
                if (options.clock_fn)() < not_before - options.leeway {
                    Err(ValidationError::NotMature)
                } else {
                    Ok(self)
                }
            },
        )
    }
}

mod serde_timestamp {
    use core::fmt;

    use chrono::{offset::TimeZone, DateTime, Utc};
    use serde::{
        de::{Error as DeError, Visitor},
        Deserializer, Serializer,
    };

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
            Utc.timestamp_opt(value, 0)
                .single()
                .ok_or_else(|| E::custom("UTC timestamp overflow"))
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            let value = i64::try_from(value).map_err(DeError::custom)?;
            Utc.timestamp_opt(value, 0)
                .single()
                .ok_or_else(|| E::custom("UTC timestamp overflow"))
        }

        #[allow(clippy::cast_possible_truncation)]
        // ^ If truncation occurs, the `timestamp_opt()` won't return a single value anyway
        fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            Utc.timestamp_opt(value as i64, 0)
                .single()
                .ok_or_else(|| E::custom("UTC timestamp overflow"))
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
    use assert_matches::assert_matches;
    use chrono::TimeZone;

    use super::*;

    #[test]
    fn empty_claims_can_be_serialized() {
        let mut claims = Claims::empty();
        assert!(serde_json::to_string(&claims).is_ok());
        claims.expiration = Some(Utc::now());
        assert!(serde_json::to_string(&claims).is_ok());
        claims.not_before = Some(Utc::now());
        assert!(serde_json::to_string(&claims).is_ok());
    }

    #[test]
    #[cfg(feature = "ciborium")]
    fn empty_claims_can_be_serialized_to_cbor() {
        let mut claims = Claims::empty();
        assert!(ciborium::into_writer(&claims, &mut vec![]).is_ok());
        claims.expiration = Some(Utc::now());
        assert!(ciborium::into_writer(&claims, &mut vec![]).is_ok());
        claims.not_before = Some(Utc::now());
        assert!(ciborium::into_writer(&claims, &mut vec![]).is_ok());
    }

    #[test]
    fn expired_claim() {
        let mut claims = Claims::empty();
        let time_options = TimeOptions::default();
        assert_matches!(
            claims.validate_expiration(&time_options).unwrap_err(),
            ValidationError::NoClaim(Claim::Expiration)
        );

        claims.expiration = Some(DateTime::<Utc>::MAX_UTC);
        assert!(claims.validate_expiration(&time_options).is_ok());

        claims.expiration = Some(Utc::now() - Duration::try_hours(1).unwrap());
        assert_matches!(
            claims.validate_expiration(&time_options).unwrap_err(),
            ValidationError::Expired
        );

        claims.expiration = Some(Utc::now() - Duration::try_seconds(10).unwrap());
        // With the default leeway, this claim is still valid.
        assert!(claims.validate_expiration(&time_options).is_ok());
        // If we set leeway lower, then the claim will be considered expired.
        assert_matches!(
            claims
                .validate_expiration(&TimeOptions::from_leeway(Duration::try_seconds(5).unwrap()))
                .unwrap_err(),
            ValidationError::Expired
        );
        // Same if we set the current time in the past.
        let expiration = claims.expiration.unwrap();
        assert!(claims
            .validate_expiration(&TimeOptions::new(
                Duration::try_seconds(3).unwrap(),
                move || { expiration }
            ))
            .is_ok());
    }

    #[test]
    fn immature_claim() {
        let mut claims = Claims::empty();
        let time_options = TimeOptions::default();
        assert_matches!(
            claims.validate_maturity(&time_options).unwrap_err(),
            ValidationError::NoClaim(Claim::NotBefore)
        );

        claims.not_before = Some(Utc::now() + Duration::try_hours(1).unwrap());
        assert_matches!(
            claims.validate_maturity(&time_options).unwrap_err(),
            ValidationError::NotMature
        );

        claims.not_before = Some(Utc::now() + Duration::try_seconds(10).unwrap());
        // With the default leeway, this claim is still valid.
        assert!(claims.validate_maturity(&time_options).is_ok());
        // If we set leeway lower, then the claim will be considered expired.
        assert_matches!(
            claims
                .validate_maturity(&TimeOptions::from_leeway(Duration::try_seconds(5).unwrap()))
                .unwrap_err(),
            ValidationError::NotMature
        );
    }
    #[test]
    fn float_timestamp() {
        let claims = "{\"exp\": 1.691203462e+9}";
        let claims: Claims<Empty> = serde_json::from_str(claims).unwrap();
        let timestamp = Utc.timestamp_opt(1_691_203_462, 0).single().unwrap();
        assert_eq!(claims.expiration, Some(timestamp));
    }

    #[test]
    fn float_timestamp_errors() {
        let invalid_claims = ["{\"exp\": 1e20}", "{\"exp\": -1e20}"];
        for claims in invalid_claims {
            let err = serde_json::from_str::<Claims<Empty>>(claims).unwrap_err();
            let err = err.to_string();
            assert!(err.contains("UTC timestamp overflow"), "{err}");
        }
    }
}
