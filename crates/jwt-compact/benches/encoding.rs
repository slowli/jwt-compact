//! Benchmarks for encoding / decoding logic.

use chrono::{Duration, Utc};
use criterion::{Criterion, criterion_group, criterion_main};
use jwt_compact::{
    AlgorithmExt, Claims, Header, TimeOptions, UntrustedToken,
    alg::{Hs256, Hs256Key},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// Fairly small list of claims.
#[derive(Serialize, Deserialize)]
struct CustomClaims {
    #[serde(rename = "aud")]
    audience: String,
    #[serde(rename = "sub")]
    user_id: Uuid,
    #[serde(rename = "jti")]
    token_id: Uuid,
    name: String,
    email: String,
    roles: Vec<Role>,
}

impl Default for CustomClaims {
    fn default() -> Self {
        Self {
            audience: "content_management".to_owned(),
            user_id: Uuid::new_v4(),
            token_id: Uuid::new_v4(),
            name: "John Doe".to_owned(),
            email: "john.doe@example.com".to_string(),
            roles: vec![Role::ContentManager],
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Role {
    ContentManager,
    Janitor,
    Admin,
}

fn encoding_benches(criterion: &mut Criterion) {
    let claims = CustomClaims::default();
    let key = Hs256Key::new(b"super_secret_key_donut_steel");
    let key_id = Uuid::new_v4().to_string();
    let time_options = TimeOptions::default();

    criterion.bench_function("encoding/full", |bencher| {
        bencher.iter(|| {
            let header = Header::empty().with_key_id(&key_id);
            let claims = Claims::new(&claims)
                .set_duration_and_issuance(&time_options, Duration::try_minutes(10).unwrap())
                .set_not_before(Utc::now() - Duration::try_minutes(10).unwrap());
            Hs256.token(&header, &claims, &key).unwrap()
        });
    });

    #[cfg(feature = "ciborium")]
    criterion.bench_function("encoding_cbor/full", |bencher| {
        bencher.iter(|| {
            let header = Header::empty().with_key_id(&key_id);
            let claims = Claims::new(&claims)
                .set_duration_and_issuance(&time_options, Duration::minutes(10))
                .set_not_before(Utc::now() - Duration::minutes(10));
            Hs256.compact_token(&header, &claims, &key).unwrap()
        });
    });
}

fn decoding_benches(criterion: &mut Criterion) {
    let key = Hs256Key::new(b"super_secret_key_donut_steel");
    let header = Header::empty().with_key_id(Uuid::new_v4().to_string());
    let time_options = TimeOptions::default();
    let claims = Claims::new(CustomClaims::default())
        .set_duration_and_issuance(&time_options, Duration::try_minutes(10).unwrap())
        .set_not_before(Utc::now() - Duration::try_minutes(10).unwrap());

    #[cfg(feature = "ciborium")]
    {
        let compact_token = Hs256.compact_token(&header, &claims, &key).unwrap();
        criterion.bench_function("decoding_cbor", |bencher| {
            bencher.iter(|| UntrustedToken::new(&compact_token).unwrap())
        });
        criterion.bench_function("decoding_cbor/full", |bencher| {
            bencher.iter(|| {
                let token = UntrustedToken::new(&compact_token).unwrap();
                Hs256
                    .validator::<CustomClaims>(&key)
                    .validate(&token)
                    .unwrap()
            });
        });
    }

    let token = Hs256.token(&header, &claims, &key).unwrap();
    criterion.bench_function("decoding", |bencher| {
        bencher.iter(|| UntrustedToken::new(&token).unwrap())
    });
    criterion.bench_function("decoding/full", |bencher| {
        bencher.iter(|| {
            let token = UntrustedToken::new(&token).unwrap();
            Hs256
                .validator::<CustomClaims>(&key)
                .validate(&token)
                .unwrap()
        });
    });
}

criterion_group!(benches, encoding_benches, decoding_benches);
criterion_main!(benches);
