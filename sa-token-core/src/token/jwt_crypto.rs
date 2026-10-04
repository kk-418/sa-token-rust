//! Built-in HMAC-only crypto provider for `jsonwebtoken`.
//! 内置的仅 HMAC 的 `jsonwebtoken` 加密后端。
//!
//! `JwtManager` always builds keys with `EncodingKey::from_secret` /
//! `DecodingKey::from_secret`, so only HS256 / HS384 / HS512 can ever succeed.
//! Without the `jwt-rust-crypto` feature this module installs a provider that
//! implements exactly those three algorithms, which keeps the `rsa` crate
//! (RUSTSEC-2023-0071) and the EC / EdDSA stacks out of the dependency graph.
//! Other algorithms fail with `InvalidAlgorithm` instead of panicking.
//!
//! `JwtManager` 的密钥始终来自 `from_secret`，只有 HS256 / HS384 / HS512 可用。
//! 未开启 `jwt-rust-crypto` 时安装仅 HMAC 的后端，依赖图中不再出现 `rsa`
//! （RUSTSEC-2023-0071）及 EC / EdDSA 依赖；其它算法返回 `InvalidAlgorithm`。
//!
//! If the process also needs RSA / EC / EdDSA through `jsonwebtoken`, enable
//! the `jwt-rust-crypto` feature: the crate-feature provider is then used and
//! nothing is installed here.
//! 若进程内其它代码需要通过 `jsonwebtoken` 使用 RSA / EC / EdDSA，开启
//! `jwt-rust-crypto` feature，此时不安装本后端。

#[cfg(not(feature = "jwt-rust-crypto"))]
mod hmac_only {
    use hmac::{Hmac, KeyInit, Mac};
    use jsonwebtoken::crypto::{CryptoProvider, JwkUtils, JwtSigner, JwtVerifier};
    use jsonwebtoken::errors::{Error, ErrorKind, Result};
    use jsonwebtoken::signature::{self, Signer, Verifier};
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};
    use sha2::{Sha256, Sha384, Sha512};

    enum HmacKey {
        Sha256(Hmac<Sha256>),
        Sha384(Hmac<Sha384>),
        Sha512(Hmac<Sha512>),
    }

    impl HmacKey {
        fn new(alg: Algorithm, secret: &[u8]) -> Result<Self> {
            let bad_key = |_| Error::from(ErrorKind::InvalidKeyFormat);
            match alg {
                Algorithm::HS256 => Hmac::new_from_slice(secret)
                    .map(Self::Sha256)
                    .map_err(bad_key),
                Algorithm::HS384 => Hmac::new_from_slice(secret)
                    .map(Self::Sha384)
                    .map_err(bad_key),
                Algorithm::HS512 => Hmac::new_from_slice(secret)
                    .map(Self::Sha512)
                    .map_err(bad_key),
                _ => Err(ErrorKind::InvalidAlgorithm.into()),
            }
        }

        fn sign(&self, msg: &[u8]) -> Vec<u8> {
            match self {
                Self::Sha256(mac) => mac
                    .clone()
                    .chain_update(msg)
                    .finalize()
                    .into_bytes()
                    .to_vec(),
                Self::Sha384(mac) => mac
                    .clone()
                    .chain_update(msg)
                    .finalize()
                    .into_bytes()
                    .to_vec(),
                Self::Sha512(mac) => mac
                    .clone()
                    .chain_update(msg)
                    .finalize()
                    .into_bytes()
                    .to_vec(),
            }
        }

        /// Constant-time comparison via `verify_slice`. | 通过 `verify_slice` 做常量时间比较。
        fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
            match self {
                Self::Sha256(mac) => mac.clone().chain_update(msg).verify_slice(sig).is_ok(),
                Self::Sha384(mac) => mac.clone().chain_update(msg).verify_slice(sig).is_ok(),
                Self::Sha512(mac) => mac.clone().chain_update(msg).verify_slice(sig).is_ok(),
            }
        }
    }

    struct HmacJwt {
        alg: Algorithm,
        key: HmacKey,
    }

    impl Signer<Vec<u8>> for HmacJwt {
        fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, signature::Error> {
            Ok(self.key.sign(msg))
        }
    }

    impl JwtSigner for HmacJwt {
        fn algorithm(&self) -> Algorithm {
            self.alg
        }
    }

    impl Verifier<Vec<u8>> for HmacJwt {
        fn verify(&self, msg: &[u8], sig: &Vec<u8>) -> std::result::Result<(), signature::Error> {
            if self.key.verify(msg, sig) {
                Ok(())
            } else {
                Err(signature::Error::new())
            }
        }
    }

    impl JwtVerifier for HmacJwt {
        fn algorithm(&self) -> Algorithm {
            self.alg
        }
    }

    fn signer_factory(alg: &Algorithm, key: &EncodingKey) -> Result<Box<dyn JwtSigner>> {
        let key = HmacKey::new(*alg, key.try_get_hmac_secret()?)?;
        Ok(Box::new(HmacJwt { alg: *alg, key }))
    }

    fn verifier_factory(alg: &Algorithm, key: &DecodingKey) -> Result<Box<dyn JwtVerifier>> {
        let key = HmacKey::new(*alg, key.try_get_hmac_secret()?)?;
        Ok(Box::new(HmacJwt { alg: *alg, key }))
    }

    static PROVIDER: CryptoProvider = CryptoProvider {
        signer_factory,
        verifier_factory,
        jwk_utils: JwkUtils::new_unimplemented(),
    };

    pub(super) fn install() {
        // Err means another provider was installed first; that one is used.
        // 返回 Err 表示进程内已先安装了其它后端，沿用即可。
        let _ = PROVIDER.install_default();
    }
}

/// Make sure a `jsonwebtoken` crypto provider is available before signing or verifying.
/// 在签名 / 验签前确保 `jsonwebtoken` 已有可用的加密后端。
pub(crate) fn ensure_provider() {
    #[cfg(not(feature = "jwt-rust-crypto"))]
    {
        static INSTALL: std::sync::Once = std::sync::Once::new();
        INSTALL.call_once(hmac_only::install);
    }
}

#[cfg(test)]
mod tests {
    use super::ensure_provider;
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
    use serde_json::{Value, json};

    fn roundtrip(alg: Algorithm) -> Value {
        ensure_provider();
        let claims = json!({ "sub": "1", "exp": 4_102_444_800_u64 });
        let token =
            encode(&Header::new(alg), &claims, &EncodingKey::from_secret(b"k")).expect("encode");
        decode::<Value>(
            &token,
            &DecodingKey::from_secret(b"k"),
            &Validation::new(alg),
        )
        .expect("decode")
        .claims
    }

    #[test]
    fn hmac_algorithms_roundtrip() {
        for alg in [Algorithm::HS256, Algorithm::HS384, Algorithm::HS512] {
            assert_eq!(roundtrip(alg)["sub"], "1");
        }
    }

    #[test]
    fn wrong_secret_is_rejected() {
        ensure_provider();
        let claims = json!({ "sub": "1", "exp": 4_102_444_800_u64 });
        let token =
            encode(&Header::default(), &claims, &EncodingKey::from_secret(b"k")).expect("encode");
        let err = decode::<Value>(
            &token,
            &DecodingKey::from_secret(b"other"),
            &Validation::default(),
        )
        .expect_err("must fail");
        assert_eq!(
            *err.kind(),
            jsonwebtoken::errors::ErrorKind::InvalidSignature
        );
    }

    #[cfg(not(feature = "jwt-rust-crypto"))]
    #[test]
    fn non_hmac_algorithm_is_an_error_not_a_panic() {
        ensure_provider();
        let err = encode(
            &Header::new(Algorithm::RS256),
            &json!({ "sub": "1" }),
            &EncodingKey::from_secret(b"k"),
        )
        .expect_err("must fail");
        assert!(matches!(
            err.kind(),
            jsonwebtoken::errors::ErrorKind::InvalidAlgorithm
                | jsonwebtoken::errors::ErrorKind::InvalidKeyFormat
        ));
    }
}
