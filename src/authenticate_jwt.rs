use crate::jwks::Jwks;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jwt_simple::prelude::*;
use serde::{de::DeserializeOwned, Serialize};

pub type Jwt = String;
pub type Sub = String;

type ValidationFn<CustomClaims> = fn(&CustomClaims) -> Result<(), String>;

#[derive(Clone)]
pub struct JwtAuthenticator<CustomClaims: Serialize + DeserializeOwned> {
    jwks: Jwks,
    custom_validations: Vec<ValidationFn<CustomClaims>>,
    verification_options: VerificationOptions,
}

impl<CustomClaims: Serialize + DeserializeOwned> JwtAuthenticator<CustomClaims> {
    pub fn new(
        jwks: Jwks,
        custom_validations: Vec<ValidationFn<CustomClaims>>,
        issuer: Option<String>,
    ) -> Self {
        Self {
            jwks,
            custom_validations,
            verification_options: VerificationOptions {
                allowed_issuers: issuer.map(|iss| {
                    let mut set = HashSet::new();
                    set.insert(iss);
                    set
                }),
                ..Default::default()
            },
        }
    }

    pub fn authenticate(&self, bearer_token: impl Into<Jwt>) -> Result<Sub, String> {
        let token = bearer_token.into();
        if !token.starts_with("Bearer ") {
            return Err(String::from("Bearer token did not start with 'Bearer'"));
        }
        let parts: Vec<&str> = token.split(' ').collect();
        if parts.len() != 2 {
            return Err(format!(
                "Bearer token had more (or less) than just 'Bearer token'. {parts:?}"
            ));
        }
        let base64_token = parts[1];
        let metadata = Token::decode_metadata(base64_token)
            .map_err(|_| String::from("Could not decode token metadata"))?;
        let key_id = metadata
            .key_id()
            .ok_or_else(|| String::from("Did not have a key id in token header"))?;
        let jwk = self
            .jwks
            .jwk(key_id)
            .ok_or_else(|| String::from("Did not have a JWK with the specified key id"))?;
        let n = URL_SAFE_NO_PAD
            .decode(jwk.n())
            .map_err(|e| format!("Could not base64url decode jwk n. {e:?}"))?;
        let e = URL_SAFE_NO_PAD
            .decode(jwk.e())
            .map_err(|e| format!("Could not base64url decode jwk e. {e:?}"))?;
        let key = RS256PublicKey::from_components(&n, &e).map_err(|e| {
            format!("Could not create RS256 pub key from n and e components in JWK. {e:?}")
        })?;
        let claims = key
            .verify_token::<CustomClaims>(base64_token, Some(self.verification_options.clone()))
            .map_err(|e| format!("Token could not be verified. {e:?}"))?;

        // Run custom validations
        for custom_validation in self.custom_validations.iter() {
            custom_validation(&claims.custom)?;
        }

        // Return the sub (usually the user id)
        let sub = claims
            .subject
            .ok_or_else(|| String::from("Sub was empty"))?;
        Ok(sub)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Jwk;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    #[test]
    fn test_no_custom_claims_happy() {
        // Given
        let key_pair = RS256KeyPair::generate(2048)
            .unwrap()
            .with_key_id("test-key-id");
        let jwk = mock_jwk(key_pair.clone());
        let jwt = mock_jwt(key_pair);
        let authenticator: JwtAuthenticator<()> = JwtAuthenticator::new(
            Jwks::new(vec![jwk]),
            vec![],
            Some(String::from("test-issuer")),
        );

        // When
        let maybe_sub = authenticator.authenticate(format!("Bearer {jwt}"));

        // Then
        if let Err(e) = maybe_sub.as_ref() {
            println!("{e}");
        }
        assert_eq!(maybe_sub.unwrap(), String::from("1234567890"));
    }

    #[test]
    fn test_with_custom_claims_happy() {
        // Given
        let key_pair = RS256KeyPair::generate(2048)
            .unwrap()
            .with_key_id("test-key-id");
        let jwk = mock_jwk(key_pair.clone());
        let jwt = mock_jwt(key_pair);
        let authenticator: JwtAuthenticator<MockCustomClaims> = JwtAuthenticator::new(
            Jwks::new(vec![jwk]),
            vec![verify_foo_is_bar],
            Some(String::from("test-issuer")),
        );

        // When
        let maybe_sub = authenticator.authenticate(format!("Bearer {jwt}"));

        // Then
        if let Err(e) = maybe_sub.as_ref() {
            println!("{e}");
        }
        assert_eq!(maybe_sub.unwrap(), String::from("1234567890"));
    }

    // TODO: test all the failure modes

    fn mock_jwk(key_pair: RS256KeyPair) -> Jwk {
        // Extract RSA components
        let public_key = key_pair.public_key();
        let rsa_components = public_key.to_components();

        // Create the JWK
        Jwk::new(
            "RS256",
            URL_SAFE_NO_PAD.encode(rsa_components.e),
            "test-key-id",
            "RSA",
            URL_SAFE_NO_PAD.encode(rsa_components.n),
            "sig",
        )
    }

    fn mock_jwt(key_pair: RS256KeyPair) -> Jwt {
        // Create the payload for the JWT
        let claims = Claims::with_custom_claims(
            MockCustomClaims {
                foo: String::from("bar"),
            },
            Duration::from_secs(3600),
        )
        .with_subject("1234567890")
        .with_issuer("test-issuer")
        .with_audience("test-audience");

        // // Set up header
        // let mut header = Header::default();
        // header.kid = Some(key_id.to_string());

        // Generate the JWT
        key_pair.sign(claims).unwrap()
    }

    fn verify_foo_is_bar(custom_claims: &MockCustomClaims) -> Result<(), String> {
        if custom_claims.foo != "bar" {
            Err(String::from("foo did not equal bar"))
        } else {
            Ok(())
        }
    }

    #[derive(Serialize, Deserialize)]
    struct MockCustomClaims {
        foo: String,
    }
}
