use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct Jwks {
    keys: Vec<Jwk>,
}

impl Jwks {
    pub fn new(jwks: Vec<Jwk>) -> Self {
        Self { keys: jwks }
    }

    pub fn jwk(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|jwk| jwk.kid == kid)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Jwk {
    alg: String,
    e: String,
    kid: String,
    kty: String,
    n: String,
    #[serde(alias = "use")]
    #[serde(rename = "use")]
    use_: String,
}

impl Jwk {
    pub fn new(
        alg: impl Into<String>,
        e: impl Into<String>,
        kid: impl Into<String>,
        kty: impl Into<String>,
        n: impl Into<String>,
        use_: impl Into<String>,
    ) -> Self {
        Self {
            alg: alg.into(),
            e: e.into(),
            kid: kid.into(),
            kty: kty.into(),
            n: n.into(),
            use_: use_.into(),
        }
    }

    pub fn alg(&self) -> &str {
        &self.alg
    }

    pub fn e(&self) -> &str {
        &self.e
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn kty(&self) -> &str {
        &self.kty
    }

    pub fn n(&self) -> &str {
        &self.n
    }

    pub fn use_(&self) -> &str {
        &self.use_
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_and_getters() {
        let json = r#"
            {
                "keys": [
                    {
                        "alg": "RS256",
                        "e": "AQAB",
                        "kid": "test-key-id",
                        "kty": "RSA",
                        "n": "1WZ_DT6JiAiz6ST1Ev3PQOjKXHeECdN0z7yyD1a0B-GmKgqbLln0a0ttFQzFK6AZbT6m7ZwyUFKen5npoeRBC4sTJ5rk_hO5yiDQi4YyyXBggNJ1greFgGyK_tN8CaOxiPzzHCYY-da9JhSV56xM7H-5ppCkIEQF8lCFEvCTFeZqwaUrWKEVljOv3tPYJz9CmJdISq_XTFqO1hF71o7EKTltxZjdAWCFNvapC9eSqnej2rfstqMa73o4-DBO_WZD4OPg6Zk6_nJ0Y6V3i3OQ5aD4RD_V96ULO61kF81uQD3h9k2Oids-g3tP9QQoQBycE-KLjdkYZHvdhMULkdAlQQ",
                        "use": "sig"
                    }
                ]
            }
        "#;
        let jwks: Jwks = serde_json::from_str(json).unwrap();
        assert!(jwks.jwk("foo").is_none());
        let jwk = jwks.jwk("test-key-id").unwrap();
        assert_eq!(jwk.alg(), "RS256");
        assert_eq!(jwk.e(), "AQAB");
        assert_eq!(jwk.kid(), "test-key-id");
        assert_eq!(jwk.kty(), "RSA");
        assert_eq!(jwk.n(), "1WZ_DT6JiAiz6ST1Ev3PQOjKXHeECdN0z7yyD1a0B-GmKgqbLln0a0ttFQzFK6AZbT6m7ZwyUFKen5npoeRBC4sTJ5rk_hO5yiDQi4YyyXBggNJ1greFgGyK_tN8CaOxiPzzHCYY-da9JhSV56xM7H-5ppCkIEQF8lCFEvCTFeZqwaUrWKEVljOv3tPYJz9CmJdISq_XTFqO1hF71o7EKTltxZjdAWCFNvapC9eSqnej2rfstqMa73o4-DBO_WZD4OPg6Zk6_nJ0Y6V3i3OQ5aD4RD_V96ULO61kF81uQD3h9k2Oids-g3tP9QQoQBycE-KLjdkYZHvdhMULkdAlQQ");
        assert_eq!(jwk.use_(), "sig");
    }
}
