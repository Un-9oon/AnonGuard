//! External verification vectors, not independent protocol/side-channel review.
use ml_dsa::{EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};

#[test]
fn ml_dsa_65_matches_all_wycheproof_verification_vectors() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/mldsa_65_verify_test.json")).unwrap();
    let mut checked = 0;
    for group in vectors["testGroups"].as_array().unwrap() {
        let public = hex::decode(group["publicKey"].as_str().unwrap()).unwrap();
        for case in group["tests"].as_array().unwrap() {
            let message = hex::decode(case["msg"].as_str().unwrap()).unwrap();
            let context = hex::decode(case["ctx"].as_str().unwrap_or("")).unwrap();
            let signature = hex::decode(case["sig"].as_str().unwrap()).unwrap();
            let actual = match (
                EncodedVerifyingKey::<MlDsa65>::try_from(public.as_slice()),
                Signature::<MlDsa65>::try_from(signature.as_slice()),
            ) {
                (Ok(encoded), Ok(signature)) => VerifyingKey::<MlDsa65>::decode(&encoded)
                    .verify_with_context(&message, &context, &signature),
                _ => false,
            };
            assert_eq!(
                actual,
                case["result"] == "valid",
                "Wycheproof case {}: {}",
                case["tcId"],
                case["comment"]
            );
            checked += 1;
        }
    }
    assert_eq!(checked, vectors["numberOfTests"].as_u64().unwrap());
    assert_eq!(checked, 210);
}
