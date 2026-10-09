use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};

use crate::PolicyError;

struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueVisitor)
    }
}

struct UniqueVisitor;

impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = UniqueValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("valid JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
        Number::from_f64(value)
            .map(|number| UniqueValue(Value::Number(number)))
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueValue>()? {
            values.push(value.0);
        }
        Ok(UniqueValue(Value::Array(values)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
        let mut values = Map::new();
        while let Some((key, value)) = access.next_entry::<String, UniqueValue>()? {
            if values.insert(key, value.0).is_some() {
                return Err(serde::de::Error::custom("duplicate JSON object key"));
            }
        }
        Ok(UniqueValue(Value::Object(values)))
    }
}

pub(crate) fn parse_unique_json(bytes: &[u8]) -> Result<Value, PolicyError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = UniqueValue::deserialize(&mut deserializer).map_err(|_| PolicyError::Malformed)?;
    deserializer.end().map_err(|_| PolicyError::Malformed)?;
    Ok(value.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_free_json_preserves_values_serialization_and_jcs() {
        let samples = [
            r#"{"z":{"b":2,"a":1},"a":[{"z":false,"a":null}]}"#,
            r#"{"😀":[{"é":"\uD834\uDD1E","a":1.5}],"λ":"line\n\t\u0000","a\u0062":"quote: \" slash: \\","é":"\u0061"}"#,
            r#"[-9223372036854775808,18446744073709551615,0,-0.0,1.5,1e-10,1e30]"#,
            r#""\u0061\n\uD834\uDD1E""#,
            "null",
            "true",
            "\n {}\t",
        ];

        for sample in samples {
            let parsed = parse_unique_json(sample.as_bytes()).unwrap();
            let ordinary: Value = serde_json::from_str(sample).unwrap();
            assert_eq!(parsed, ordinary, "sample: {sample}");
            assert_eq!(
                serde_json::to_vec(&parsed).unwrap(),
                serde_json::to_vec(&ordinary).unwrap(),
                "sample: {sample}"
            );
            assert_eq!(
                serde_jcs::to_vec(&parsed).unwrap(),
                serde_jcs::to_vec(&ordinary).unwrap(),
                "sample: {sample}"
            );
        }

        assert_eq!(
            serde_json::to_string(&parse_unique_json(samples[0].as_bytes()).unwrap()).unwrap(),
            r#"{"a":[{"a":null,"z":false}],"z":{"a":1,"b":2}}"#
        );
    }

    #[test]
    fn duplicate_keys_at_any_depth_are_malformed() {
        for sample in [
            r#"{"a":1,"a":2}"#,
            r#"{"outer":[{"b":1,"b":2}]}"#,
            r#"{"outer":{"key":1,"\u006bey":2}}"#,
        ] {
            assert!(
                matches!(
                    parse_unique_json(sample.as_bytes()),
                    Err(PolicyError::Malformed)
                ),
                "sample: {sample}"
            );
        }
    }

    #[test]
    fn trailing_data_is_malformed() {
        for sample in [r#"{} {}"#, r#"{"a":1}false"#, "[] true", "nullx"] {
            assert!(
                matches!(
                    parse_unique_json(sample.as_bytes()),
                    Err(PolicyError::Malformed)
                ),
                "sample: {sample}"
            );
        }
    }
}
