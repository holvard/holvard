// SPDX-FileCopyrightText: 2026 Holvard contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Trezor's SLIP-39 reference vectors: every valid set of mnemonics must
//! combine into exactly the expected master secret, and every invalid set
//! must be rejected.
//!
//! The vectors use the passphrase "TREZOR" (SLIP-39, "Test vectors").
//! Holvard itself always uses the empty passphrase.

use std::error::Error;

const VECTORS: &str = include_str!("../../../test-vectors/slip39/vectors.json");

/// Number of vectors in the vendored file, so a truncated or misread file
/// cannot pass by testing fewer cases.
const VECTOR_COUNT: usize = 45;

#[test]
fn every_trezor_vector_combines_or_is_rejected() -> Result<(), Box<dyn Error>> {
    let vectors = json::parse(VECTORS)?;
    let vectors = vectors.as_list()?;
    assert_eq!(
        vectors.len(),
        VECTOR_COUNT,
        "vectors.json was not read completely"
    );

    let mut failures = Vec::new();
    for vector in vectors {
        let [description, mnemonics, expected_secret, _bip32_key] = vector.as_four()?;
        let description = description.as_str()?;
        let mnemonics: Vec<&str> = mnemonics
            .as_list()?
            .iter()
            .map(json::Value::as_str)
            .collect::<Result<_, _>>()?;
        let expected_secret = expected_secret.as_str()?;

        let result = holvard_core::slip39::combine(&mnemonics, "TREZOR");
        let outcome = match &result {
            Ok(secret) => Some(hex(secret.as_bytes())),
            Err(_) => None,
        };
        let expected = if expected_secret.is_empty() {
            None
        } else {
            Some(expected_secret.to_owned())
        };
        if outcome != expected {
            failures.push(format!(
                "{description}: expected {expected:?}, got {result:?}"
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {VECTOR_COUNT} vectors failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// A minimal JSON reader for vectors.json, which contains only nested lists
/// of strings. Kept here so the tests need no JSON dependency.
mod json {
    use std::error::Error;

    #[derive(Debug)]
    pub enum Value {
        Str(String),
        List(Vec<Value>),
    }

    impl Value {
        pub fn as_str(&self) -> Result<&str, Box<dyn Error>> {
            match self {
                Value::Str(s) => Ok(s),
                Value::List(_) => Err("expected a string".into()),
            }
        }

        pub fn as_list(&self) -> Result<&[Value], Box<dyn Error>> {
            match self {
                Value::List(items) => Ok(items),
                Value::Str(_) => Err("expected a list".into()),
            }
        }

        pub fn as_four(&self) -> Result<[&Value; 4], Box<dyn Error>> {
            match self.as_list()? {
                [a, b, c, d] => Ok([a, b, c, d]),
                _ => Err("expected a list of four items".into()),
            }
        }
    }

    pub fn parse(text: &str) -> Result<Value, Box<dyn Error>> {
        let mut chars = text.chars().peekable();
        let value = parse_value(&mut chars)?;
        skip_whitespace(&mut chars);
        match chars.next() {
            None => Ok(value),
            Some(c) => Err(format!("unexpected {c:?} after the JSON value").into()),
        }
    }

    type Chars<'a> = std::iter::Peekable<std::str::Chars<'a>>;

    fn skip_whitespace(chars: &mut Chars<'_>) {
        while chars.next_if(|c| c.is_whitespace()).is_some() {}
    }

    fn parse_value(chars: &mut Chars<'_>) -> Result<Value, Box<dyn Error>> {
        skip_whitespace(chars);
        match chars.next() {
            Some('"') => parse_string(chars).map(Value::Str),
            Some('[') => parse_list(chars).map(Value::List),
            other => Err(format!("unexpected {other:?}").into()),
        }
    }

    fn parse_string(chars: &mut Chars<'_>) -> Result<String, Box<dyn Error>> {
        let mut out = String::new();
        loop {
            match chars.next() {
                Some('"') => return Ok(out),
                Some('\\') => match chars.next() {
                    Some(c @ ('"' | '\\' | '/')) => out.push(c),
                    other => return Err(format!("unsupported escape {other:?}").into()),
                },
                Some(c) => out.push(c),
                None => return Err("unterminated string".into()),
            }
        }
    }

    fn parse_list(chars: &mut Chars<'_>) -> Result<Vec<Value>, Box<dyn Error>> {
        let mut items = Vec::new();
        skip_whitespace(chars);
        if chars.next_if_eq(&']').is_some() {
            return Ok(items);
        }
        loop {
            items.push(parse_value(chars)?);
            skip_whitespace(chars);
            match chars.next() {
                Some(',') => {}
                Some(']') => return Ok(items),
                other => return Err(format!("expected ',' or ']', got {other:?}").into()),
            }
        }
    }
}
