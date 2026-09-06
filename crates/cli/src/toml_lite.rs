#[derive(Clone, Debug)]
pub enum Value {
    Str(String),
    Int(i64),
    Bool(bool),
}

impl Value {
    pub fn parse(s: &str) -> Option<Value> {
        let s = if s.starts_with('"') {
            s
        } else {
            s.split('#').next().unwrap_or(s).trim()
        };
        if let Some(rest) = s.strip_prefix('"') {
            let mut out = String::new();
            let mut chars = rest.chars();
            while let Some(c) = chars.next() {
                match c {
                    '"' => return Some(Value::Str(out)),
                    '\\' => out.push(chars.next()?),
                    _ => out.push(c),
                }
            }
            return None;
        }
        match s {
            "true" => return Some(Value::Bool(true)),
            "false" => return Some(Value::Bool(false)),
            _ => {}
        }
        let cleaned = s.replace('_', "");
        if let Some(hex) = cleaned.strip_prefix("0x") {
            return i64::from_str_radix(hex, 16).ok().map(Value::Int);
        }
        cleaned.parse::<i64>().ok().map(Value::Int)
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Int(i) => Some(*i as u64),
            Value::Str(s) => Value::parse(s).and_then(|v| v.as_u64()),
            Value::Bool(_) => None,
        }
    }
}

pub fn quote(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        if c == '"' || c == '\\' {
            o.push('\\');
        }
        o.push(c);
    }
    o.push('"');
    o
}

pub fn get<'a>(kv: &'a [(String, Value)], key: &str) -> Option<&'a Value> {
    kv.iter().rev().find(|(n, _)| n == key).map(|(_, v)| v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_strings_ints_hex_and_bools() {
        assert!(matches!(Value::parse("\"hi\""), Some(Value::Str(s)) if s == "hi"));
        assert!(matches!(Value::parse("42"), Some(Value::Int(42))));
        assert!(matches!(Value::parse("1_000_000"), Some(Value::Int(1_000_000))));
        assert!(matches!(Value::parse("0x2a"), Some(Value::Int(0x2a))));
        assert!(matches!(Value::parse("true"), Some(Value::Bool(true))));
        assert!(matches!(Value::parse("false"), Some(Value::Bool(false))));
        assert!(Value::parse("not a value").is_none());
    }

    #[test]
    fn strips_trailing_comments_outside_quotes() {
        assert!(matches!(Value::parse("42 # the answer"), Some(Value::Int(42))));
        assert!(matches!(Value::parse("\"a # b\""), Some(Value::Str(s)) if s == "a # b"));
    }

    #[test]
    fn quote_escapes_quotes_and_backslashes() {
        assert_eq!(quote("a\"b\\c"), "\"a\\\"b\\\\c\"");
    }

    #[test]
    fn as_u64_unwraps_a_quoted_hex_address() {
        let v = Value::Str("0x20001c2c".into());
        assert_eq!(v.as_u64(), Some(0x2000_1c2c));
    }

    #[test]
    fn get_returns_the_last_matching_key() {
        let kv = vec![
            ("a".to_string(), Value::Int(1)),
            ("a".to_string(), Value::Int(2)),
            ("b".to_string(), Value::Bool(true)),
        ];
        assert!(matches!(get(&kv, "a"), Some(Value::Int(2))));
        assert!(matches!(get(&kv, "b"), Some(Value::Bool(true))));
        assert!(get(&kv, "c").is_none());
    }
}
