//! Parse human durations such as `15m`, `72h`, `30d`, `90s`.

use std::time::Duration;

/// Parse a duration string: an integer followed by a unit (`s`, `m`, `h`, `d`).
/// A bare integer is interpreted as seconds.
pub fn parse(input: &str) -> Result<Duration, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("empty duration".into());
    }
    let (num, unit) = match s.find(|c: char| !c.is_ascii_digit()) {
        Some(idx) => s.split_at(idx),
        None => (s, "s"),
    };
    let n: u64 = num
        .parse()
        .map_err(|_| format!("invalid duration {input:?}"))?;
    let secs = match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86_400,
        _ => {
            return Err(format!(
                "invalid duration unit in {input:?} (use s, m, h, d)"
            ))
        }
    };
    if secs == 0 {
        return Err(format!("duration {input:?} must be positive"));
    }
    Ok(Duration::from_secs(secs))
}

/// Convert to a chrono duration for date arithmetic.
pub fn to_chrono(d: Duration) -> chrono::Duration {
    chrono::Duration::seconds(d.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_units() {
        assert_eq!(parse("15m").unwrap(), Duration::from_secs(900));
        assert_eq!(parse("72h").unwrap(), Duration::from_secs(259_200));
        assert_eq!(parse("30d").unwrap(), Duration::from_secs(2_592_000));
        assert_eq!(parse("45").unwrap(), Duration::from_secs(45));
        assert_eq!(parse("10s").unwrap(), Duration::from_secs(10));
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse("").is_err());
        assert!(parse("abc").is_err());
        assert!(parse("5w").is_err());
        assert!(parse("0m").is_err());
        assert!(parse("-5m").is_err());
    }
}
