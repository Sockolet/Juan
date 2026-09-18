use anyhow::{Result, bail, ensure};

use crate::capture::SessionSummary;

#[derive(Clone, Debug)]
enum Term {
    Text(String),
    Host(String),
    Method(String),
    Status(u16, u16),
    Type(String),
    Https(bool),
    Error(bool),
}

#[derive(Clone, Debug, Default)]
pub struct Filter {
    terms: Vec<(bool, Term)>,
}

impl Filter {
    pub fn parse(input: &str) -> Result<Self> {
        let mut terms = Vec::new();
        for token in input.split_whitespace() {
            let (negated, token) = match token.strip_prefix('-') {
                Some(rest) => (true, rest),
                None => (false, token),
            };
            ensure!(
                !token.is_empty(),
                "A minus sign must be followed by a filter"
            );
            let lower = token.to_lowercase();
            let term = if let Some((field, value)) = lower.split_once(':') {
                ensure!(!value.is_empty(), "Missing value for {field}:");
                match field {
                    "host" => Term::Host(value.to_owned()),
                    "method" => Term::Method(value.to_owned()),
                    "status" => {
                        let (min, max) = status_range(value)?;
                        Term::Status(min, max)
                    }
                    "type" => Term::Type(value.to_owned()),
                    "scheme" => match value {
                        "https" => Term::Https(true),
                        "http" => Term::Https(false),
                        _ => bail!("scheme: must be http or https"),
                    },
                    "error" => match value {
                        "true" => Term::Error(true),
                        "false" => Term::Error(false),
                        _ => bail!("error: must be true or false"),
                    },
                    // URLs are useful search terms, rather than unknown field names.
                    "http" | "https" => Term::Text(lower),
                    _ => bail!(
                        "Unknown filter '{field}:'. Use host, method, status, type, scheme, or error"
                    ),
                }
            } else {
                Term::Text(lower)
            };
            terms.push((negated, term));
        }
        Ok(Self { terms })
    }

    pub fn matches(&self, session: &SessionSummary) -> bool {
        self.terms.iter().all(|(negated, term)| {
            let matches = match term {
                Term::Text(value) => {
                    session.url.to_lowercase().contains(value)
                        || session.method.to_lowercase().contains(value)
                        || session.content_type.to_lowercase().contains(value)
                }
                Term::Host(value) => session.host.to_lowercase().contains(value),
                Term::Method(value) => session.method.eq_ignore_ascii_case(value),
                Term::Status(min, max) => session.status.is_some_and(|s| s >= *min && s <= *max),
                Term::Type(value) => session.content_type.to_lowercase().contains(value),
                Term::Https(value) => session.is_https() == *value,
                Term::Error(value) => session.is_error() == *value,
            };
            matches != *negated
        })
    }
}

fn status_range(value: &str) -> Result<(u16, u16)> {
    if value.len() == 3 && value.ends_with("xx") {
        let base = value[..1].parse::<u16>()? * 100;
        ensure!(
            (100..=500).contains(&base),
            "Status class must be 1xx through 5xx"
        );
        return Ok((base, base + 99));
    }
    if let Some((start, end)) = value.split_once('-') {
        let (start, end) = (start.parse::<u16>()?, end.parse::<u16>()?);
        ensure!(
            start >= 100 && end <= 599 && start <= end,
            "Invalid status range"
        );
        return Ok((start, end));
    }
    let status = value.parse::<u16>()?;
    ensure!(
        (100..=599).contains(&status),
        "Status must be 100 through 599"
    );
    Ok((status, status))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::SessionKind;

    fn session() -> SessionSummary {
        SessionSummary {
            id: 1,
            method: "POST".into(),
            url: "https://api.example.test/v1/token".into(),
            host: "api.example.test".into(),
            path: "/v1/token".into(),
            protocol: "HTTP/2".into(),
            status: Some(401),
            kind: SessionKind::Http,
            content_type: "application/json".into(),
            bytes: 120,
            elapsed_ms: Some(50),
            complete: true,
            failed: false,
        }
    }

    #[test]
    fn combines_fields_case_insensitively() {
        let filter =
            Filter::parse("host:EXAMPLE method:post status:4xx type:json scheme:https").unwrap();
        assert!(filter.matches(&session()));
        assert!(!Filter::parse("status:200").unwrap().matches(&session()));
    }

    #[test]
    fn supports_negation_ranges_and_literal_urls() {
        assert!(
            Filter::parse("-status:200-399 error:true /v1")
                .unwrap()
                .matches(&session())
        );
        assert!(
            Filter::parse("https://api.example.test")
                .unwrap()
                .matches(&session())
        );
        assert!(!Filter::parse("-host:example").unwrap().matches(&session()));
    }

    #[test]
    fn reports_invalid_filters_instead_of_ignoring_them() {
        for input in [
            "status:700",
            "status:5x",
            "host:",
            "unknown:value",
            "-",
            "scheme:ftp",
        ] {
            assert!(Filter::parse(input).is_err(), "{input}");
        }
    }
}
