//! The little of the Cloudflare API that bsjn needs: check the token, find the zone, manage
//! the wildcard A record. The token only ever goes into the `Authorization` header.

use crate::paths::Paths;
use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Duration;

const API: &str = "https://api.cloudflare.com/client/v4";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Zone {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Record {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub content: String,
}

/// The token `bsjn setup` stored, if any.
pub fn stored_token(paths: &Paths) -> Option<String> {
    std::fs::read_to_string(paths.token_file())
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
}

pub struct Client {
    agent: ureq::Agent,
    token: String,
}

impl Client {
    pub fn new(token: &str) -> Self {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .http_status_as_error(false)
            .build()
            .into();
        Self {
            agent,
            token: token.to_string(),
        }
    }

    /// Send a request and return the envelope's `result`.
    fn call(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value> {
        let url = format!("{API}{path}");
        let auth = format!("Bearer {}", self.token);
        let response = match (method, body) {
            ("GET", _) => self.agent.get(&url).header("Authorization", &auth).call(),
            ("POST", Some(b)) => self
                .agent
                .post(&url)
                .header("Authorization", &auth)
                .send_json(b),
            ("PATCH", Some(b)) => self
                .agent
                .patch(&url)
                .header("Authorization", &auth)
                .send_json(b),
            _ => bail!("unsupported request {method}"),
        };
        let mut response = response.map_err(|e| anyhow!("cannot reach Cloudflare: {e}"))?;
        let status = response.status().as_u16();
        let text = response
            .body_mut()
            .read_to_string()
            .context("cannot read Cloudflare's answer")?;
        parse_envelope(status, &text)
    }

    /// Fails unless the token is active.
    pub fn verify(&self) -> Result<()> {
        let result = self
            .call("GET", "/user/tokens/verify", None)
            .context("Cloudflare does not accept this token")?;
        match result.get("status").and_then(Value::as_str) {
            Some("active") => Ok(()),
            other => bail!(
                "the Cloudflare token is not active (status: {})",
                other.unwrap_or("unknown")
            ),
        }
    }

    /// Every zone the token can see.
    pub fn zones(&self) -> Result<Vec<Zone>> {
        let mut zones = Vec::new();
        for page in 1..=20 {
            let result = self
                .call("GET", &format!("/zones?per_page=50&page={page}"), None)
                .context("cannot list the zones (does the token have Zone:Zone:Read?)")?;
            let batch: Vec<Zone> = serde_json::from_value(result)?;
            let done = batch.len() < 50;
            zones.extend(batch);
            if done {
                break;
            }
        }
        Ok(zones)
    }

    pub fn find_record(&self, zone_id: &str, name: &str) -> Result<Option<Record>> {
        let result = self
            .call(
                "GET",
                &format!("/zones/{zone_id}/dns_records?name={}", encode(name)),
                None,
            )
            .context("cannot read the DNS records (does the token have Zone:DNS:Edit?)")?;
        let records: Vec<Record> = serde_json::from_value(result)?;
        Ok(records.into_iter().next())
    }

    /// A DNS-only A record with a 300 s TTL.
    pub fn create_a(&self, zone_id: &str, name: &str, ip: &str) -> Result<()> {
        self.call(
            "POST",
            &format!("/zones/{zone_id}/dns_records"),
            Some(record_body(name, ip)),
        )
        .context("cannot create the DNS record")?;
        Ok(())
    }

    pub fn update_a(&self, zone_id: &str, record_id: &str, name: &str, ip: &str) -> Result<()> {
        self.call(
            "PATCH",
            &format!("/zones/{zone_id}/dns_records/{record_id}"),
            Some(record_body(name, ip)),
        )
        .context("cannot update the DNS record")?;
        Ok(())
    }
}

fn record_body(name: &str, ip: &str) -> Value {
    json!({"type": "A", "name": name, "content": ip, "ttl": 300, "proxied": false})
}

/// Percent-encode a DNS name for a query string (`*` is the only unusual character).
fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Cloudflare wraps every answer in `{success, errors, result}`.
fn parse_envelope(status: u16, text: &str) -> Result<Value> {
    let v: Value = serde_json::from_str(text).map_err(|_| {
        anyhow!("Cloudflare answered HTTP {status} with something that is not JSON")
    })?;
    if v.get("success").and_then(Value::as_bool) == Some(true) {
        return Ok(v.get("result").cloned().unwrap_or(Value::Null));
    }
    let messages: Vec<String> = v
        .get("errors")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|e| e.get("message").and_then(Value::as_str))
        .map(String::from)
        .collect();
    if messages.is_empty() {
        bail!("Cloudflare answered HTTP {status}");
    }
    bail!("Cloudflare answered HTTP {status}: {}", messages.join("; "))
}

/// The zone for `domain`: the longest zone name that equals it or is one of its parents.
pub fn pick_zone<'a>(zones: &'a [Zone], domain: &str) -> Option<&'a Zone> {
    zones
        .iter()
        .filter(|z| domain == z.name || domain.ends_with(&format!(".{}", z.name)))
        .max_by_key(|z| z.name.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zone(name: &str) -> Zone {
        Zone {
            id: format!("id-{name}"),
            name: name.into(),
        }
    }

    #[test]
    fn the_longest_matching_zone_wins() {
        let zones = [
            zone("example.com"),
            zone("dev.example.com"),
            zone("other.com"),
            zone("teibar.com"),
        ];
        assert_eq!(
            pick_zone(&zones, "dev.example.com").unwrap().name,
            "dev.example.com"
        );
        assert_eq!(
            pick_zone(&zones[..1], "dev.example.com").unwrap().name,
            "example.com"
        );
        assert_eq!(pick_zone(&zones[3..], "dev.example.com"), None);
        assert_eq!(pick_zone(&zones[2..3], "dev.example.com"), None);
    }

    #[test]
    fn envelopes_give_the_result_or_cloudflares_reason() {
        let ok = parse_envelope(
            200,
            r#"{"success":true,"errors":[],"result":{"status":"active"}}"#,
        );
        assert_eq!(ok.unwrap()["status"], "active");
        let err = parse_envelope(
            403,
            r#"{"success":false,"errors":[{"code":9109,"message":"Invalid access token"}],"result":null}"#,
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("403") && err.contains("Invalid access token"),
            "{err}"
        );
        assert!(parse_envelope(502, "<html>").is_err());
    }

    #[test]
    fn the_wildcard_name_is_query_encoded() {
        assert_eq!(encode("*.dev.example.com"), "%2A.dev.example.com");
    }

    #[test]
    fn the_record_is_dns_only_with_a_short_ttl() {
        let b = record_body("*.d.example.com", "100.64.0.1");
        assert_eq!(b["proxied"], false);
        assert_eq!(b["ttl"], 300);
        assert_eq!(b["type"], "A");
    }
}
