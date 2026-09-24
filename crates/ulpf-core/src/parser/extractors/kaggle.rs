use chrono::Utc;
use std::collections::HashMap;

use crate::schema::ocsf::{
    activity_id, disposition, ConnectionInfo, Endpoint, Metadata, NetworkActivity, Product, Traffic,
};

pub struct KaggleExtractor;

impl KaggleExtractor {
    pub fn new() -> Self {
        Self
    }

    pub fn parse(&self, raw: &str) -> anyhow::Result<NetworkActivity> {
        let trimmed = raw.trim();

        // Check if raw is the CSV header row
        if trimmed.starts_with("Source Port") || trimmed.starts_with("source port") {
            let now_ms = Utc::now().timestamp_millis();
            let product = Product::new("Kaggle", "Firewall-Simulator", None);
            let metadata = Metadata::new(product, raw, "", "", now_ms);
            return Ok(NetworkActivity::new(
                activity_id::OTHER,
                now_ms,
                disposition::UNKNOWN,
                Endpoint::default(),
                Endpoint::default(),
                ConnectionInfo::default(),
                None,
                metadata,
            ));
        }

        // Branch 1: Syslog format containing %KAGGLE-FW-
        if trimmed.contains("%KAGGLE-FW-") {
            self.parse_syslog(trimmed, raw)
        } else {
            // Branch 2: Raw CSV row
            self.parse_csv(trimmed, raw)
        }
    }

    fn parse_syslog(&self, trimmed: &str, raw: &str) -> anyhow::Result<NetworkActivity> {
        let mut src_port = None;
        let mut dst_port = None;
        let mut nat_src_port = None;
        let mut nat_dst_port = None;
        let mut action = None;
        let mut bytes = None;
        let mut sent_bytes = None;
        let mut rcvd_bytes = None;
        let mut packets = None;
        let mut elapsed = None;
        let mut pkts_sent = None;
        let mut pkts_rcvd = None;

        let mut unmapped = HashMap::new();

        // Extract key=val pairs from the body
        for part in trimmed.split_whitespace() {
            if let Some(eq) = part.find('=') {
                let k = &part[..eq];
                let v = part[eq + 1..].trim_matches('"');
                match k {
                    "src_port" => src_port = v.parse::<u16>().ok(),
                    "dst_port" => dst_port = v.parse::<u16>().ok(),
                    "nat_src_port" => nat_src_port = v.parse::<u16>().ok(),
                    "nat_dst_port" => nat_dst_port = v.parse::<u16>().ok(),
                    "action" => action = Some(v.to_string()),
                    "bytes" => bytes = v.parse::<u64>().ok(),
                    "sent_bytes" => sent_bytes = v.parse::<u64>().ok(),
                    "rcvd_bytes" => rcvd_bytes = v.parse::<u64>().ok(),
                    "packets" => packets = v.parse::<u64>().ok(),
                    "elapsed_sec" => elapsed = v.parse::<u64>().ok(),
                    "pkts_sent" => pkts_sent = v.parse::<u64>().ok(),
                    "pkts_rcvd" => pkts_rcvd = v.parse::<u64>().ok(),
                    _ => {
                        unmapped.insert(k.to_string(), v.to_string());
                    }
                }
            }
        }

        self.build_ocsf(
            src_port,
            dst_port,
            nat_src_port,
            nat_dst_port,
            action.as_deref(),
            bytes,
            sent_bytes,
            rcvd_bytes,
            packets,
            elapsed,
            pkts_sent,
            pkts_rcvd,
            unmapped,
            raw,
        )
    }

    fn parse_csv(&self, trimmed: &str, raw: &str) -> anyhow::Result<NetworkActivity> {
        let parts: Vec<&str> = trimmed.split(',').map(|s| s.trim()).collect();
        if parts.len() < 5 {
            return Err(anyhow::anyhow!("Invalid Kaggle CSV line: {}", trimmed));
        }

        let src_port = parts[0].parse::<u16>().ok();
        let dst_port = parts.get(1).and_then(|s| s.parse::<u16>().ok());
        let nat_src_port = parts.get(2).and_then(|s| s.parse::<u16>().ok());
        let nat_dst_port = parts.get(3).and_then(|s| s.parse::<u16>().ok());
        let action = parts.get(4).map(|s| s.to_string());
        let bytes = parts.get(5).and_then(|s| s.parse::<u64>().ok());
        let sent_bytes = parts.get(6).and_then(|s| s.parse::<u64>().ok());
        let rcvd_bytes = parts.get(7).and_then(|s| s.parse::<u64>().ok());
        let packets = parts.get(8).and_then(|s| s.parse::<u64>().ok());
        let elapsed = parts.get(9).and_then(|s| s.parse::<u64>().ok());
        let pkts_sent = parts.get(10).and_then(|s| s.parse::<u64>().ok());
        let pkts_rcvd = parts.get(11).and_then(|s| s.parse::<u64>().ok());

        let unmapped = HashMap::new();

        self.build_ocsf(
            src_port,
            dst_port,
            nat_src_port,
            nat_dst_port,
            action.as_deref(),
            bytes,
            sent_bytes,
            rcvd_bytes,
            packets,
            elapsed,
            pkts_sent,
            pkts_rcvd,
            unmapped,
            raw,
        )
    }

    fn build_ocsf(
        &self,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        nat_src_port: Option<u16>,
        nat_dst_port: Option<u16>,
        action: Option<&str>,
        _bytes: Option<u64>,
        sent_bytes: Option<u64>,
        rcvd_bytes: Option<u64>,
        _packets: Option<u64>,
        elapsed: Option<u64>,
        pkts_sent: Option<u64>,
        pkts_rcvd: Option<u64>,
        mut unmapped: HashMap<String, String>,
        raw: &str,
    ) -> anyhow::Result<NetworkActivity> {
        let now_ms = Utc::now().timestamp_millis();

        // Synthetic deterministic private IP addresses derived from port numbers
        let s_port = src_port.unwrap_or(0);
        let d_port = dst_port.unwrap_or(0);
        let src_ip = format!("10.10.{}.{}", (s_port >> 8) & 0xff, s_port & 0xff);
        let dst_ip = format!("10.20.{}.{}", (d_port >> 8) & 0xff, d_port & 0xff);

        if let Some(nsp) = nat_src_port {
            unmapped.insert("nat_src_port".to_string(), nsp.to_string());
        }
        if let Some(ndp) = nat_dst_port {
            unmapped.insert("nat_dst_port".to_string(), ndp.to_string());
        }
        if let Some(el) = elapsed {
            unmapped.insert("elapsed_sec".to_string(), el.to_string());
        }

        // Action disposition & activity ID
        let (disp, act_id) = match action.map(|s| s.to_ascii_lowercase()).as_deref() {
            Some("allow") | Some("accept") | Some("permit") => {
                (disposition::ALLOWED, activity_id::TRAFFIC_FLOW)
            }
            Some("deny") | Some("block") => (disposition::BLOCKED, activity_id::OTHER),
            Some("drop") => (disposition::DROPPED, activity_id::OTHER),
            Some("reset-both") | Some("close") => (disposition::ALLOWED, activity_id::CLOSE),
            _ => (disposition::UNKNOWN, activity_id::TRAFFIC_FLOW),
        };

        // Determine protocol: port 53 is UDP, otherwise default to TCP
        let (proto_num, proto_name) = if d_port == 53 || s_port == 53 {
            (Some(17u8), Some("UDP".to_string()))
        } else {
            (Some(6u8), Some("TCP".to_string()))
        };

        let src_endpoint = Endpoint::new(Some(src_ip), src_port, None, None);
        let dst_endpoint = Endpoint::new(Some(dst_ip), dst_port, None, None);
        let connection_info = ConnectionInfo::new(proto_num, proto_name, None);

        let traffic = if sent_bytes.is_some()
            || rcvd_bytes.is_some()
            || pkts_sent.is_some()
            || pkts_rcvd.is_some()
        {
            Some(Traffic::new(rcvd_bytes, sent_bytes, pkts_rcvd, pkts_sent))
        } else {
            None
        };

        let product = Product::new("Kaggle", "Firewall-Simulator", None);
        let metadata = Metadata::new(product, raw, "", "", now_ms);

        Ok(NetworkActivity::new(
            act_id,
            now_ms,
            disp,
            src_endpoint,
            dst_endpoint,
            connection_info,
            traffic,
            metadata,
        )
        .with_unmapped(unmapped))
    }
}

impl Default for KaggleExtractor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kaggle_syslog_parse() {
        let extractor = KaggleExtractor::new();
        let raw = r#"<134>Sep 21 14:00:00 firewall-kaggle-01 %KAGGLE-FW-1-TRAFFIC: action="allow" src_port=57222 dst_port=53 nat_src_port=54587 nat_dst_port=53 bytes=177 sent_bytes=94 rcvd_bytes=83 packets=2 elapsed_sec=30 pkts_sent=1 pkts_rcvd=1"#;
        let event = extractor.parse(raw).unwrap();

        assert_eq!(event.activity_id, activity_id::TRAFFIC_FLOW);
        assert_eq!(event.disposition, disposition::ALLOWED);
        assert_eq!(event.src_endpoint.port, Some(57222));
        assert_eq!(event.dst_endpoint.port, Some(53));
        assert!(event.src_endpoint.ip.is_some());
        assert!(event.dst_endpoint.ip.is_some());
        assert_eq!(event.connection_info.protocol_name.as_deref(), Some("UDP"));

        let traffic = event.traffic.unwrap();
        assert_eq!(traffic.bytes_out, Some(94));
        assert_eq!(traffic.bytes_in, Some(83));
    }

    #[test]
    fn test_kaggle_csv_row_parse() {
        let extractor = KaggleExtractor::new();
        let raw = "57222,53,54587,53,allow,177,94,83,2,30,1,1";
        let event = extractor.parse(raw).unwrap();

        assert_eq!(event.disposition, disposition::ALLOWED);
        assert_eq!(event.src_endpoint.port, Some(57222));
        assert_eq!(event.dst_endpoint.port, Some(53));
        assert!(event.src_endpoint.ip.is_some());
        assert!(event.dst_endpoint.ip.is_some());
    }
}
