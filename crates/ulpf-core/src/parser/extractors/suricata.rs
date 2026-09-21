use std::collections::HashMap;
use chrono::Utc;
use serde_json::Value;

use crate::schema::ocsf::{
    activity_id, disposition, ConnectionInfo, Endpoint, Metadata, NetworkActivity, Product, Traffic,
};
use super::{parse_rfc3339_or_fallback, protocol_num_from_name};

pub struct SuricataExtractor;

impl SuricataExtractor {
    pub fn new() -> Self {
        Self
    }

    pub fn parse(&self, raw: &str) -> anyhow::Result<NetworkActivity> {
        let json_slice = if let Some(pos) = raw.find('{') {
            &raw[pos..]
        } else {
            raw.trim()
        };

        let val: Value = serde_json::from_str(json_slice)
            .map_err(|e| anyhow::anyhow!("Failed to parse Suricata JSON: {} in {}", e, raw))?;

        let now_ms = Utc::now().timestamp_millis();
        let event_time = val
            .get("timestamp")
            .and_then(|v| v.as_str())
            .map(|ts| parse_rfc3339_or_fallback(ts, now_ms))
            .unwrap_or(now_ms);

        let event_type = val
            .get("event_type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let src_ip = val
            .get("src_ip")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let src_port = val
            .get("src_port")
            .and_then(|v| v.as_u64())
            .map(|p| p as u16);
        let in_iface = val
            .get("in_iface")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let dst_ip = val
            .get("dest_ip")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let dst_port = val
            .get("dest_port")
            .and_then(|v| v.as_u64())
            .map(|p| p as u16);

        let proto_str = val.get("proto").and_then(|v| v.as_str());
        let proto_name = proto_str.map(|p| p.to_ascii_uppercase());
        let proto_num = proto_name.as_deref().and_then(protocol_num_from_name);

        let mut unmapped = HashMap::new();
        unmapped.insert("event_type".to_string(), event_type.to_string());

        if let Some(flow_id) = val.get("flow_id") {
            unmapped.insert("flow_id".to_string(), flow_id.to_string());
        }

        let mut traffic = None;
        let mut disp = disposition::ALLOWED;
        let mut act_id = activity_id::TRAFFIC_FLOW;

        if let Some(flow_obj) = val.get("flow").and_then(|v| v.as_object()) {
            let bytes_toserver = flow_obj.get("bytes_toserver").and_then(|v| v.as_u64());
            let bytes_toclient = flow_obj.get("bytes_toclient").and_then(|v| v.as_u64());
            let pkts_toserver = flow_obj.get("pkts_toserver").and_then(|v| v.as_u64());
            let pkts_toclient = flow_obj.get("pkts_toclient").and_then(|v| v.as_u64());

            if bytes_toserver.is_some() || bytes_toclient.is_some() || pkts_toserver.is_some() || pkts_toclient.is_some() {
                traffic = Some(Traffic::new(
                    bytes_toclient,
                    bytes_toserver,
                    pkts_toclient,
                    pkts_toserver,
                ));
            }

            if let Some(flow_action) = flow_obj.get("action").and_then(|v| v.as_str()) {
                if flow_action.eq_ignore_ascii_case("drop") {
                    disp = disposition::DROPPED;
                }
            }

            if let Some(state) = flow_obj.get("state").and_then(|v| v.as_str()) {
                match state.to_ascii_lowercase().as_str() {
                    "closed" => act_id = activity_id::CLOSE,
                    "new" => act_id = activity_id::OPEN,
                    _ => {}
                }
                unmapped.insert("flow_state".to_string(), state.to_string());
            }
        }

        if let Some(alert_obj) = val.get("alert").and_then(|v| v.as_object()) {
            act_id = activity_id::OTHER;
            if let Some(action) = alert_obj.get("action").and_then(|v| v.as_str()) {
                disp = match action.to_ascii_lowercase().as_str() {
                    "blocked" | "reject" => disposition::BLOCKED,
                    "drop" | "dropped" => disposition::DROPPED,
                    "allowed" | "pass" => disposition::ALLOWED,
                    _ => disposition::BLOCKED,
                };
                unmapped.insert("alert_action".to_string(), action.to_string());
            } else {
                disp = disposition::BLOCKED;
            }

            if let Some(sig) = alert_obj.get("signature").and_then(|v| v.as_str()) {
                unmapped.insert("alert_signature".to_string(), sig.to_string());
            }
            if let Some(cat) = alert_obj.get("category").and_then(|v| v.as_str()) {
                unmapped.insert("alert_category".to_string(), cat.to_string());
            }
            if let Some(sev) = alert_obj.get("severity") {
                unmapped.insert("alert_severity".to_string(), sev.to_string());
            }
        }

        let src_endpoint = Endpoint::new(src_ip, src_port, in_iface, None);
        let dst_endpoint = Endpoint::new(dst_ip, dst_port, None, None);
        let connection_info = ConnectionInfo::new(proto_num, proto_name, None);

        let product = Product::new("OISF", "Suricata", None);
        let metadata = Metadata::new(product, raw, "", "", now_ms);

        Ok(NetworkActivity::new(
            act_id,
            event_time,
            disp,
            src_endpoint,
            dst_endpoint,
            connection_info,
            traffic,
            metadata,
        ).with_unmapped(unmapped))
    }
}

impl Default for SuricataExtractor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suricata_alert() {
        let extractor = SuricataExtractor::new();
        let raw = r#"{"timestamp":"2023-10-15T10:20:30.123456+0000","flow_id":1234567890,"in_iface":"eth0","event_type":"alert","src_ip":"192.168.1.10","src_port":54321,"dest_ip":"203.0.113.20","dest_port":80,"proto":"TCP","alert":{"action":"blocked","signature":"ET SCAN Potential SSH Scan","category":"Attempted Information Leak","severity":2}}"#;
        let event = extractor.parse(raw).unwrap();

        assert_eq!(event.activity_id, activity_id::OTHER);
        assert_eq!(event.disposition, disposition::BLOCKED);
        assert_eq!(event.src_endpoint.ip.as_deref(), Some("192.168.1.10"));
        assert_eq!(event.src_endpoint.port, Some(54321));
        assert_eq!(event.src_endpoint.interface.as_deref(), Some("eth0"));
        assert_eq!(event.dst_endpoint.ip.as_deref(), Some("203.0.113.20"));
        assert_eq!(event.dst_endpoint.port, Some(80));
        assert_eq!(event.connection_info.protocol_name.as_deref(), Some("TCP"));
        assert_eq!(event.connection_info.protocol_num, Some(6));

        let unmapped = event.unmapped.unwrap();
        assert_eq!(unmapped.get("alert_signature").map(|s| s.as_str()), Some("ET SCAN Potential SSH Scan"));
    }

    #[test]
    fn test_suricata_flow_closed() {
        let extractor = SuricataExtractor::new();
        let raw = r#"{"timestamp":"2023-10-15T10:20:30.123456+0000","flow_id":9876543210,"in_iface":"eth0","event_type":"flow","src_ip":"10.0.0.5","src_port":49152,"dest_ip":"198.51.100.1","dest_port":443,"proto":"TCP","flow":{"pkts_toserver":12,"pkts_toclient":18,"bytes_toserver":1500,"bytes_toclient":8500,"state":"closed","action":"pass"}}"#;
        let event = extractor.parse(raw).unwrap();

        assert_eq!(event.activity_id, activity_id::CLOSE);
        assert_eq!(event.disposition, disposition::ALLOWED);
        let traffic = event.traffic.unwrap();
        assert_eq!(traffic.bytes_out, Some(1500));
        assert_eq!(traffic.bytes_in, Some(8500));
        assert_eq!(traffic.packets_out, Some(12));
        assert_eq!(traffic.packets_in, Some(18));
    }
}
