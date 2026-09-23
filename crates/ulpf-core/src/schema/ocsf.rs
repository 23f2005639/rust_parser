use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// OCSF 1.3 Category UID for Network Activity
pub const CATEGORY_UID_NETWORK_ACTIVITY: u8 = 4;
/// OCSF 1.3 Class UID for Network Activity
pub const CLASS_UID_NETWORK_ACTIVITY: u16 = 4001;

/// Standard Activity IDs for OCSF 1.3 Network Activity
pub mod activity_id {
    pub const OPEN: u8 = 1;
    pub const CLOSE: u8 = 2;
    pub const TRAFFIC_FLOW: u8 = 3;
    pub const OTHER: u8 = 99;
}

/// Standard Dispositions for OCSF 1.3
pub mod disposition {
    pub const ALLOWED: &str = "Allowed";
    pub const BLOCKED: &str = "Blocked";
    pub const DROPPED: &str = "Dropped";
    pub const UNKNOWN: &str = "Unknown";
}

/// Helper to convert Activity ID to standard OCSF Activity Name
pub fn activity_name_from_id(id: u8) -> &'static str {
    match id {
        activity_id::OPEN => "Open",
        activity_id::CLOSE => "Close",
        activity_id::TRAFFIC_FLOW => "Traffic/Flow",
        activity_id::OTHER => "Other",
        _ => "Unknown",
    }
}

/// Helper to calculate Type UID according to OCSF convention: class_uid * 100 + activity_id
pub fn calculate_type_uid(class_uid: u16, activity_id: u8) -> u32 {
    (class_uid as u32) * 100 + (activity_id as u32)
}

/// OCSF Endpoint object representing an IP endpoint
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Endpoint {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
}

impl Endpoint {
    pub fn new(
        ip: Option<String>,
        port: Option<u16>,
        interface: Option<String>,
        zone: Option<String>,
    ) -> Self {
        Self {
            ip,
            port,
            interface,
            zone,
        }
    }
}

/// OCSF ConnectionInfo object
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ConnectionInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_num: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
}

impl ConnectionInfo {
    pub fn new(
        protocol_num: Option<u8>,
        protocol_name: Option<String>,
        direction: Option<String>,
    ) -> Self {
        Self {
            protocol_num,
            protocol_name,
            direction,
        }
    }
}

/// OCSF Traffic object representing network metrics
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Traffic {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_in: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_out: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packets_in: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packets_out: Option<u64>,
}

impl Traffic {
    pub fn new(
        bytes_in: Option<u64>,
        bytes_out: Option<u64>,
        packets_in: Option<u64>,
        packets_out: Option<u64>,
    ) -> Self {
        Self {
            bytes_in,
            bytes_out,
            packets_in,
            packets_out,
        }
    }
}

/// OCSF Product object representing the logging product/vendor
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Product {
    pub vendor_name: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

impl Product {
    pub fn new(
        vendor_name: impl Into<String>,
        name: impl Into<String>,
        version: Option<String>,
    ) -> Self {
        Self {
            vendor_name: vendor_name.into(),
            name: name.into(),
            version,
        }
    }
}

/// OCSF Metadata object preserving raw data, hash, time, and UUIDv7 event identifier
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Metadata {
    pub product: Product,
    pub raw_data: String,
    pub raw_hash: String,
    pub event_id: String,
    pub ingest_time: i64,
}

impl Metadata {
    pub fn new(
        product: Product,
        raw_data: impl Into<String>,
        raw_hash: impl Into<String>,
        event_id: impl Into<String>,
        ingest_time: i64,
    ) -> Self {
        Self {
            product,
            raw_data: raw_data.into(),
            raw_hash: raw_hash.into(),
            event_id: event_id.into(),
            ingest_time,
        }
    }
}

/// OCSF 1.3 Network Activity Event (Class UID 4001)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkActivity {
    pub activity_id: u8,
    pub activity_name: String,
    pub category_uid: u8,
    pub class_uid: u16,
    pub type_uid: u32,
    pub time: i64,
    pub disposition: String,
    pub src_endpoint: Endpoint,
    pub dst_endpoint: Endpoint,
    pub connection_info: ConnectionInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traffic: Option<Traffic>,
    pub metadata: Metadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unmapped: Option<HashMap<String, String>>,
}

impl NetworkActivity {
    pub fn new(
        activity_id: u8,
        time: i64,
        disposition: impl Into<String>,
        src_endpoint: Endpoint,
        dst_endpoint: Endpoint,
        connection_info: ConnectionInfo,
        traffic: Option<Traffic>,
        metadata: Metadata,
    ) -> Self {
        let activity_name = activity_name_from_id(activity_id).to_string();
        let type_uid = calculate_type_uid(CLASS_UID_NETWORK_ACTIVITY, activity_id);
        Self {
            activity_id,
            activity_name,
            category_uid: CATEGORY_UID_NETWORK_ACTIVITY,
            class_uid: CLASS_UID_NETWORK_ACTIVITY,
            type_uid,
            time,
            disposition: disposition.into(),
            src_endpoint,
            dst_endpoint,
            connection_info,
            traffic,
            metadata,
            unmapped: None,
        }
    }

    pub fn with_unmapped(mut self, unmapped: HashMap<String, String>) -> Self {
        if !unmapped.is_empty() {
            self.unmapped = Some(unmapped);
        }
        self
    }

    pub fn add_unmapped(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let map = self.unmapped.get_or_insert_with(HashMap::new);
        map.insert(key.into(), value.into());
    }
}
