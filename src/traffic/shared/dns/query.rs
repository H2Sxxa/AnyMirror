use std::time::Duration;

use anyhow::{Context, Result};
use hickory_proto::{
    op::{LowerQuery, Message},
    rr::{Name, RData, Record, RecordType},
};

use super::DnsLookupQuery;

impl DnsLookupQuery {
    pub(super) fn from_message(request: &Message) -> Vec<Self> {
        request
            .queries()
            .iter()
            .map(|query| Self::new(&query.name().to_utf8(), query.query_type()))
            .collect()
    }

    pub(super) fn from_lower_queries(queries: &[LowerQuery]) -> Vec<Self> {
        queries
            .iter()
            .map(|query| Self::new(&query.name().to_utf8(), query.query_type()))
            .collect()
    }

    fn new(name: &str, record_type: RecordType) -> Self {
        Self {
            name: Self::normalize_name(name),
            record_type,
        }
    }

    pub(super) fn build_record(&self, ttl: Duration, data: RData) -> Result<Record> {
        let record_name = Name::from_ascii(&self.name)
            .with_context(|| format!("invalid DNS record name `{}`", self.name))?;
        Ok(Record::from_rdata(record_name, ttl.as_secs() as u32, data))
    }

    fn normalize_name(name: &str) -> String {
        name.trim_end_matches('.').to_ascii_lowercase()
    }
}
