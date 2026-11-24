use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use lockbox_protocol::crypto::VerifyingKey;
use lockbox_protocol::message::MAX_LIFETIME_SECS;
use lockbox_protocol::{FetchHeader, FileHeader, FileId};

use crate::core::error::{CoreError, Result};
use crate::core::ports::driven::Clock;
use crate::core::services::{ForDelete, ForFetch, ForUpload, Verified};

struct Record {
    owner: VerifyingKey,
    header: FileHeader,
}

pub struct Registry<C> {
    clock: Arc<C>,
    records: Mutex<HashMap<FileId, Record>>,
}

impl<C> Registry<C>
where
    C: Clock,
{
    pub fn new(clock: Arc<C>) -> Self {
        Self {
            clock,
            records: Mutex::new(HashMap::new()),
        }
    }

    pub fn register(&self, owner: &Verified<ForUpload>, header: FileHeader) -> Result<u64> {
        header.validate().map_err(|_| CoreError::Denied)?;
        let now = self.clock.now();
        if header.expires_at <= now {
            return Err(CoreError::Denied);
        }
        let expires_at = header.expires_at.min(now.saturating_add(MAX_LIFETIME_SECS));
        let header = FileHeader {
            expires_at,
            ..header
        };
        match self.records().entry(owner.file_id()) {
            Entry::Occupied(_) => Err(CoreError::Denied),
            Entry::Vacant(slot) => {
                slot.insert(Record {
                    owner: *owner.key(),
                    header,
                });
                Ok(expires_at)
            }
        }
    }

    pub fn fetch_header(&self, requester: &Verified<ForFetch>) -> Result<FetchHeader> {
        let records = self.records();
        let record = records
            .get(&requester.file_id())
            .filter(|record| record.header.expires_at > self.clock.now())
            .ok_or(CoreError::Denied)?;
        record
            .header
            .fetch_header_for(requester.key())
            .ok_or(CoreError::Denied)
    }

    pub fn delete(&self, requester: &Verified<ForDelete>) -> Result<()> {
        let now = self.clock.now();
        let mut records = self.records();
        let owned = records.get(&requester.file_id()).is_some_and(|record| {
            record.header.expires_at > now && record.owner == *requester.key()
        });
        if !owned {
            return Err(CoreError::Denied);
        }
        records.remove(&requester.file_id());
        Ok(())
    }

    pub fn expire(&self, file_id: FileId) -> bool {
        let now = self.clock.now();
        let mut records = self.records();
        let expired = records
            .get(&file_id)
            .is_some_and(|record| record.header.expires_at <= now);
        if expired {
            records.remove(&file_id);
        }
        expired
    }

    fn records(&self) -> MutexGuard<'_, HashMap<FileId, Record>> {
        self.records.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
