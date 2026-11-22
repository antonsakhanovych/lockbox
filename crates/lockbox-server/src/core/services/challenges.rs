use std::sync::Arc;

use lockbox_protocol::crypto::VerifyingKey;
use lockbox_protocol::{Challenge, FileId, Purpose, SignedRequest};

use crate::core::error::{CoreError, Result};
use crate::core::ports::driven::Clock;

#[derive(Debug)]
pub struct Verified {
    file_id: FileId,
    key: VerifyingKey,
}

impl Verified {
    pub fn file_id(&self) -> FileId {
        self.file_id
    }

    pub fn key(&self) -> &VerifyingKey {
        &self.key
    }
}

pub struct Challenges<C> {
    clock: Arc<C>,
}

impl<C> Challenges<C>
where
    C: Clock,
{
    pub fn new(clock: Arc<C>) -> Self {
        Self { clock }
    }

    pub fn issue(&self, file_id: FileId, purpose: Purpose) -> Challenge {
        Challenge::new(file_id, purpose, self.clock.now())
    }

    pub fn verify(
        &self,
        challenge: Challenge,
        proof: &SignedRequest,
        purpose: Purpose,
    ) -> Result<Verified> {
        proof
            .check(&challenge, purpose, self.clock.now())
            .map_err(|_| CoreError::Denied)?;
        Ok(Verified {
            file_id: challenge.file_id(),
            key: proof.public_key,
        })
    }
}
