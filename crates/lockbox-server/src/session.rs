//! One connection's ordered conversation. Challenges and unfinished uploads belong
//! to this connection; completed files live in the shared services.

use std::sync::Arc;
use std::time::Duration;

use lockbox_protocol::{Challenge, ErrorCode, FileId, Purpose, Request, Response};
use tokio::time::timeout;

use crate::app::{Ports, Services};
use crate::core::error::CoreError;
use crate::core::ports::driving::{Channel, ChannelError};
use crate::core::services::{ForDelete, ForFetch, ForUpload, Upload};

/// Maximum wait for a complete request or for a response to be written.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error(transparent)]
    Channel(#[from] ChannelError),

    #[error(transparent)]
    Core(#[from] CoreError),

    #[error("that message was not expected now")]
    UnexpectedMessage,

    #[error("the peer stopped making progress")]
    TimedOut,
}

impl SessionError {
    fn code(&self) -> Option<ErrorCode> {
        match self {
            Self::Core(error) => Some(error.into()),
            Self::UnexpectedMessage => Some(ErrorCode::UnexpectedMessage),
            Self::Channel(error @ ChannelError::Codec(_)) => Some(error.into()),
            Self::Channel(ChannelError::Io(_)) | Self::TimedOut => None,
        }
    }
}

enum State<P: Ports> {
    Idle,
    Challenged(Challenge),
    Uploading(Box<Upload<P::Clock, P::Store, P::Scheduler>>),
}

pub struct Session<P: Ports, C> {
    services: Arc<Services<P>>,
    channel: C,
}

impl<P: Ports, C: Channel> Session<P, C> {
    pub fn new(services: Arc<Services<P>>, channel: C) -> Self {
        Self { services, channel }
    }

    /// Runs until EOF, timeout or a failed request. Errors are answered with only
    /// a wire code before closing; an unfinished upload is dropped and removed.
    pub async fn run(mut self) -> Result<(), SessionError> {
        let result = self.converse().await;

        if let Err(error) = &result
            && let Some(code) = error.code()
        {
            let _ = self.send(&Response::Error(code)).await;
        }

        result
    }

    async fn converse(&mut self) -> Result<(), SessionError> {
        let mut state = State::Idle;

        loop {
            let request = timeout(IDLE_TIMEOUT, self.channel.receive())
                .await
                .map_err(|_| SessionError::TimedOut)??;

            let Some(request) = request else {
                return Ok(());
            };

            state = self.handle(state, request).await?;
        }
    }

    async fn handle(
        &mut self,
        state: State<P>,
        request: Request,
    ) -> Result<State<P>, SessionError> {
        match (state, request) {
            (State::Idle, Request::BeginUpload) => {
                self.challenge(FileId::random(), Purpose::Upload).await
            }

            (State::Idle, Request::BeginFetch { file_id }) => {
                self.challenge(file_id, Purpose::Fetch).await
            }

            (State::Idle, Request::BeginDelete { file_id }) => {
                self.challenge(file_id, Purpose::Delete).await
            }

            (State::Challenged(challenge), Request::Upload { proof, header })
                if challenge.purpose() == Purpose::Upload =>
            {
                let owner = self
                    .services
                    .challenges
                    .verify::<ForUpload>(challenge, &proof)?;

                let upload = self.services.uploads.begin(owner, header).await?;
                self.send(&Response::ReadyForUpload).await?;

                Ok(State::Uploading(Box::new(upload)))
            }

            (State::Challenged(challenge), Request::Fetch(proof))
                if challenge.purpose() == Purpose::Fetch =>
            {
                let requester = self
                    .services
                    .challenges
                    .verify::<ForFetch>(challenge, &proof)?;

                let mut fetch = self.services.fetches.begin(requester).await?;
                self.send(&Response::FetchReady(Box::new(fetch.header().clone())))
                    .await?;

                while let Some(chunk) = fetch.next_chunk().await? {
                    self.send(&Response::Chunk(chunk)).await?;
                }

                Ok(State::Idle)
            }

            (State::Challenged(challenge), Request::Delete(proof))
                if challenge.purpose() == Purpose::Delete =>
            {
                let requester = self
                    .services
                    .challenges
                    .verify::<ForDelete>(challenge, &proof)?;

                self.services.deletes.delete(requester).await?;
                self.send(&Response::Deleted).await?;

                Ok(State::Idle)
            }

            (State::Uploading(mut upload), Request::UploadChunk(chunk)) => {
                upload.write(&chunk).await?;

                if upload.remaining() == 0 {
                    let file_id = upload.file_id();
                    let expires_at = (*upload).finish().await?;

                    self.send(&Response::Uploaded {
                        file_id,
                        expires_at,
                    })
                    .await?;

                    Ok(State::Idle)
                } else {
                    Ok(State::Uploading(upload))
                }
            }

            _ => Err(SessionError::UnexpectedMessage),
        }
    }

    async fn challenge(
        &mut self,
        file_id: FileId,
        purpose: Purpose,
    ) -> Result<State<P>, SessionError> {
        let challenge = self.services.challenges.issue(file_id, purpose);
        self.send(&Response::Challenge(challenge.clone())).await?;

        Ok(State::Challenged(challenge))
    }

    async fn send(&mut self, response: &Response) -> Result<(), SessionError> {
        timeout(IDLE_TIMEOUT, self.channel.send(response))
            .await
            .map_err(|_| SessionError::TimedOut)??;

        Ok(())
    }
}
