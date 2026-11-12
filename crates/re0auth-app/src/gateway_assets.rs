use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_util::Stream;
use parking_lot::RwLock;
use re0auth_api::connector::{AssetStream, UpstreamError};
use tokio::sync::watch;

struct FlightInner {
    chunks: Vec<Bytes>,
    content_type: Option<Result<String, UpstreamError>>,
    outcome: Option<Result<Bytes, UpstreamError>>,
}

/// Shared, append-only response state. Readers pull chunks independently.
pub(crate) struct AssetFlight {
    inner: RwLock<FlightInner>,
    version: watch::Sender<u64>,
    subscribers: AtomicUsize,
}

impl AssetFlight {
    pub(crate) fn new() -> Arc<Self> {
        let (version, _) = watch::channel(0);
        Arc::new(Self {
            inner: RwLock::new(FlightInner {
                chunks: Vec::new(),
                content_type: None,
                outcome: None,
            }),
            version,
            subscribers: AtomicUsize::new(0),
        })
    }

    pub(crate) fn join(self: &Arc<Self>) -> SubscriberStream {
        self.subscribers.fetch_add(1, Ordering::AcqRel);
        SubscriberStream {
            flight: Arc::clone(self),
            cursor: 0,
            position: 0,
            version: self.version.subscribe(),
            changed: None,
            terminated: false,
        }
    }

    pub(crate) fn publish_content_type(&self, content_type: Result<String, UpstreamError>) {
        {
            let mut inner = self.inner.write();
            debug_assert!(
                inner.content_type.is_none(),
                "content type is published once"
            );
            inner.content_type = Some(content_type);
        }
        self.notify();
    }

    pub(crate) fn append(&self, chunk: Bytes) {
        {
            let mut inner = self.inner.write();
            debug_assert!(inner.outcome.is_none(), "cannot append after the outcome");
            inner.chunks.push(chunk);
        }
        self.notify();
    }

    pub(crate) fn finish(&self, outcome: Result<Bytes, UpstreamError>) {
        {
            let mut inner = self.inner.write();
            debug_assert!(inner.outcome.is_none(), "outcome is published once");
            if outcome.is_ok() {
                inner.chunks.clear();
            }
            inner.outcome = Some(outcome);
        }
        self.notify();
    }

    pub(crate) fn subscriber_count(&self) -> usize {
        self.subscribers.load(Ordering::Acquire)
    }

    pub(crate) fn outcome(&self) -> Option<Result<Bytes, UpstreamError>> {
        self.inner.read().outcome.clone()
    }

    pub(crate) fn assemble(&self) -> Bytes {
        let inner = self.inner.read();
        let total = inner.chunks.iter().map(Bytes::len).sum();
        let mut body = bytes::BytesMut::with_capacity(total);
        for chunk in &inner.chunks {
            body.extend_from_slice(chunk);
        }
        body.freeze()
    }

    fn notify(&self) {
        self.version.send_modify(|version| {
            *version = version.wrapping_add(1);
        });
    }
}

/// A pending `watch::Receiver::changed` future, boxed so the cursor struct keeps
/// a fixed size across awaits.
type ChangedFuture = Pin<Box<dyn Future<Output = Result<(), watch::error::RecvError>> + Send>>;

/// One independent cursor into an [`AssetFlight`].
///
/// The count is tied to the value's lifetime rather than a normal EOF, so an
/// axum disconnect or request cancellation cannot strand an orphan reader.
pub(crate) struct SubscriberStream {
    flight: Arc<AssetFlight>,
    cursor: usize,
    position: usize,
    version: watch::Receiver<u64>,
    changed: Option<ChangedFuture>,
    terminated: bool,
}

impl SubscriberStream {
    /// Waits only for magic validation, not for the complete upstream body.
    pub(crate) async fn wait_content_type(&mut self) -> Result<String, UpstreamError> {
        loop {
            {
                let inner = self.flight.inner.read();
                if let Some(content_type) = &inner.content_type {
                    return content_type.clone();
                }
                if let Some(outcome) = &inner.outcome {
                    return match outcome {
                        Ok(_) => Err(UpstreamError::Internal),
                        Err(error) => Err(error.clone()),
                    };
                }
            }
            if self.version.changed().await.is_err() {
                return Err(UpstreamError::Internal);
            }
        }
    }
}

impl Stream for SubscriberStream {
    type Item = Result<Bytes, UpstreamError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if self.terminated {
                return Poll::Ready(None);
            }

            enum Next {
                Wait,
                Chunk(Bytes),
                End,
                Error(UpstreamError),
            }
            let next = {
                let inner = self.flight.inner.read();
                match &inner.content_type {
                    Some(Err(error)) => Next::Error(error.clone()),
                    Some(Ok(_)) => {
                        if let Some(Ok(body)) = &inner.outcome {
                            if self.position == body.len() {
                                Next::End
                            } else {
                                Next::Chunk(body.slice(self.position..))
                            }
                        } else if self.cursor < inner.chunks.len() {
                            Next::Chunk(inner.chunks[self.cursor].clone())
                        } else {
                            match &inner.outcome {
                                Some(Ok(_)) => Next::End,
                                Some(Err(error)) => Next::Error(error.clone()),
                                None => Next::Wait,
                            }
                        }
                    }
                    None => match &inner.outcome {
                        Some(Ok(_)) => Next::Error(UpstreamError::Internal),
                        Some(Err(error)) => Next::Error(error.clone()),
                        None => Next::Wait,
                    },
                }
            };
            match next {
                Next::Chunk(chunk) => {
                    self.cursor += 1;
                    self.position += chunk.len();
                    return Poll::Ready(Some(Ok(chunk)));
                }
                Next::End => {
                    self.terminated = true;
                    return Poll::Ready(None);
                }
                Next::Error(error) => {
                    self.terminated = true;
                    return Poll::Ready(Some(Err(error)));
                }
                Next::Wait => {}
            }

            if self.changed.is_none() {
                match self.version.has_changed() {
                    Ok(true) => {
                        self.version.mark_unchanged();
                        continue;
                    }
                    Ok(false) => {
                        let mut version = self.version.clone();
                        self.changed = Some(Box::pin(async move { version.changed().await }));
                    }
                    Err(_) => {
                        self.terminated = true;
                        return Poll::Ready(Some(Err(UpstreamError::Internal)));
                    }
                }
            }
            let changed = self.changed.as_mut().expect("change future exists");
            match changed.as_mut().poll(cx) {
                Poll::Ready(Ok(())) => {
                    self.changed = None;
                    self.version.mark_unchanged();
                }
                Poll::Ready(Err(_)) => {
                    self.terminated = true;
                    return Poll::Ready(Some(Err(UpstreamError::Internal)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl Drop for SubscriberStream {
    fn drop(&mut self) {
        self.flight.subscribers.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Joins at chunk zero and exposes a body as soon as validation publishes its
/// content type. There is deliberately no wait-for-completion path.
pub(crate) async fn asset_stream(flight: Arc<AssetFlight>) -> Result<AssetStream, UpstreamError> {
    let mut subscriber = flight.join();
    let content_type = subscriber.wait_content_type().await?;
    Ok(AssetStream {
        content_type,
        body: Box::pin(subscriber),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MagicStatus {
    Incomplete,
    Valid,
    Invalid,
}

/// Validates as much of a media prefix as is currently available.
///
/// `eof` distinguishes an incomplete prefix from a complete, but too short,
/// upstream body. AVIF is accepted only after its entire declared `ftyp` box is
/// present; a compatible `avif` brand alone does not make a truncated box valid.
pub(crate) fn validate_magic_prefix(content_type: &str, prefix: &[u8], eof: bool) -> MagicStatus {
    match content_type {
        "image/png" => fixed_signature(prefix, eof, b"\x89PNG\r\n\x1a\n"),
        "image/jpeg" => fixed_signature(prefix, eof, b"\xff\xd8\xff"),
        "image/gif" => {
            let available = prefix.len().min(6);
            if prefix[..available] != b"GIF87a"[..available]
                && prefix[..available] != b"GIF89a"[..available]
            {
                return MagicStatus::Invalid;
            }
            if available == 6 {
                MagicStatus::Valid
            } else if eof {
                MagicStatus::Invalid
            } else {
                MagicStatus::Incomplete
            }
        }
        "image/webp" => {
            if prefix.len() < 12 {
                return if eof {
                    MagicStatus::Invalid
                } else {
                    MagicStatus::Incomplete
                };
            }
            if &prefix[..4] == b"RIFF" && &prefix[8..12] == b"WEBP" {
                MagicStatus::Valid
            } else {
                MagicStatus::Invalid
            }
        }
        "image/avif" => avif_signature(prefix, eof),
        _ => MagicStatus::Invalid,
    }
}

fn fixed_signature(prefix: &[u8], eof: bool, signature: &[u8]) -> MagicStatus {
    let available = prefix.len().min(signature.len());
    if prefix[..available] != signature[..available] {
        return MagicStatus::Invalid;
    }
    if available == signature.len() {
        MagicStatus::Valid
    } else if eof {
        MagicStatus::Invalid
    } else {
        MagicStatus::Incomplete
    }
}

fn avif_signature(prefix: &[u8], eof: bool) -> MagicStatus {
    if prefix.len() < 4 {
        return if eof {
            MagicStatus::Invalid
        } else {
            MagicStatus::Incomplete
        };
    }

    let box_len = u32::from_be_bytes(prefix[..4].try_into().expect("four-byte prefix")) as usize;
    if !(16..=256).contains(&box_len) || !box_len.is_multiple_of(4) {
        return MagicStatus::Invalid;
    }
    if prefix.len() < 8 {
        return if eof {
            MagicStatus::Invalid
        } else {
            MagicStatus::Incomplete
        };
    }
    if &prefix[4..8] != b"ftyp" {
        return MagicStatus::Invalid;
    }
    if prefix.len() < box_len {
        return if eof {
            MagicStatus::Invalid
        } else {
            MagicStatus::Incomplete
        };
    }

    let major_is_avif = &prefix[8..12] == b"avif";
    let compatible_is_avif = prefix[16..box_len]
        .as_chunks::<4>()
        .0
        .iter()
        .any(|brand| brand == b"avif");
    if major_is_avif || compatible_is_avif {
        MagicStatus::Valid
    } else {
        MagicStatus::Invalid
    }
}

#[cfg(test)]
mod tests {
    use futures_util::StreamExt;

    use super::*;

    async fn read_all(mut stream: SubscriberStream) -> Vec<u8> {
        let mut body = Vec::new();
        while let Some(chunk) = stream.next().await {
            body.extend_from_slice(&chunk.expect("stream succeeds"));
        }
        body
    }

    fn avif_box(major: &[u8; 4], first: &[u8; 4], second: &[u8; 4]) -> Vec<u8> {
        let mut prefix = Vec::from(24_u32.to_be_bytes());
        prefix.extend_from_slice(b"ftyp");
        prefix.extend_from_slice(major);
        prefix.extend_from_slice(&0_u32.to_be_bytes());
        prefix.extend_from_slice(first);
        prefix.extend_from_slice(second);
        prefix
    }

    #[tokio::test]
    async fn every_reader_starts_at_chunk_zero() {
        let flight = AssetFlight::new();
        let mut first = flight.join();
        flight.publish_content_type(Ok("image/png".into()));
        let second = flight.join();
        let stream = asset_stream(Arc::clone(&flight))
            .await
            .expect("validated stream");

        flight.append(Bytes::from_static(b"first"));
        flight.append(Bytes::from_static(b"second"));
        flight.finish(Ok(Bytes::from_static(b"firstsecond")));

        assert_eq!(first.wait_content_type().await.as_deref(), Ok("image/png"));
        assert_eq!(read_all(first).await, b"firstsecond");
        assert_eq!(read_all(second).await, b"firstsecond");
        let body: Vec<u8> = stream
            .body
            .map(|chunk| chunk.expect("stream succeeds"))
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .flatten()
            .collect();
        assert_eq!(body, b"firstsecond");
    }

    #[tokio::test]
    async fn slow_reader_does_not_delay_fast_reader_or_lose_eof_chunks() {
        let flight = AssetFlight::new();
        let mut slow = flight.join();
        let fast = flight.join();
        flight.publish_content_type(Ok("image/png".into()));
        flight.append(Bytes::from_static(b"a"));
        assert_eq!(
            slow.next().await.expect("chunk").expect("valid"),
            Bytes::from_static(b"a")
        );
        flight.append(Bytes::from_static(b"b"));
        flight.append(Bytes::from_static(b"c"));
        flight.finish(Ok(Bytes::from_static(b"abc")));

        // The fast reader reaches EOF while the slow reader is still at byte 1.
        assert_eq!(read_all(fast).await, b"abc");
        assert_eq!(read_all(slow).await, b"bc");
        assert_eq!(
            flight.outcome().expect("outcome").expect("success"),
            Bytes::from_static(b"abc")
        );
    }

    #[tokio::test]
    async fn drop_accounts_for_unpolled_eof_and_cancelled_readers() {
        let flight = AssetFlight::new();
        let unpolled = flight.join();
        let mut completed = flight.join();
        let waiting = flight.join();
        assert_eq!(flight.subscriber_count(), 3);

        drop(unpolled);
        assert_eq!(flight.subscriber_count(), 2);
        flight.publish_content_type(Ok("image/png".into()));
        flight.finish(Ok(Bytes::new()));
        assert!(completed.next().await.is_none());
        assert_eq!(flight.subscriber_count(), 2);
        drop(completed);
        assert_eq!(flight.subscriber_count(), 1);
        drop(waiting);
        assert_eq!(flight.subscriber_count(), 0);
    }

    #[tokio::test]
    async fn terminal_outcome_before_content_type_wakes_waiter() {
        let flight = AssetFlight::new();
        let mut subscriber = flight.join();
        flight.finish(Err(UpstreamError::Internal));
        assert_eq!(
            subscriber.wait_content_type().await,
            Err(UpstreamError::Internal)
        );
    }

    #[test]
    fn assembled_outcome_and_cache_share_one_body_allocation() {
        let flight = AssetFlight::new();
        flight.publish_content_type(Ok("image/png".into()));
        let slow = flight.join();
        for chunk in ["a", "b", "c", "d", "e"] {
            flight.append(Bytes::from_static(chunk.as_bytes()));
        }
        let full = flight.assemble();
        let cached = re0auth_api::cache::CachedResponse::new("image/png", full.clone());
        flight.finish(Ok(full));
        let outcome = flight.outcome().expect("outcome").expect("success");
        assert_eq!(outcome.as_ptr(), cached.body_bytes().as_ptr());
        assert_eq!(outcome, Bytes::from_static(b"abcde"));
        assert!(flight.inner.read().chunks.is_empty());
        drop(slow);
    }

    #[test]
    fn short_and_mismatched_fixed_signatures_fail_closed() {
        assert_eq!(
            validate_magic_prefix("image/png", b"\x89PNG", false),
            MagicStatus::Incomplete
        );
        assert_eq!(
            validate_magic_prefix("image/png", b"\x89PNG", true),
            MagicStatus::Invalid
        );
        assert_eq!(
            validate_magic_prefix("image/jpeg", b"\xff\xd8", true),
            MagicStatus::Invalid
        );
        assert_eq!(
            validate_magic_prefix("image/gif", b"GIF89", true),
            MagicStatus::Invalid
        );
        assert_eq!(
            validate_magic_prefix("image/webp", b"RIFF\x00\x00\x00\x00WEB", true),
            MagicStatus::Invalid
        );
        assert_eq!(
            validate_magic_prefix("image/gif", b"GIF87a", true),
            MagicStatus::Valid
        );
        assert_eq!(
            validate_magic_prefix("image/gif", b"GIF89a", true),
            MagicStatus::Valid
        );
        assert_eq!(
            validate_magic_prefix("image/webp", b"RIFF\x04\x00\x00\x00WEBP", true),
            MagicStatus::Valid
        );
        assert_eq!(
            validate_magic_prefix("image/png", b"not a png", true),
            MagicStatus::Invalid
        );
    }

    #[test]
    fn avif_accepts_compatible_brand_at_byte_16_or_20_after_full_box() {
        for prefix in [
            avif_box(b"mif1", b"avif", b"mif1"),
            avif_box(b"miaf", b"isom", b"avif"),
        ] {
            for end in 0..prefix.len() {
                assert_eq!(
                    validate_magic_prefix("image/avif", &prefix[..end], false),
                    MagicStatus::Incomplete,
                    "prefix length {end}"
                );
            }
            assert_eq!(
                validate_magic_prefix("image/avif", &prefix, false),
                MagicStatus::Valid
            );
        }

        let major_only = avif_box(b"avif", b"mif1", b"miaf");
        assert_eq!(
            validate_magic_prefix("image/avif", &major_only[..12], true),
            MagicStatus::Invalid
        );
        assert_eq!(
            validate_magic_prefix("image/avif", &major_only, true),
            MagicStatus::Valid
        );
    }

    #[test]
    fn avif_rejects_bad_brands_truncation_and_malformed_boxes() {
        assert_eq!(
            validate_magic_prefix("image/avif", &avif_box(b"mif1", b"isom", b"miaf"), true),
            MagicStatus::Invalid
        );
        assert_eq!(
            validate_magic_prefix(
                "image/avif",
                &avif_box(b"mif1", b"avif", b"mif1")[..20],
                true
            ),
            MagicStatus::Invalid
        );

        for box_len in [12_u32, 258, 260, 18] {
            let mut prefix = avif_box(b"avif", b"mif1", b"miaf");
            prefix[..4].copy_from_slice(&box_len.to_be_bytes());
            assert_eq!(
                validate_magic_prefix("image/avif", &prefix, false),
                MagicStatus::Invalid
            );
        }
        let mut wrong_box = avif_box(b"avif", b"mif1", b"miaf");
        wrong_box[4..8].copy_from_slice(b"free");
        assert_eq!(
            validate_magic_prefix("image/avif", &wrong_box, true),
            MagicStatus::Invalid
        );
    }
}
