//! Length-prefixed JSON framing for the P2P wire protocol.
//!
//! Every message is encoded as a 4-byte big-endian length followed by that
//! many bytes of JSON. A hard cap on the frame size protects against memory
//! exhaustion from a hostile peer.

use std::io::ErrorKind;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Error, Result};

use super::message::Message;

/// Largest accepted message, in bytes.
pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

/// Read one message, or `None` on a clean end of stream.
pub async fn read_message<R>(reader: &mut R) -> Result<Option<Message>>
where
    R: AsyncRead + Unpin,
{
    let mut len_bytes = [0u8; 4];
    match reader.read_exact(&mut len_bytes).await {
        Ok(_) => {}
        Err(err) if err.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err.into()),
    }

    let len = u32::from_be_bytes(len_bytes) as usize;
    if len == 0 || len > MAX_FRAME_LEN {
        return Err(Error::Network(format!("invalid frame length {len}")));
    }

    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    let message =
        serde_json::from_slice(&buf).map_err(|err| Error::Serialization(err.to_string()))?;
    Ok(Some(message))
}

/// Write one message and flush it.
pub async fn write_message<W>(writer: &mut W, message: &Message) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let body = serde_json::to_vec(message).map_err(|err| Error::Serialization(err.to_string()))?;
    if body.len() > MAX_FRAME_LEN {
        return Err(Error::Network(format!(
            "message too large to send ({} bytes)",
            body.len()
        )));
    }

    writer.write_all(&(body.len() as u32).to_be_bytes()).await?;
    writer.write_all(&body).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trips_messages_over_a_pipe() {
        let (mut client, mut server) = tokio::io::duplex(4096);

        let sent = Message::Hello {
            protocol_version: 1,
            chain_id: 4242,
            best_height: 7,
            best_hash: [9u8; 32],
            finalized_height: 5,
        };

        let writer = tokio::spawn(async move {
            write_message(&mut client, &sent).await.unwrap();
            write_message(&mut client, &Message::Ping { nonce: 42 })
                .await
                .unwrap();
        });

        let first = read_message(&mut server).await.unwrap().unwrap();
        match first {
            Message::Hello {
                finalized_height,
                best_height,
                ..
            } => {
                assert_eq!(best_height, 7);
                assert_eq!(finalized_height, 5);
            }
            other => panic!("unexpected message: {other:?}"),
        }

        let second = read_message(&mut server).await.unwrap().unwrap();
        assert!(matches!(second, Message::Ping { nonce: 42 }));

        writer.await.unwrap();
    }

    #[tokio::test]
    async fn clean_eof_yields_none() {
        let (client, mut server) = tokio::io::duplex(64);
        drop(client);
        assert!(read_message(&mut server).await.unwrap().is_none());
    }
}
