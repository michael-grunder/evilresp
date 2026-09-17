//! Keep partially read upstream frames alive across command/event selection.
//! A bounded queue applies backpressure; dropping the session stops the reader.

use std::io;

use tokio::io::{AsyncRead, BufReader};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::resp::read_raw_frame;

pub(crate) struct UpstreamReader {
    frames: mpsc::Receiver<io::Result<Vec<u8>>>,
    task: JoinHandle<()>,
}

impl UpstreamReader {
    pub(crate) fn new<R: AsyncRead + Unpin + Send + 'static>(read: R) -> Self {
        let (send, frames) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            let mut read = BufReader::new(read);
            loop {
                // Reserve before reading, bounding queued and in-flight frames.
                let Ok(permit) = send.reserve().await else {
                    break;
                };
                let frame = read_raw_frame(&mut read).await;
                let failed = frame.is_err();
                permit.send(frame);
                if failed {
                    break;
                }
            }
        });
        Self { frames, task }
    }

    pub(crate) async fn next(&mut self) -> io::Result<Vec<u8>> {
        self.frames.recv().await.unwrap_or_else(|| {
            Err(io::Error::from(io::ErrorKind::UnexpectedEof))
        })
    }
}

impl Drop for UpstreamReader {
    fn drop(&mut self) {
        self.task.abort();
    }
}
