use std::path::Path;
use std::sync::Arc;

use serde::Serialize;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use crate::error::AppResult;
use crate::evil::{AppliedMutation, EvilMode, deterministic_hash};

#[derive(Clone)]
pub struct ReproWriter {
    file: Arc<Mutex<tokio::fs::File>>,
}

impl ReproWriter {
    pub async fn open(path: impl AsRef<Path>) -> AppResult<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?;
        Ok(Self {
            file: Arc::new(Mutex::new(file)),
        })
    }

    pub async fn append(&self, record: ReproRecord) -> AppResult<()> {
        let mut line = serde_json::to_vec(&record)?;
        line.push(b'\n');

        let mut file = self.file.lock().await;
        file.write_all(&line).await?;
        file.flush().await?;
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct ReproRecord {
    pub global_seed: u64,
    pub connection_id: u64,
    pub command_index: u64,
    pub command_hash: String,
    pub command_bytes_hex: String,
    pub upstream_response_hash: Option<String>,
    pub upstream_response_bytes_hex: Option<String>,
    pub mutated_response_hash: String,
    pub mutated_response_bytes_hex: String,
    pub selected_evil_mode: EvilMode,
    pub mutations: Vec<AppliedMutation>,
}

impl ReproRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        global_seed: u64,
        connection_id: u64,
        command_index: u64,
        command_bytes: &[u8],
        upstream_response_bytes: Option<&[u8]>,
        mutated_response_bytes: &[u8],
        selected_evil_mode: EvilMode,
        mutations: Vec<AppliedMutation>,
    ) -> Self {
        Self {
            global_seed,
            connection_id,
            command_index,
            command_hash: deterministic_hash(command_bytes),
            command_bytes_hex: hex::encode(command_bytes),
            upstream_response_hash: upstream_response_bytes
                .map(deterministic_hash),
            upstream_response_bytes_hex: upstream_response_bytes
                .map(hex::encode),
            mutated_response_hash: deterministic_hash(mutated_response_bytes),
            mutated_response_bytes_hex: hex::encode(mutated_response_bytes),
            selected_evil_mode,
            mutations,
        }
    }
}
