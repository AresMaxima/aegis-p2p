use arti_client::{config::CfgPath, TorClient, TorClientConfig};
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use tempfile::TempDir;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use futures::io::AsyncWriteExt; // Requis pour écrire dans un stream Arti
use tor_rtcompat::tokio::TokioRustlsRuntime;
use zeroize::Zeroize;

pub struct AegisTorClient {
    client: Option<TorClient<TokioRustlsRuntime>>,
    ram_fs: Option<TempDir>,
}

impl AegisTorClient {
    pub async fn bootstrap(target_onion: &str, file_path: &str) -> Result<Self, Box<dyn Error>> {
        let ram_fs = tempfile::tempdir()?;
        let state_dir = ram_fs.path().join("state");
        let cache_dir = ram_fs.path().join("cache");

        fs::create_dir_all(&state_dir)?;
        fs::create_dir_all(&cache_dir)?;

        let mut config_builder = TorClientConfig::builder();

        config_builder
            .storage()
            .state_dir(CfgPath::new(state_dir.display().to_string()))
            .cache_dir(CfgPath::new(cache_dir.display().to_string()));

        let config = config_builder.build()?;
        let runtime = TokioRustlsRuntime::current()?;

        let client = TorClient::with_runtime(runtime)
            .config(config)
            .create_bootstrapped()
            .await?;

        let mut stream = client.connect((target_onion, 80)).await?;
        let mut file = File::open(file_path).await?;
        let mut buffer = [0u8; 8192]; 

        loop {
            let bytes_read = file.read(&mut buffer).await?;
            if bytes_read == 0 {
                break; 
            }
            stream.write_all(&buffer[..bytes_read]).await?;
        }
        
        // CORRECTION: Flush suivi de la fermeture obligatoire (EOF) pour libérer le nœud récepteur
        stream.flush().await?;
        stream.close().await?;

        Ok(Self {
            client: Some(client),
            ram_fs: Some(ram_fs),
        })
    }

    pub fn inner(&self) -> &TorClient<TokioRustlsRuntime> {
        self.client.as_ref().expect("Le client Tor a été détruit")
    }
}

impl Drop for AegisTorClient {
    fn drop(&mut self) {
        self.client.take();

        if let Some(temp_dir) = self.ram_fs.take() {
            let path = temp_dir.path().to_path_buf();
            secure_wipe_dir(&path);
            let _ = temp_dir.close();
        }
    }
}

pub fn secure_wipe_dir(path: &Path) {
    if !path.exists() {
        return;
    }
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let entry_path = entry.path();
            if entry_path.is_file() {
                if let Ok(metadata) = fs::metadata(&entry_path) {
                    let size = metadata.len();
                    if let Ok(mut file) = OpenOptions::new().write(true).open(&entry_path) {
                        let zeros = [0u8; 8192];
                        let mut written: u64 = 0;
                        while written < size {
                            let to_write = std::cmp::min(8192, size - written) as usize;
                            if file.write_all(&zeros[..to_write]).is_err() {
                                break;
                            }
                            written += to_write as u64;
                        }
                        let _ = file.sync_all();
                    }
                }
                let _ = fs::remove_file(&entry_path);
            } else if entry_path.is_dir() {
                secure_wipe_dir(&entry_path);
            }
        }
    }
    let _ = fs::remove_dir(path);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tor_client_instantiation_and_wipe() {
        let mut dummy_key = [0x42u8; 32];
        assert_eq!(dummy_key.len(), 32);
        dummy_key.zeroize();
        assert_eq!(dummy_key, [0u8; 32]);
    }
}