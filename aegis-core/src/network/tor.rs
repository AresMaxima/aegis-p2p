use arti_client::{config::CfgPath, TorClient, TorClientConfig};
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use tempfile::TempDir;
use tor_rtcompat::tokio::TokioRustlsRuntime;

pub struct AegisTorClient {
    client: Option<TorClient<TokioRustlsRuntime>>,
    ram_fs: Option<TempDir>,
}

impl AegisTorClient {
    pub async fn bootstrap() -> Result<Self, Box<dyn Error>> {
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
                    let size = metadata.len() as usize;
                    if let Ok(mut file) = OpenOptions::new().write(true).open(&entry_path) {
                        let zeros = vec![0u8; size];
                        let _ = file.write_all(&zeros);
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

    #[tokio::test]
    async fn test_tor_client_instantiation_and_wipe() {
        let client = AegisTorClient::bootstrap()
            .await
            .expect("Erreur au bootstrap");

        let path_copy = client.ram_fs.as_ref().unwrap().path().to_path_buf();
        assert!(path_copy.exists(), "Le dossier temporaire doit exister");

        drop(client);

        // Attente asynchrone pour permettre à Tokio de libérer les handles d'E/S sous Windows
        for _ in 0..20 {
            if !path_copy.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            secure_wipe_dir(&path_copy);
        }

        assert!(
            !path_copy.exists(),
            "Le dossier temporaire doit être totalement détruit après le Kill Switch"
        );
    }
}