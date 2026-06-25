use crate::ui::messages::{ReplyAcceptKey, RequestAcceptKey, RequestUi};
use anyhow::{anyhow, bail, Context, Error, Result};
use async_channel::{Receiver, Sender};
use log::{error, warn};
use ssh_key::Fingerprint;
use ssh_key::HashAlg::Sha256;
use ssh_key::PublicKey;
use std::collections::HashMap;
use std::fs::File;
use std::io::ErrorKind;
use std::io::Write;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use tokio::sync::oneshot;

pub enum RequestKnownHosts {
    KnownHost(RequestKnownHost, oneshot::Sender<Result<()>>),
}

pub struct RequestKnownHost {
    pub host: String,
    pub key: PublicKey,
}

impl RequestKnownHost {
    pub async fn request(self, tx: &Sender<RequestKnownHosts>) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RequestKnownHosts::KnownHost(self, reply_tx))
            .await
            .unwrap();
        reply_rx.await.unwrap()
    }
}

pub struct KnownHosts {
    hosts: HashMap<String, Entry>,
    file_path: PathBuf,
    req_rx: Receiver<RequestKnownHosts>,
    req_ui_tx: Sender<RequestUi>,
}

#[derive(Debug)]
struct Entry {
    line_num: usize,
    key: PublicKey,
}

impl KnownHosts {
    fn read(file_path: &Path) -> Result<HashMap<String, Entry>> {
        let hosts: HashMap<String, Entry> = match File::open(file_path) {
            Err(e) if e.kind() == ErrorKind::NotFound => {
                File::create(file_path)?;
                HashMap::new()
            }
            Err(e) => return Err(e.into()),
            Ok(file) => {
                let mut hosts = HashMap::new();
                for line in BufReader::new(file).lines() {
                    let line = line?;
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    let Some((host, openssh_public_key)) = line.split_once(' ') else {
                        bail!(
                            "missing space between host and public key in line {}",
                            hosts.len() + 1
                        );
                    };
                    let key = PublicKey::from_openssh(openssh_public_key)?;
                    let entry = Entry {
                        line_num: hosts.len() + 1,
                        key,
                    };
                    hosts.insert(host.to_string(), entry);
                }
                hosts
            }
        };
        Ok(hosts)
    }
    fn _append(&mut self, host: &str, key: PublicKey) -> Result<()> {
        let mut file = File::options().append(true).open(&self.file_path)?;
        let key_openssh = key.to_openssh().expect("valid key");
        write!(&mut file, "{} {}\n", host, key_openssh)?;
        let entry = Entry {
            line_num: self.hosts.len() + 1,
            key,
        };
        self.hosts.insert(host.to_string(), entry);
        Ok(())
    }
    fn append(&mut self, host: &str, key: PublicKey) {
        if let Err(e) = self._append(host, key) {
            error!("fatal: failed to append known_hosts: {e}");
            std::process::exit(1);
        }
    }
    pub fn new(
        file_path: impl AsRef<Path>,
        req_rx: Receiver<RequestKnownHosts>,
        req_ui_tx: Sender<RequestUi>,
    ) -> Result<Self> {
        let hosts = Self::read(file_path.as_ref())?;
        Ok(Self {
            hosts,
            file_path: file_path.as_ref().to_path_buf(),
            req_rx,
            req_ui_tx,
        })
    }

    pub async fn run(mut self) {
        while let Ok(req) = self.req_rx.recv().await {
            match req {
                RequestKnownHosts::KnownHost(req, reply_tx) => {
                    let res = self.handle_req_known_host(req).await;
                    reply_tx.send(res).unwrap();
                }
            }
        }
    }

    async fn handle_req_known_host(&mut self, req: RequestKnownHost) -> Result<()> {
        if let Some(entry) = self.hosts.get(&req.host) {
            if entry.key == req.key {
                return Ok(());
            } else {
                warn!("WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!");
                warn!("TODO: Show more info {:?}", entry);
                bail!("key fingerprint for {} has changed", req.host);
            }
        } else {
            let ReplyAcceptKey { accept } = RequestAcceptKey {
                host: req.host.clone(),
                key: req.key.clone(),
            }
            .request(&self.req_ui_tx)
            .await;
            if accept {
                self.append(&req.host, req.key);
                Ok(())
            } else {
                Err(anyhow!(
                    "rejected host {} with key fingerprint {}",
                    req.host,
                    req.key.fingerprint(Sha256)
                ))
            }
        }
    }
}
