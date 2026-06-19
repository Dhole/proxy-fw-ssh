use std::collections::HashMap;
use std::fs;
use std::hash::Hash;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use crate::model::Permission;
use crate::ui::messages::{
    ReplyClientName, ReplyPermission, RequestClientName, RequestPermission, RequestUi,
};
use anyhow::{anyhow, bail, Context, Error, Result};
use async_channel::{Receiver, Sender};
use log::error;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::oneshot;

pub enum RequestRules {
    Exec(RequestRulesExec, oneshot::Sender<Result<()>>),
}

pub struct RequestRulesExec {
    pub pk_openssh: String,
    pub server_addr: String,
    pub user: String,
    pub data: String,
}

impl RequestRulesExec {
    pub async fn request(self, tx: &Sender<RequestRules>) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RequestRules::Exec(self, reply_tx)).await.unwrap();
        reply_rx.await.unwrap()
    }
}

pub struct Rules {
    clients: HashMap<String, ClientRules>,
    file_path: PathBuf,
    req_rx: Receiver<RequestRules>,
    req_ui_tx: Sender<RequestUi>,
}

impl Rules {
    pub fn new(
        file_path: &Path,
        req_rx: Receiver<RequestRules>,
        req_ui_tx: Sender<RequestUi>,
    ) -> Result<Self> {
        let clients: HashMap<String, ClientRules> = match fs::read(file_path) {
            Err(e) if e.kind() == ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(e.into()),
            Ok(rules_json) => serde_json::from_slice(&rules_json)?,
        };
        Ok(Self {
            clients,
            file_path: file_path.to_path_buf(),
            req_rx,
            req_ui_tx,
        })
    }

    fn _save(&self) -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&self.file_path)?;
        serde_json::to_writer_pretty(&mut file, &self.clients)?;
        Ok(())
    }
    fn save(&self) {
        if let Err(e) = self._save() {
            error!("fatal: failed to save rules: {e}");
            std::process::exit(1);
        }
    }

    pub async fn run(mut self) {
        while let Ok(req) = self.req_rx.recv().await {
            match req {
                RequestRules::Exec(req, reply_tx) => {
                    let res = self.handle_req_exec(req).await;
                    reply_tx.send(res).unwrap();
                }
            }
        }
    }

    async fn handle_req_exec(&mut self, req: RequestRulesExec) -> Result<()> {
        let mut updated = false;
        let client_rules = match self.clients.get_mut(&req.pk_openssh) {
            Some(rules) => rules,
            None => {
                updated = true;
                let ReplyClientName { name } = (RequestClientName {
                    pk_openssh: req.pk_openssh.clone(),
                })
                .request(&self.req_ui_tx)
                .await;
                if let Some(name) = name {
                    self.clients
                        .insert(req.pk_openssh.clone(), ClientRules::new(name));
                    self.clients
                        .get_mut(&req.pk_openssh)
                        .expect("just inserted")
                } else {
                    bail!("no client name set");
                }
            }
        };
        let res = client_rules
            .validate_exec(&mut updated, &self.req_ui_tx, &req)
            .await;
        if updated {
            self.save();
        }
        res
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ClientRules {
    name: String,
    servers: HashMap<String, ServerRules>,
}

impl ClientRules {
    fn new(name: String) -> Self {
        Self {
            name,
            servers: HashMap::new(),
        }
    }
    pub async fn validate_exec(
        &mut self,
        updated: &mut bool,
        req_ui_tx: &Sender<RequestUi>,
        req: &RequestRulesExec,
    ) -> Result<()> {
        let server_rules = match self.servers.get_mut(&req.server_addr) {
            Some(server_rules) => server_rules,
            None => {
                *updated = true;
                self.servers
                    .insert(req.server_addr.clone(), ServerRules::default());
                self.servers
                    .get_mut(&req.server_addr)
                    .expect("just inserted")
            }
        };
        if GitRules::matches_exec(&req.user, &req.data) {
            return server_rules
                .git
                .validate_exec(updated, req_ui_tx, &req)
                .await
                .context("git rule");
        }
        bail!(
            "no plugin matches with user:{}, data:{}",
            &req.user,
            &req.data
        );
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct ServerRules {
    git: GitRules,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct GitRules {
    #[serde(flatten)]
    paths: HashMap<String, GitAccessRule>,
}

impl GitRules {
    fn matches_exec(user: &str, data: &str) -> bool {
        user == "git"
            && (data.starts_with("git-upload-pack") || data.starts_with("git-receive-pack"))
    }
    async fn validate_exec(
        &mut self,
        updated: &mut bool,
        req_ui_tx: &Sender<RequestUi>,
        req: &RequestRulesExec,
    ) -> Result<()> {
        let Some(args) = shlex::split(&req.data) else {
            bail!("parsing command");
        };
        let Some(arg0) = args.get(0) else {
            bail!("missing arg0");
        };
        let Some(arg1) = args.get(1) else {
            bail!("missing arg1");
        };
        let access_rule = match self.paths.get_mut(arg1) {
            Some(access_rule) => access_rule,
            None => {
                *updated = true;
                self.paths.insert(arg1.clone(), GitAccessRule::default());
                self.paths.get_mut(arg1).expect("just inserted")
            }
        };
        match arg0.as_str() {
            "git-upload-pack" => match access_rule.read {
                Permission::Yes => Ok(()),
                Permission::No => Err(anyhow!("read not allowed")),
                Permission::Ask => {
                    let ReplyPermission { now, future } = RequestPermission {
                        pk_openssh: req.pk_openssh.clone(),
                        action: format!("read from {}", arg1),
                    }
                    .request(req_ui_tx)
                    .await;
                    if !matches!(future, Permission::Ask) {
                        *updated = true;
                        access_rule.read = future;
                    }
                    if now {
                        Ok(())
                    } else {
                        Err(anyhow!("interactively denied"))
                    }
                }
            },
            "git-receive-pack" => match access_rule.write {
                Permission::Yes => Ok(()),
                Permission::No => Err(anyhow!("write not allowed")),
                Permission::Ask => {
                    let ReplyPermission { now, future } = RequestPermission {
                        pk_openssh: req.pk_openssh.clone(),
                        action: format!("write to {}", arg1),
                    }
                    .request(req_ui_tx)
                    .await;
                    if !matches!(future, Permission::Ask) {
                        *updated = true;
                        access_rule.write = future;
                    }
                    if now {
                        Ok(())
                    } else {
                        Err(anyhow!("interactively denied"))
                    }
                }
            },
            _ => Err(anyhow!("invalid command {}", arg0)),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct GitAccessRule {
    read: Permission,
    write: Permission,
}
