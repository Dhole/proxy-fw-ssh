use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::model::Permission;
use crate::ui::messages::{ReplyPermission, RequestPermission, RequestUi};
use anyhow::{anyhow, bail, Context, Error, Result};
use async_channel::{Receiver, Sender};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::oneshot;

// pub struct RequestUiHandler<'a> {
//     pub pk_openssh: &'a str,
//     pub tx: &'a Sender<RequestUi>,
// }
//
// impl<'a> RequestUiHandler<'a> {
//     async fn request(self, action: String) -> ReplyPermission {
//         let req = RequestPermission {
//             pk_openssh: self.pk_openssh.to_string(),
//             action,
//         };
//         req.request(self.tx).await
//     }
// }

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
        let rules_toml = fs::read(file_path)?;
        let clients: HashMap<String, ClientRules> = toml::from_slice(&rules_toml)?;
        Ok(Self {
            clients,
            file_path: file_path.to_path_buf(),
            req_rx,
            req_ui_tx,
        })
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
        let mut client_rules = match self.clients.get_mut(&req.pk_openssh) {
            Some(rules) => rules,
            None => {
                // TODO: New client, ui request to give it a name and save it
                updated = true;
                todo!()
            }
        };
        let res = client_rules
            .validate_exec(&mut updated, &self.req_ui_tx, &req)
            .await;
        if updated {
            todo!("update");
        }
        res
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ClientRules {
    name: Option<String>,
    servers: HashMap<String, ServerRules>,
}

impl ClientRules {
    pub async fn validate_exec(
        &mut self,
        updated: &mut bool,
        req_ui_tx: &Sender<RequestUi>,
        req: &RequestRulesExec,
    ) -> Result<()> {
        let Some(server_rules) = self.servers.get(&req.server_addr) else {
            bail!("TODO: server {} not in rules", &req.server_addr);
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

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ServerRules {
    git: GitRules,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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
        &self,
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
        let access_rule = self.paths.get(arg1).cloned().unwrap_or_default();
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
                    if now {
                        Ok(())
                    } else {
                        Err(anyhow!("interactively denied"))
                    }
                    // TODO: update rules with future
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
                    if now {
                        Ok(())
                    } else {
                        Err(anyhow!("interactively denied"))
                    }
                    // TODO: update rules with future
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

impl GitAccessRule {
    fn read(&self) -> bool {
        matches!(self.read, Permission::Yes)
    }
    fn write(&self) -> bool {
        matches!(self.write, Permission::Yes)
    }
}
