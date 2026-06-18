use std::collections::HashMap;

use crate::model::Permission;
use crate::ui::messages::{ReplyPermission, RequestPermission, UiRequest};
use async_channel::{Receiver, Sender};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::oneshot;

pub struct RequestHandler {
    pub pk_openssh: String,
    pub tx: Sender<UiRequest>,
}

impl RequestHandler {
    async fn request(&self, action: String) -> ReplyPermission {
        let (reply_tx, reply_rx) = oneshot::channel();
        let req = RequestPermission {
            pk_openssh: self.pk_openssh.clone(),
            action,
            reply_tx,
        };
        self.tx.send(UiRequest::Permission(req)).await.unwrap();
        reply_rx.await.unwrap()
    }
}

pub type Rules = HashMap<String, ClientRules>;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ClientRules {
    name: Option<String>,
    servers: HashMap<String, ServerRules>,
}

impl ClientRules {
    pub async fn validate_exec(
        &self,
        handler: &RequestHandler,
        server_addr: &str,
        user: &str,
        data: &str,
    ) -> Result<(), String> {
        let Some(server_rules) = self.servers.get(server_addr) else {
            return Err(format!("server {} not in rules", server_addr));
        };
        if GitRules::matches_exec(user, data) {
            return server_rules
                .git
                .validate_exec(handler, user, data)
                .await
                .map_err(|e| format!("git: {}", e));
        }
        return Err(format!(
            "no plugin matches with user:{}, data:{}",
            user, data
        ));
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
        handler: &RequestHandler,
        _user: &str,
        data: &str,
    ) -> Result<(), String> {
        let Some(args) = shlex::split(data) else {
            return Err("parsing command".to_string());
        };
        let Some(arg0) = args.get(0) else {
            return Err("missing arg0".to_string());
        };
        let Some(arg1) = args.get(1) else {
            return Err("missing arg1".to_string());
        };
        let access_rule = self.paths.get(arg1).cloned().unwrap_or_default();
        match arg0.as_str() {
            "git-upload-pack" => match access_rule.read {
                Permission::Yes => Ok(()),
                Permission::No => Err("read not allowed".to_string()),
                Permission::Ask => {
                    let ReplyPermission { now, future } =
                        handler.request(format!("read from {}", arg1)).await;
                    if now {
                        Ok(())
                    } else {
                        Err("interactively denied".to_string())
                    }
                    // TODO: update rules with future
                }
            },
            "git-receive-pack" => match access_rule.write {
                Permission::Yes => Ok(()),
                Permission::No => Err("write not allowed".to_string()),
                Permission::Ask => {
                    let ReplyPermission { now, future } =
                        handler.request(format!("write to {}", arg1)).await;
                    if now {
                        Ok(())
                    } else {
                        Err("interactively denied".to_string())
                    }
                    // TODO: update rules with future
                }
            },
            _ => Err(format!("invalid command {}", arg0)),
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
