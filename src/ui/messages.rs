use std::sync::Arc;
use tokio::sync::oneshot;

use crate::model::Permission;

pub enum UiRequest {
    Permission(RequestPermission),
}

pub struct RequestPermission {
    pub pk_openssh: String,
    pub action: String,
    pub reply_tx: oneshot::Sender<ReplyPermission>,
}

#[derive(Debug)]
pub struct ReplyPermission {
    pub now: bool,
    pub future: Permission,
}
