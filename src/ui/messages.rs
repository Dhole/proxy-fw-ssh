use async_channel::{Receiver, Sender};
use std::sync::Arc;
use tokio::sync::oneshot;

use crate::model::Permission;

pub enum RequestUi {
    Permission(RequestPermission, oneshot::Sender<ReplyPermission>),
}

pub struct RequestPermission {
    pub pk_openssh: String,
    pub action: String,
}

#[derive(Debug)]
pub struct ReplyPermission {
    pub now: bool,
    pub future: Permission,
}

impl RequestPermission {
    pub async fn request(self, tx: &Sender<RequestUi>) -> ReplyPermission {
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RequestUi::Permission(self, reply_tx))
            .await
            .unwrap();
        reply_rx.await.unwrap()
    }
}
