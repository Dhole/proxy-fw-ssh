use async_channel::{Receiver, Sender};
use ssh_key::PublicKey;
use std::sync::Arc;
use tokio::sync::oneshot;

use crate::model::Permission;

pub enum RequestUi {
    Permission(RequestPermission, oneshot::Sender<ReplyPermission>),
    ClientName(RequestClientName, oneshot::Sender<ReplyClientName>),
    AcceptKey(RequestAcceptKey, oneshot::Sender<ReplyAcceptKey>),
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

pub struct RequestClientName {
    pub pk_openssh: String,
}

#[derive(Debug)]
pub struct ReplyClientName {
    pub name: Option<String>,
}

impl RequestClientName {
    pub async fn request(self, tx: &Sender<RequestUi>) -> ReplyClientName {
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RequestUi::ClientName(self, reply_tx))
            .await
            .unwrap();
        reply_rx.await.unwrap()
    }
}

pub struct RequestAcceptKey {
    pub host: String,
    pub key: PublicKey,
}

#[derive(Debug)]
pub struct ReplyAcceptKey {
    pub accept: bool,
}

impl RequestAcceptKey {
    pub async fn request(self, tx: &Sender<RequestUi>) -> ReplyAcceptKey {
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RequestUi::AcceptKey(self, reply_tx)).await.unwrap();
        reply_rx.await.unwrap()
    }
}
