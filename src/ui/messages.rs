use std::sync::Arc;
use tokio::sync::SetOnce;

use crate::model::Permission;

pub enum UiRequest {
    Permission(PermissionRequest),
}

pub struct PermissionRequest {
    pub pk_openssh: String,
    pub action: String,
    pub reply: Arc<SetOnce<(bool, Permission)>>,
}
