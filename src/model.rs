use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum Permission {
    #[default]
    #[serde(rename = "ask")]
    Ask,
    #[serde(rename = "yes")]
    Yes,
    #[serde(rename = "no")]
    No,
}
