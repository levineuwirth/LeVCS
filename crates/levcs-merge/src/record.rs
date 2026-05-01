//! Merge metadata blob, written at `.levcs/merge-record` in the merge
//! commit's tree (§6.5).

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MergeRecord {
    pub schema_version: u32,
    pub base: String,
    pub ours: String,
    pub theirs: String,
    #[serde(default, rename = "file")]
    pub files: Vec<FileRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileRecord {
    pub path: String,
    pub handler: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub handler_hash: String,
    pub status: FileStatus,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes: String,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileStatus {
    Auto,
    Manual,
    Ours,
    Theirs,
}

impl MergeRecord {
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }

    pub fn from_toml(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }
}
