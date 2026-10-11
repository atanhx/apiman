use crate::security::SecretString;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretEntry {
    pub id: String,
    pub name: String,
    pub project: Option<String>,
    pub value: SecretString,
    pub tags: Vec<String>,
    pub description: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

impl SecretEntry {
    pub fn new(
        name: String,
        value: SecretString,
        project: Option<String>,
        tags: Vec<String>,
        description: Option<String>,
    ) -> Self {
        let now = current_timestamp();
        let normalized_project = match project.as_deref().map(str::trim) {
            None | Some("") => None,
            Some(p) if p.eq_ignore_ascii_case("global") => None,
            Some(p) => Some(p.to_string()),
        };

        Self {
            id: Uuid::new_v4().to_string(),
            name: name.trim().to_string(),
            project: normalized_project,
            value,
            tags: tags.into_iter().map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect(),
            description: description.map(|d| d.trim().to_string()).filter(|d| !d.is_empty()),
            created_at: now,
            updated_at: now,
        }
    }

    pub fn is_global(&self) -> bool {
        self.project.is_none() || self.project.as_deref() == Some("global")
    }

    pub fn project_display(&self) -> &str {
        self.project.as_deref().unwrap_or("global")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Vault {
    pub version: u32,
    pub entries: Vec<SecretEntry>,
}

impl Default for Vault {
    fn default() -> Self {
        Self::new()
    }
}

impl Vault {
    pub fn new() -> Self {
        Self {
            version: 1,
            entries: Vec::new(),
        }
    }

    pub fn set(
        &mut self,
        name: String,
        value: SecretString,
        project: Option<String>,
        tags: Vec<String>,
        description: Option<String>,
    ) -> &SecretEntry {
        let normalized_name = name.trim().to_string();
        let normalized_project = match project.as_deref().map(str::trim) {
            None | Some("") => None,
            Some(p) if p.eq_ignore_ascii_case("global") => None,
            Some(p) => Some(p.to_string()),
        };

        if let Some(pos) = self.entries.iter().position(|e| {
            e.name == normalized_name && e.project == normalized_project
        }) {
            let entry = &mut self.entries[pos];
            entry.value = value;
            if !tags.is_empty() {
                entry.tags = tags.into_iter().map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect();
            }
            if description.is_some() {
                entry.description = description;
            }
            entry.updated_at = current_timestamp();
            &self.entries[pos]
        } else {
            let entry = SecretEntry::new(normalized_name, value, normalized_project, tags, description);
            self.entries.push(entry);
            self.entries.last().unwrap()
        }
    }

    pub fn get(&self, name: &str, target_project: Option<&str>) -> Option<&SecretEntry> {
        let normalized_name = name.trim();
        let target_project = target_project.map(str::trim).filter(|p| !p.is_empty() && *p != "global");

        // 1. If explicit project specified, try to find in that project first
        if let Some(p) = target_project {
            if let Some(entry) = self.entries.iter().find(|e| {
                e.name.eq_ignore_ascii_case(normalized_name)
                    && e.project.as_deref().map(|s| s.eq_ignore_ascii_case(p)).unwrap_or(false)
            }) {
                return Some(entry);
            }
        }

        // 2. Try global entry (exact match first, then case-insensitive)
        if let Some(entry) = self.entries.iter().find(|e| e.name == normalized_name && e.is_global()) {
            return Some(entry);
        }
        if let Some(entry) = self.entries.iter().find(|e| e.name.eq_ignore_ascii_case(normalized_name) && e.is_global()) {
            return Some(entry);
        }

        // 3. Search across all projects without needing --project flag
        if let Some(entry) = self.entries.iter().find(|e| e.name == normalized_name) {
            return Some(entry);
        }
        if let Some(entry) = self.entries.iter().find(|e| e.name.eq_ignore_ascii_case(normalized_name)) {
            return Some(entry);
        }

        None
    }

    pub fn list(&self, project_filter: Option<&str>, tag_filter: Option<&str>) -> Vec<&SecretEntry> {
        self.entries
            .iter()
            .filter(|e| {
                if let Some(p) = project_filter {
                    let p_clean = p.trim();
                    if !p_clean.eq_ignore_ascii_case("all") {
                        if p_clean.eq_ignore_ascii_case("global") {
                            if !e.is_global() {
                                return false;
                            }
                        } else if e
                            .project
                            .as_deref()
                            .map(|ep| !ep.eq_ignore_ascii_case(p_clean))
                            .unwrap_or(true)
                            && !e.is_global()
                        {
                            return false;
                        }
                    }
                }
                if let Some(t) = tag_filter {
                    let t_clean = t.trim();
                    if !t_clean.is_empty() && !e.tags.iter().any(|tag| tag.eq_ignore_ascii_case(t_clean)) {
                        return false;
                    }
                }
                true
            })
            .collect()
    }

    pub fn resolve_env_map(
        &self,
        project: Option<&str>,
        tag_filter: Option<&str>,
    ) -> HashMap<String, String> {
        let mut map = HashMap::new();

        // 1. Insert global entries
        for entry in self.entries.iter().filter(|e| e.is_global()) {
            if let Some(t) = tag_filter {
                if !entry.tags.iter().any(|tag| tag.eq_ignore_ascii_case(t)) {
                    continue;
                }
            }
            map.insert(entry.name.clone(), entry.value.expose_secret().to_string());
        }

        // 2. Overlay project entries (scope match is case-insensitive like get/list)
        if let Some(proj) = project.map(str::trim).filter(|p| !p.is_empty() && !p.eq_ignore_ascii_case("global")) {
            for entry in self.entries.iter().filter(|e| {
                e.project
                    .as_deref()
                    .map(|ep| ep.eq_ignore_ascii_case(proj))
                    .unwrap_or(false)
            }) {
                if let Some(t) = tag_filter {
                    if !entry.tags.iter().any(|tag| tag.eq_ignore_ascii_case(t)) {
                        continue;
                    }
                }
                map.insert(entry.name.clone(), entry.value.expose_secret().to_string());
            }
        }

        map
    }

    pub fn to_json_bytes(&self) -> Result<Zeroizing<Vec<u8>>, serde_json::Error> {
        let vec = serde_json::to_vec(self)?;
        Ok(Zeroizing::new(vec))
    }

    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn validate_secret_name(name: &str) -> Result<String, String> {
    let normalized = name.trim().to_string();
    if normalized.is_empty() {
        return Err("Secret name cannot be empty".to_string());
    }
    if normalized.contains('=') {
        return Err(format!(
            "Invalid secret name '{normalized}': '=' is not allowed (breaks .env format)"
        ));
    }
    if normalized.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!(
            "Invalid secret name '{normalized}': whitespace and control characters are not allowed"
        ));
    }
    Ok(normalized)
}
