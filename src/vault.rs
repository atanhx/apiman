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
        let normalized_project = match project.as_deref() {
            None | Some("") | Some("global") => None,
            Some(p) => Some(p.trim().to_string()),
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
        let normalized_project = match project.as_deref() {
            None | Some("") | Some("global") => None,
            Some(p) => Some(p.trim().to_string()),
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

        if let Some(p) = target_project {
            if let Some(entry) = self.entries.iter().find(|e| {
                e.name == normalized_name && e.project.as_deref() == Some(p)
            }) {
                return Some(entry);
            }
        }

        self.entries.iter().find(|e| {
            e.name == normalized_name && e.is_global()
        })
    }

    pub fn get_exact(&self, name: &str, project: Option<&str>) -> Option<&SecretEntry> {
        let normalized_name = name.trim();
        let normalized_project = match project.map(str::trim) {
            None | Some("") | Some("global") => None,
            Some(p) => Some(p),
        };

        self.entries.iter().find(|e| {
            e.name == normalized_name && e.project.as_deref() == normalized_project
        })
    }

    pub fn delete(&mut self, name: &str, project: Option<&str>) -> bool {
        let normalized_name = name.trim();
        let normalized_project = match project.map(str::trim) {
            None | Some("") | Some("global") => None,
            Some(p) => Some(p),
        };

        if let Some(pos) = self.entries.iter().position(|e| {
            e.name == normalized_name && e.project.as_deref() == normalized_project
        }) {
            self.entries.remove(pos);
            true
        } else {
            false
        }
    }

    pub fn list(&self, project_filter: Option<&str>, tag_filter: Option<&str>) -> Vec<&SecretEntry> {
        self.entries
            .iter()
            .filter(|e| {
                if let Some(p) = project_filter {
                    let p_clean = p.trim();
                    if p_clean != "all" {
                        if p_clean == "global" {
                            if !e.is_global() {
                                return false;
                            }
                        } else if e.project.as_deref() != Some(p_clean) && !e.is_global() {
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

        // 2. Overlay project entries
        if let Some(proj) = project.map(str::trim).filter(|p| !p.is_empty() && *p != "global") {
            for entry in self.entries.iter().filter(|e| e.project.as_deref() == Some(proj)) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_crud_and_scoping() {
        let mut vault = Vault::new();

        vault.set(
            "API_KEY".to_string(),
            SecretString::new("global-key"),
            None,
            vec!["core".to_string()],
            None,
        );

        vault.set(
            "API_KEY".to_string(),
            SecretString::new("proj-key"),
            Some("ecommerce".to_string()),
            vec!["payment".to_string()],
            None,
        );

        // When queried without project, get global
        let global_res = vault.get("API_KEY", None).unwrap();
        assert_eq!(global_res.value.expose_secret(), "global-key");

        // When queried with project, get project-specific
        let proj_res = vault.get("API_KEY", Some("ecommerce")).unwrap();
        assert_eq!(proj_res.value.expose_secret(), "proj-key");

        // When queried with non-matching project, fallback to global
        let fallback_res = vault.get("API_KEY", Some("analytics")).unwrap();
        assert_eq!(fallback_res.value.expose_secret(), "global-key");

        // Resolve env map
        let env_map = vault.resolve_env_map(Some("ecommerce"), None);
        assert_eq!(env_map.get("API_KEY").unwrap(), "proj-key");

        // Delete project entry
        assert!(vault.delete("API_KEY", Some("ecommerce")));
        let after_del = vault.get("API_KEY", Some("ecommerce")).unwrap();
        assert_eq!(after_del.value.expose_secret(), "global-key");
    }
}
