use crate::security::SecretString;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
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

/// Blank and "global" (any case) both mean the global scope.
pub fn normalize_project(project: Option<&str>) -> Option<String> {
    match project.map(str::trim) {
        None | Some("") => None,
        Some(p) if p.eq_ignore_ascii_case("global") => None,
        Some(p) => Some(p.to_string()),
    }
}

pub fn normalize_tags<I: IntoIterator<Item = String>>(tags: I) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for t in tags {
        let t = t.trim();
        if !t.is_empty() && !out.iter().any(|o| o.eq_ignore_ascii_case(t)) {
            out.push(t.to_string());
        }
    }
    out
}

pub fn same_project(a: Option<&str>, b: Option<&str>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => x.eq_ignore_ascii_case(y),
        _ => false,
    }
}

fn normalize_description(description: Option<String>) -> Option<String> {
    description
        .map(|d| d.trim().to_string())
        .filter(|d| !d.is_empty())
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
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.trim().to_string(),
            project: normalize_project(project.as_deref()),
            value,
            tags: normalize_tags(tags),
            description: normalize_description(description),
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

    pub fn in_scope(&self, project: Option<&str>) -> bool {
        same_project(self.project.as_deref(), project)
    }

    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t.eq_ignore_ascii_case(tag))
    }

    pub fn touch(&mut self) {
        self.updated_at = current_timestamp();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupError {
    NotFound { name: String, scope: Option<String> },
    Ambiguous { name: String, projects: Vec<String> },
}

impl fmt::Display for LookupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound { name, scope: None } => write!(f, "Secret '{name}' not found"),
            Self::NotFound {
                name,
                scope: Some(scope),
            } => write!(f, "Secret '{name}' not found in scope '{scope}'"),
            Self::Ambiguous { name, projects } => write!(
                f,
                "Secret '{name}' exists in several projects ({}); pass --project to pick one",
                projects.join(", ")
            ),
        }
    }
}

impl std::error::Error for LookupError {}

/// A pointer to a secret, written as `apiman://NAME` or `apiman://PROJECT/NAME`.
/// References can live in committed files and shell environments because they
/// carry no secret material; `apiman run` swaps them for real values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRef {
    pub project: Option<String>,
    pub name: String,
}

pub const REF_PREFIX: &str = "apiman://";

impl SecretRef {
    pub fn parse(value: &str) -> Option<Self> {
        let rest = value.trim().strip_prefix(REF_PREFIX)?;
        let (project, name) = match rest.rsplit_once('/') {
            Some((p, n)) => (normalize_project(Some(p)), n),
            None => (None, rest),
        };
        let name = name.trim();
        if name.is_empty() {
            return None;
        }
        Some(Self {
            project,
            name: name.to_string(),
        })
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.project {
            Some(p) => write!(f, "{REF_PREFIX}{p}/{}", self.name),
            None => write!(f, "{REF_PREFIX}{}", self.name),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Vault {
    pub version: u32,
    pub entries: Vec<SecretEntry>,
    /// Kept inside the encrypted vault so routes (which decide where a key may
    /// be sent) cannot be redirected by editing a plaintext file.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proxy_routes: Vec<crate::proxy::ProxyRoute>,
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
            proxy_routes: Vec::new(),
        }
    }

    /// Insert or update the entry with this exact name in this scope (scope
    /// names compare case-insensitively). Empty `tags` and `None` description
    /// keep the existing values on update.
    pub fn set(
        &mut self,
        name: String,
        value: SecretString,
        project: Option<String>,
        tags: Vec<String>,
        description: Option<String>,
    ) -> &SecretEntry {
        let name = name.trim().to_string();
        let project = normalize_project(project.as_deref());

        if let Some(pos) = self.position_exact(&name, project.as_deref()) {
            let entry = &mut self.entries[pos];
            entry.value = value;
            if !tags.is_empty() {
                entry.tags = normalize_tags(tags);
            }
            if description.is_some() {
                entry.description = normalize_description(description);
            }
            entry.touch();
            &self.entries[pos]
        } else {
            self.entries
                .push(SecretEntry::new(name, value, project, tags, description));
            self.entries.last().unwrap()
        }
    }

    pub fn position_exact(&self, name: &str, project: Option<&str>) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| e.name == name && e.in_scope(project))
    }

    pub fn find_exact(&self, name: &str, project: Option<&str>) -> Option<&SecretEntry> {
        self.position_exact(name, project).map(|i| &self.entries[i])
    }

    pub fn find_by_id(&self, id: &str) -> Option<&SecretEntry> {
        self.entries.iter().find(|e| e.id == id)
    }

    /// Entry `name` in exactly one scope (`None` = global). Exact-case names win
    /// over case-insensitive matches.
    pub fn find_in_scope(&self, name: &str, project: Option<&str>) -> Option<&SecretEntry> {
        let name = name.trim();
        self.find_exact(name, project).or_else(|| {
            self.entries
                .iter()
                .find(|e| e.in_scope(project) && e.name.eq_ignore_ascii_case(name))
        })
    }

    /// Resolve a name the way users expect from `get`, `copy`, and references:
    /// - explicit project: that project first, then global (like `run`);
    /// - explicit "global": global only;
    /// - no project: global first, then the single project that has it.
    ///
    /// A name living in several projects is an error rather than a guess.
    pub fn resolve(&self, name: &str, project: Option<&str>) -> Result<&SecretEntry, LookupError> {
        let name = name.trim();
        let explicit_global = project
            .map(|p| p.trim().eq_ignore_ascii_case("global"))
            .unwrap_or(false);
        let scope = normalize_project(project);

        if let Some(p) = scope.as_deref() {
            return self
                .find_in_scope(name, Some(p))
                .or_else(|| self.find_in_scope(name, None))
                .ok_or_else(|| LookupError::NotFound {
                    name: name.to_string(),
                    scope: Some(p.to_string()),
                });
        }

        if let Some(e) = self.find_in_scope(name, None) {
            return Ok(e);
        }
        if explicit_global {
            return Err(LookupError::NotFound {
                name: name.to_string(),
                scope: Some("global".to_string()),
            });
        }

        let exact: Vec<&SecretEntry> = self.entries.iter().filter(|e| e.name == name).collect();
        let candidates = if exact.is_empty() {
            self.entries
                .iter()
                .filter(|e| e.name.eq_ignore_ascii_case(name))
                .collect()
        } else {
            exact
        };
        match candidates.len() {
            0 => Err(LookupError::NotFound {
                name: name.to_string(),
                scope: None,
            }),
            1 => Ok(candidates[0]),
            _ => {
                let mut projects: Vec<String> = candidates
                    .iter()
                    .map(|e| e.project_display().to_string())
                    .collect();
                projects.sort();
                projects.dedup();
                Err(LookupError::Ambiguous {
                    name: name.to_string(),
                    projects,
                })
            }
        }
    }

    pub fn get(&self, name: &str, target_project: Option<&str>) -> Option<&SecretEntry> {
        self.resolve(name, target_project).ok()
    }

    pub fn resolve_ref(&self, reference: &SecretRef) -> Result<&SecretEntry, LookupError> {
        self.resolve(&reference.name, reference.project.as_deref())
    }

    pub fn has_project(&self, project: &str) -> bool {
        self.entries.iter().any(|e| {
            e.project
                .as_deref()
                .is_some_and(|p| p.eq_ignore_ascii_case(project.trim()))
        })
    }

    pub fn projects(&self) -> Vec<String> {
        let mut projects: Vec<String> = Vec::new();
        for p in self.entries.iter().filter_map(|e| e.project.as_deref()) {
            if !projects.iter().any(|x| x.eq_ignore_ascii_case(p)) {
                projects.push(p.to_string());
            }
        }
        projects.sort_by_key(|p| p.to_lowercase());
        projects
    }

    /// `project_filter`: None/"all" = everything, "global" = global only,
    /// otherwise that project plus the globals it inherits.
    pub fn list(
        &self,
        project_filter: Option<&str>,
        tag_filter: Option<&str>,
    ) -> Vec<&SecretEntry> {
        let tag = tag_filter.map(str::trim).filter(|t| !t.is_empty());
        let project = project_filter
            .map(str::trim)
            .filter(|p| !p.is_empty() && !p.eq_ignore_ascii_case("all"));
        self.entries
            .iter()
            .filter(|e| match project {
                None => true,
                Some(p) if p.eq_ignore_ascii_case("global") => e.is_global(),
                Some(p) => e.is_global() || e.in_scope(Some(p)),
            })
            .filter(|e| tag.is_none_or(|t| e.has_tag(t)))
            .collect()
    }

    /// Environment for `run`/`export`: globals, overlaid by the project's own
    /// entries. Keys are sorted so output is deterministic.
    pub fn resolve_env_map(
        &self,
        project: Option<&str>,
        tag_filter: Option<&str>,
    ) -> BTreeMap<String, Zeroizing<String>> {
        let tag = tag_filter.map(str::trim).filter(|t| !t.is_empty());
        let project = normalize_project(project);
        let mut map = BTreeMap::new();
        let matches_tag = |e: &SecretEntry| tag.is_none_or(|t| e.has_tag(t));

        for entry in self
            .entries
            .iter()
            .filter(|e| e.is_global() && matches_tag(e))
        {
            map.insert(
                entry.name.clone(),
                Zeroizing::new(entry.value.expose_secret().to_string()),
            );
        }
        if let Some(p) = project.as_deref() {
            for entry in self
                .entries
                .iter()
                .filter(|e| !e.is_global() && e.in_scope(Some(p)) && matches_tag(e))
            {
                map.insert(
                    entry.name.clone(),
                    Zeroizing::new(entry.value.expose_secret().to_string()),
                );
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

pub fn current_timestamp() -> u64 {
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
    if normalized
        .chars()
        .any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(format!(
            "Invalid secret name '{normalized}': whitespace and control characters are not allowed"
        ));
    }
    if normalized.starts_with(REF_PREFIX) || normalized.contains('/') {
        return Err(format!(
            "Invalid secret name '{normalized}': '/' is not allowed"
        ));
    }
    Ok(normalized)
}

pub fn validate_project_name(project: &str) -> Result<(), String> {
    if project.contains('/') || project.chars().any(char::is_control) {
        return Err(format!(
            "Invalid project name '{project}': '/' and control characters are not allowed"
        ));
    }
    Ok(())
}
