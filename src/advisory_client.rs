// Minimal advisory client for future API integration
// Most functionality moved to database_updater.rs for better organization

use serde::{Deserialize, Serialize};

// OSV API structures (kept for database_updater.rs)
#[derive(Debug, Serialize, Deserialize)]
pub struct OSVQuery {
    pub package: OSVPackage,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OSVPackage {
    pub ecosystem: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct OSVVulnerability {
    pub id: String,
    pub summary: String,
    pub details: Option<String>,
    pub affected: Vec<OSVAffected>,
    pub severity: Option<Vec<OSVSeverity>>,
    pub references: Option<Vec<OSVReference>>,
    pub published: Option<String>,
    pub modified: String,
    pub aliases: Option<Vec<String>>, // CVE IDs, GHSA IDs, etc.
}

#[derive(Debug, Deserialize)]
pub struct OSVAffected {
    pub package: OSVPackage,
    pub ranges: Option<Vec<OSVRange>>,
    pub versions: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct OSVRange {
    pub events: Vec<OSVEvent>,
}

#[derive(Debug, Deserialize)]
pub struct OSVEvent {
    pub introduced: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OSVSeverity {
    pub score: String,
    #[serde(rename = "type")]
    pub severity_type: String,
}

#[derive(Debug, Deserialize)]
pub struct OSVReference {
    pub url: String,
}

// GitHub Advisory Database structures
#[derive(Debug, Deserialize)]
pub struct GitHubAdvisory {
    #[allow(dead_code)]
    pub schema_version: String,
    pub id: String, // GHSA-xxxx-xxxx-xxxx
    pub modified: String,
    pub published: Option<String>,
    #[allow(dead_code)]
    pub withdrawn: Option<String>,
    pub aliases: Option<Vec<String>>, // CVE IDs, etc.
    pub summary: String,
    pub details: String,
    pub severity: Option<Vec<GitHubSeverity>>,
    pub affected: Vec<GitHubAffected>,
    pub references: Option<Vec<GitHubReference>>,
    pub database_specific: Option<GitHubDatabaseSpecific>,
}

#[derive(Debug, Deserialize)]
pub struct GitHubSeverity {
    #[serde(rename = "type")]
    pub severity_type: String, // CVSS_V3, etc.
    pub score: String,
}

#[derive(Debug, Deserialize)]
pub struct GitHubAffected {
    pub package: GitHubPackage,
    pub ranges: Option<Vec<GitHubRange>>,
    pub versions: Option<Vec<String>>,
    #[allow(dead_code)]
    pub ecosystem_specific: Option<serde_json::Value>,
    #[allow(dead_code)]
    pub database_specific: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct GitHubPackage {
    pub ecosystem: String,
    pub name: String,
    #[allow(dead_code)]
    pub purl: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GitHubRange {
    #[serde(rename = "type")]
    #[allow(dead_code)]
    pub range_type: String, // ECOSYSTEM, SEMVER, etc.
    pub events: Vec<GitHubRangeEvent>,
}

#[derive(Debug, Deserialize)]
pub struct GitHubRangeEvent {
    pub introduced: Option<String>,
    #[allow(dead_code)]
    pub fixed: Option<String>,
    #[allow(dead_code)]
    pub last_affected: Option<String>,
    #[allow(dead_code)]
    pub limit: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GitHubReference {
    #[serde(rename = "type")]
    #[allow(dead_code)]
    pub ref_type: String, // WEB, ADVISORY, etc.
    pub url: String,
}

#[derive(Debug, Deserialize)]
pub struct GitHubDatabaseSpecific {
    pub cwe_ids: Option<Vec<String>>,
    pub severity: Option<String>, // LOW, MODERATE, HIGH, CRITICAL
    pub github_reviewed: Option<bool>,
    pub github_reviewed_at: Option<String>,
    pub nvd_published_at: Option<String>,
    #[allow(dead_code)]
    pub last_known_affected_version_range: Option<String>,
}
