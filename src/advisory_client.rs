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
