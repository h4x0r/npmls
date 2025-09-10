use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaliciousPackage {
    pub name: String,
    pub version: String,
    pub discovered: DateTime<Utc>,
    pub threat_type: ThreatType,
    pub description: String,
    pub severity: Severity,
    pub references: Vec<String>,
    // New GitHub Advisory Database fields
    #[serde(default)]
    pub cwe_ids: Vec<String>,
    #[serde(default)]
    pub github_reviewed: Option<bool>,
    #[serde(default)]
    pub github_reviewed_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub nvd_published_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub cvss_score: Option<f32>,
    #[serde(default)]
    pub cvss_vector: Option<String>,
    #[serde(default = "default_source_database")]
    pub source_database: VulnerabilitySource,
    #[serde(default)]
    pub aliases: Vec<String>, // CVE IDs, other identifiers
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ThreatType {
    SupplyChainAttack,
    Cryptojacking,
    CredentialTheft,
    Backdoor,
    DataExfiltration,
    Ransomware,
    CrossSiteScripting,
    SqlInjection,
    RemoteCodeExecution,
    DenialOfService,
    PrivilegeEscalation,
    BufferOverflow,
    Other,
    // For backward compatibility with unknown variants
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VulnerabilitySource {
    OSV,
    GitHub,
    BuiltIn,
    Combined, // When data is merged from multiple sources
    #[serde(other)]
    Unknown, // For backward compatibility
}

fn default_source_database() -> VulnerabilitySource {
    VulnerabilitySource::BuiltIn
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageInfo {
    pub name: String,
    pub version: String,
    pub path: String,
    pub size_bytes: u64,
    pub modified: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub package: PackageInfo,
    pub threat: Option<MaliciousPackage>,
    pub is_malicious: bool,
}

#[derive(Debug)]
pub struct ThreatDatabase {
    malicious_packages: HashMap<String, Vec<MaliciousPackage>>,
    online_mode: bool,
}

impl ThreatDatabase {
    pub fn new() -> Self {
        Self::new_with_options(true)
    }

    pub fn new_offline() -> Self {
        Self::new_with_options(false)
    }

    pub fn new_with_options(online_mode: bool) -> Self {
        let mut db = Self {
            malicious_packages: HashMap::new(),
            online_mode,
        };

        // Always load static database as fallback
        db.load_september_2025_attack();
        db.load_nx_attack();
        db.load_historical_threats();

        db
    }

    pub async fn load_or_update_database(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.online_mode {
            return Ok(());
        }

        use crate::database_updater::DatabaseUpdater;

        let updater = DatabaseUpdater::new()?;

        // Try to load existing cached database
        match updater.load_database().await {
            Ok(Some(cached_db)) => {
                // Check if database is stale (older than 1 hour)
                let age = chrono::Utc::now().signed_duration_since(cached_db.last_updated);

                if age.num_hours() > 1 {
                    print!(
                        "🔄 Cached database is {}h old, updating... ",
                        age.num_hours()
                    );
                    self.update_database_with_progress(&updater).await?;
                } else {
                    self.merge_cached_database(cached_db.clone());
                    let total_threats = self.get_all_malicious_packages().len();
                    if cached_db.total_vulnerabilities > 0 {
                        print!(
                            "📥 Loaded {} vulnerabilities from cache ({}h old) ",
                            cached_db.total_vulnerabilities,
                            age.num_hours()
                        );
                    } else {
                        print!(
                            "📥 Cache is up to date ({}h old), using {} built-in threats ",
                            age.num_hours(),
                            total_threats
                        );
                    }
                }
            }
            Ok(None) => {
                // No cached database, download fresh data
                print!("📥 No cached database found, downloading... ");
                self.update_database_with_progress(&updater).await?;
            }
            Err(_) => {
                // Error loading cache, try to update
                print!("⚠️  Error loading cached database, downloading fresh data... ");
                self.update_database_with_progress(&updater).await?;
            }
        }

        Ok(())
    }

    async fn update_database_with_progress(
        &mut self,
        updater: &crate::database_updater::DatabaseUpdater,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Download complete vulnerability database
        let database = updater.update_database(&[]).await?;
        self.merge_cached_database(database);
        Ok(())
    }

    fn merge_cached_database(&mut self, cached_db: crate::database_updater::VulnerabilityDatabase) {
        for (package_name, vulns) in cached_db.packages {
            let entry = self.malicious_packages.entry(package_name).or_default();
            for vuln in vulns {
                // Avoid duplicates
                if !entry
                    .iter()
                    .any(|existing| existing.version == vuln.version && existing.name == vuln.name)
                {
                    entry.push(vuln);
                }
            }
        }
    }

    fn load_september_2025_attack(&mut self) {
        let qix_attack_date = DateTime::parse_from_rfc3339("2025-09-08T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let malicious_packages = vec![
            ("ansi-regex", "6.2.1"),
            ("ansi-styles", "6.2.2"),
            ("backslash", "0.2.1"),
            ("chalk", "5.6.1"),
            ("chalk-template", "1.1.1"),
            ("color", "5.0.1"),
            ("color-convert", "3.1.1"),
            ("color-name", "2.0.1"),
            ("color-string", "2.1.1"),
            ("debug", "4.4.2"),
            ("error-ex", "1.3.3"),
            ("has-ansi", "6.0.1"),
            ("is-arrayish", "0.3.3"),
            ("simple-swizzle", "0.2.3"),
            ("slice-ansi", "7.1.1"),
            ("strip-ansi", "7.1.1"),
            ("supports-color", "10.2.1"),
            ("supports-hyperlinks", "4.1.1"),
            ("wrap-ansi", "9.0.1"),
        ];

        for (name, version) in malicious_packages {
            let package = MaliciousPackage {
                name: name.to_string(),
                version: version.to_string(),
                discovered: qix_attack_date,
                threat_type: ThreatType::SupplyChainAttack,
                description: "Compromised in September 2025 Qix phishing attack. Contains crypto wallet hijacking malware that intercepts blockchain transactions and redirects funds to attacker-controlled addresses.".to_string(),
                severity: Severity::Critical,
                references: vec![
                    "https://socket.dev/blog/npm-author-qix-compromised-in-major-supply-chain-attack".to_string(),
                    "https://github.com/chalk/chalk/issues/656".to_string(),
                    "https://github.com/debug-js/debug/issues/1005".to_string(),
                ],
                cwe_ids: vec!["CWE-506".to_string()], // Embedded Malicious Code
                github_reviewed: None,
                github_reviewed_at: None,
                nvd_published_at: None,
                cvss_score: Some(9.8),
                cvss_vector: None,
                source_database: VulnerabilitySource::BuiltIn,
                aliases: vec![],
            };

            self.malicious_packages
                .entry(name.to_string())
                .or_default()
                .push(package);
        }
    }

    fn load_nx_attack(&mut self) {
        let nx_attack_date = DateTime::parse_from_rfc3339("2025-08-26T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let nx_packages = vec![
            ("@nx/nx-darwin-arm64", "19.6.0"),
            ("@nx/nx-darwin-x64", "19.6.0"),
            ("@nx/nx-linux-arm64-gnu", "19.6.0"),
            ("@nx/nx-linux-arm64-musl", "19.6.0"),
            ("@nx/nx-linux-x64-gnu", "19.6.0"),
            ("@nx/nx-linux-x64-musl", "19.6.0"),
            ("@nx/nx-win32-arm64-msvc", "19.6.0"),
            ("@nx/nx-win32-x64-msvc", "19.6.0"),
        ];

        for (name, version) in nx_packages {
            let package = MaliciousPackage {
                name: name.to_string(),
                version: version.to_string(),
                discovered: nx_attack_date,
                threat_type: ThreatType::CredentialTheft,
                description: "Compromised Nx packages containing malware that scans for and exfiltrates developer credentials, SSH keys, and other sensitive data from development environments.".to_string(),
                severity: Severity::Critical,
                references: vec![
                    "https://socket.dev/blog/nx-packages-compromised".to_string(),
                ],
                cwe_ids: vec!["CWE-522".to_string()], // Insufficiently Protected Credentials
                github_reviewed: None,
                github_reviewed_at: None,
                nvd_published_at: None,
                cvss_score: Some(9.1),
                cvss_vector: None,
                source_database: VulnerabilitySource::BuiltIn,
                aliases: vec![],
            };

            self.malicious_packages
                .entry(name.to_string())
                .or_default()
                .push(package);
        }
    }

    fn load_historical_threats(&mut self) {
        // Add other known malicious packages from recent history
        let historical_threats = vec![
            (
                "event-stream",
                "3.3.6",
                "2018-11-26T00:00:00Z",
                ThreatType::Backdoor,
                "Contained malicious code targeting Copay Bitcoin wallets",
            ),
            (
                "eslint-scope",
                "3.7.2",
                "2018-07-12T00:00:00Z",
                ThreatType::CredentialTheft,
                "Harvested npm credentials from developers' machines",
            ),
            (
                "crossenv",
                "7.0.3",
                "2017-05-02T00:00:00Z",
                ThreatType::DataExfiltration,
                "Typosquatting attack that stole environment variables",
            ),
            (
                "flatmap-stream",
                "0.1.1",
                "2018-11-26T00:00:00Z",
                ThreatType::Backdoor,
                "Part of the event-stream attack chain",
            ),
        ];

        for (name, version, date, threat_type, description) in historical_threats {
            let discovered = DateTime::parse_from_rfc3339(date)
                .unwrap()
                .with_timezone(&Utc);

            let package = MaliciousPackage {
                name: name.to_string(),
                version: version.to_string(),
                discovered,
                threat_type,
                description: description.to_string(),
                severity: Severity::High,
                references: vec![],
                cwe_ids: vec![],
                github_reviewed: None,
                github_reviewed_at: None,
                nvd_published_at: None,
                cvss_score: None,
                cvss_vector: None,
                source_database: VulnerabilitySource::BuiltIn,
                aliases: vec![],
            };

            self.malicious_packages
                .entry(name.to_string())
                .or_default()
                .push(package);
        }
    }

    // Fast read-only check optimized for bulk scanning (no API calls, no mutations)
    pub fn check_package_fast(&self, name: &str, version: &str) -> Option<MaliciousPackage> {
        if let Some(packages) = self.malicious_packages.get(name) {
            packages.iter().find(|pkg| pkg.version == version).cloned()
        } else {
            None
        }
    }

    pub fn get_all_malicious_packages(&self) -> Vec<&MaliciousPackage> {
        self.malicious_packages.values().flatten().collect()
    }
}
