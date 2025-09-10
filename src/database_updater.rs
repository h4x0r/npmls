use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use colored::Colorize;
use futures::stream::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tokio::time::{timeout, Duration};

use crate::threats::{MaliciousPackage, Severity, ThreatType};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityDatabase {
    pub last_updated: DateTime<Utc>,
    pub version: String,
    pub packages: HashMap<String, Vec<MaliciousPackage>>,
    pub total_vulnerabilities: usize,
    #[serde(default)]
    pub osv_vulnerabilities: usize,
    #[serde(default)]
    pub github_vulnerabilities: usize,
    #[serde(default)]
    pub sources: Vec<String>, // Track which databases were used
}

// Re-use structures from advisory_client
use crate::advisory_client::{GitHubAdvisory, OSVVulnerability};
use crate::threats::VulnerabilitySource;

pub struct DatabaseUpdater {
    client: Client,
    cache_dir: PathBuf,
}

impl DatabaseUpdater {
    pub fn new() -> Result<Self> {
        let cache_dir = dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("npmls");

        fs::create_dir_all(&cache_dir).context("Failed to create cache directory")?;

        let client = Client::builder()
            .user_agent("npmls/0.1.0 (security-scanner)")
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(Self { client, cache_dir })
    }

    #[allow(clippy::future_not_send)]
    pub async fn update_database(
        &self,
        _package_names: &[String],
    ) -> Result<VulnerabilityDatabase> {
        println!("{}", "🔄 Updating vulnerability database...".bright_blue());

        // Download from both OSV and GitHub Advisory databases
        let osv_db = self.download_complete_osv_database().await?;
        let github_db = self.download_github_advisory_database().await?;
        let database = self.merge_databases(osv_db, github_db);
        println!("{}", "✅ Database update complete".bright_green());
        Ok(database)
    }

    #[allow(clippy::future_not_send)]
    pub async fn update_database_force(&self) -> Result<VulnerabilityDatabase> {
        println!(
            "{}",
            "🔄 Force updating vulnerability database...".bright_blue()
        );

        // Force update - download from both databases
        let osv_db = self.download_complete_osv_database().await?;
        let github_db = self.download_github_advisory_database().await?;
        let database = self.merge_databases(osv_db, github_db);
        println!("{}", "✅ Force update complete".bright_green());
        Ok(database)
    }

    #[allow(clippy::future_not_send)]
    async fn download_complete_osv_database(&self) -> Result<VulnerabilityDatabase> {
        let download_url = "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip";

        let response = timeout(
            Duration::from_secs(120), // Allow 2 minutes for large download
            self.client.get(download_url).send(),
        )
        .await
        .context("OSV bulk download timeout")?
        .context("Failed to download OSV bulk database")?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "OSV bulk download failed with status: {}",
                response.status()
            ));
        }

        let content_length = response.content_length().unwrap_or(55_000_000); // ~55MB estimate

        // Set up progress bar for download
        let pb = ProgressBar::new(content_length);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("\r📥 [{bar:20.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                .unwrap()
                .progress_chars("#>-"),
        );

        // Download with progress tracking
        let mut zip_data = Vec::new();
        let mut stream = response.bytes_stream();

        while let Some(chunk) = stream.next().await {
            let chunk = chunk.context("Error reading download stream")?;
            zip_data.extend_from_slice(&chunk);
            pb.set_position(zip_data.len() as u64);
        }

        pb.finish_and_clear();
        #[allow(clippy::cast_precision_loss)]
        let size_mb = zip_data.len() as f64 / 1_000_000.0;
        println!("📦 Downloaded {size_mb:.1}MB from OSV database");

        // Extract and parse vulnerability data with progress bar
        let database = self.parse_osv_zip_data(&zip_data).await?;

        // Save to cache (this was missing!)
        self.save_database(&database).await?;

        Ok(database)
    }

    #[allow(clippy::future_not_send)]
    async fn parse_osv_zip_data(&self, zip_data: &[u8]) -> Result<VulnerabilityDatabase> {
        use std::io::Cursor;

        let cursor = Cursor::new(zip_data);
        let mut archive = zip::ZipArchive::new(cursor)?;

        // Set up progress bar for processing
        let pb = ProgressBar::new(archive.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("\r🔍 [{bar:20.cyan/blue}] {pos}/{len}")
                .unwrap()
                .progress_chars("#>-"),
        );

        let mut all_packages: HashMap<String, Vec<MaliciousPackage>> = HashMap::new();
        let mut processed_count = 0;

        for i in 0..archive.len() {
            let file = archive.by_index(i)?;

            // Only process JSON files
            if std::path::Path::new(file.name())
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
            {
                if let Ok(vulnerability) = serde_json::from_reader::<_, OSVVulnerability>(file) {
                    // Extract npm packages from this vulnerability
                    for affected in &vulnerability.affected {
                        if affected.package.ecosystem == "npm" {
                            let package_name = &affected.package.name;

                            let malicious_package =
                                self.osv_to_malicious_package(&vulnerability, package_name);
                            let entry = all_packages.entry(package_name.clone()).or_default();
                            entry.push(malicious_package);
                            processed_count += 1;
                        }
                    }
                }
                // Skip malformed JSON files silently
            }

            pb.set_position((i + 1) as u64);

            // Small async yield every 1000 files to prevent blocking
            if i % 1000 == 0 {
                tokio::task::yield_now().await;
            }
        }

        pb.finish_and_clear();

        let total_vulnerabilities = all_packages.values().map(Vec::len).sum();

        println!("🔍 Processed {processed_count} OSV vulnerabilities");

        let database = VulnerabilityDatabase {
            last_updated: Utc::now(),
            version: "3.0.0".to_string(), // Updated for combined OSV+GitHub data
            packages: all_packages,
            total_vulnerabilities,
            osv_vulnerabilities: processed_count,
            github_vulnerabilities: 0, // This will be updated when merged
            sources: vec!["OSV".to_string()],
        };

        Ok(database)
    }

    fn osv_to_malicious_package(
        &self,
        vuln: &OSVVulnerability,
        package_name: &str,
    ) -> MaliciousPackage {
        let discovered = Self::parse_osv_date(&vuln.modified)
            .or_else(|| {
                vuln.published
                    .as_ref()
                    .and_then(|p| Self::parse_osv_date(p))
            })
            .unwrap_or_else(Utc::now);

        let severity = Self::determine_severity(vuln);
        let threat_type = Self::determine_threat_type(vuln);

        let description = vuln
            .details
            .clone()
            .or_else(|| Some(vuln.summary.clone()))
            .unwrap_or_else(|| "Security vulnerability detected".to_string());

        let references = vuln
            .references
            .as_ref()
            .map(|refs| refs.iter().map(|r| r.url.clone()).collect())
            .unwrap_or_default();

        // Extract version from affected ranges (simplified)
        let version =
            Self::extract_version_from_vuln(vuln).unwrap_or_else(|| "unknown".to_string());

        MaliciousPackage {
            name: package_name.to_string(),
            version,
            discovered,
            threat_type,
            description: format!("[{}] {description}", vuln.id),
            severity,
            references,
            cwe_ids: vec![], // OSV doesn't typically include CWE IDs
            github_reviewed: None,
            github_reviewed_at: None,
            nvd_published_at: None,
            cvss_score: Self::extract_cvss_score(vuln),
            cvss_vector: Self::extract_cvss_vector(vuln),
            source_database: VulnerabilitySource::OSV,
            aliases: vuln.aliases.clone().unwrap_or_default(),
        }
    }

    fn extract_version_from_vuln(vuln: &OSVVulnerability) -> Option<String> {
        for affected in &vuln.affected {
            if let Some(versions) = &affected.versions {
                if let Some(version) = versions.first() {
                    return Some(version.clone());
                }
            }

            if let Some(ranges) = &affected.ranges {
                for range in ranges {
                    for event in &range.events {
                        if let Some(introduced) = &event.introduced {
                            if introduced != "0" {
                                return Some(introduced.clone());
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn parse_osv_date(date_str: &str) -> Option<DateTime<Utc>> {
        DateTime::parse_from_rfc3339(date_str)
            .map(|dt| dt.with_timezone(&Utc))
            .ok()
    }

    fn determine_severity(vuln: &OSVVulnerability) -> Severity {
        if let Some(severity_list) = &vuln.severity {
            for sev in severity_list {
                if sev.severity_type == "CVSS_V3" {
                    if let Ok(score) = sev.score.parse::<f32>() {
                        return match score {
                            s if s >= 9.0 => Severity::Critical,
                            s if s >= 7.0 => Severity::High,
                            s if s >= 4.0 => Severity::Medium,
                            _ => Severity::Low,
                        };
                    }
                }
            }
        }

        // Check for keywords in summary/description
        let text =
            format!("{} {}", vuln.summary, vuln.details.as_deref().unwrap_or("")).to_lowercase();

        if text.contains("critical") || text.contains("rce") {
            Severity::Critical
        } else if text.contains("high") || text.contains("sql injection") {
            Severity::High
        } else if text.contains("medium") {
            Severity::Medium
        } else {
            Severity::Low
        }
    }

    fn determine_threat_type(vuln: &OSVVulnerability) -> ThreatType {
        let text =
            format!("{} {}", vuln.summary, vuln.details.as_deref().unwrap_or("")).to_lowercase();

        if text.contains("supply chain") || text.contains("malicious package") {
            ThreatType::SupplyChainAttack
        } else if text.contains("credential") || text.contains("token") {
            ThreatType::CredentialTheft
        } else if text.contains("crypto") || text.contains("mining") {
            ThreatType::Cryptojacking
        } else if text.contains("data") && text.contains("exfilt") {
            ThreatType::DataExfiltration
        } else if text.contains("ransomware") {
            ThreatType::Ransomware
        } else if text.contains("xss") || text.contains("cross-site scripting") {
            ThreatType::CrossSiteScripting
        } else if text.contains("sql injection") || text.contains("sqli") {
            ThreatType::SqlInjection
        } else if text.contains("rce") || text.contains("remote code execution") {
            ThreatType::RemoteCodeExecution
        } else if text.contains("dos") || text.contains("denial of service") {
            ThreatType::DenialOfService
        } else if text.contains("privilege escalation") || text.contains("privilege elevation") {
            ThreatType::PrivilegeEscalation
        } else if text.contains("buffer overflow") || text.contains("buffer overrun") {
            ThreatType::BufferOverflow
        } else {
            ThreatType::Other
        }
    }

    fn extract_cvss_score(vuln: &OSVVulnerability) -> Option<f32> {
        if let Some(severity_list) = &vuln.severity {
            for sev in severity_list {
                if sev.severity_type == "CVSS_V3" || sev.severity_type == "CVSS_V2" {
                    if let Ok(score) = sev.score.parse::<f32>() {
                        return Some(score);
                    }
                }
            }
        }
        None
    }

    fn extract_cvss_vector(vuln: &OSVVulnerability) -> Option<String> {
        if let Some(severity_list) = &vuln.severity {
            for sev in severity_list {
                if sev.severity_type == "CVSS_V3" || sev.severity_type == "CVSS_V2" {
                    // CVSS vector is typically in the score field for some formats
                    if sev.score.starts_with("CVSS:") {
                        return Some(sev.score.clone());
                    }
                }
            }
        }
        None
    }

    #[allow(clippy::future_not_send)]
    async fn download_github_advisory_database(&self) -> Result<VulnerabilityDatabase> {
        println!(
            "{}",
            "⬇️  Downloading GitHub Advisory Database...".bright_blue()
        );

        let download_url = "https://github.com/github/advisory-database/archive/main.zip";

        let response = timeout(
            Duration::from_secs(120),
            self.client.get(download_url).send(),
        )
        .await
        .context("GitHub Advisory download timeout")?
        .context("Failed to download GitHub Advisory database")?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "GitHub Advisory download failed with status: {}",
                response.status()
            ));
        }

        let zip_data = response.bytes().await?.to_vec();
        println!("🔄 Parsing GitHub Advisory database...");

        let database = self.parse_github_zip_data(&zip_data).await?;

        Ok(database)
    }

    async fn parse_github_zip_data(&self, zip_data: &[u8]) -> Result<VulnerabilityDatabase> {
        use std::io::Cursor;
        use zip::ZipArchive;

        let reader = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(reader)?;
        let mut all_packages: HashMap<String, Vec<MaliciousPackage>> = HashMap::new();
        let mut processed_count = 0;

        // Progress bar for GitHub advisories
        let npm_files: Vec<_> = (0..archive.len())
            .filter_map(|i| {
                if let Ok(file) = archive.by_index(i) {
                    let path = file.name();
                    if path.contains("/advisories/github-reviewed/")
                        && path.ends_with(".json")
                        && path.contains("/npm/")
                    {
                        Some(i)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        let pb = ProgressBar::new(npm_files.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{bar:40.cyan/blue} {pos:>7}/{len:7} GitHub advisories parsed")
                .unwrap()
                .progress_chars("##-"),
        );

        for (idx, &i) in npm_files.iter().enumerate() {
            let file = archive.by_index(i)?;

            if let Ok(advisory) = serde_json::from_reader::<_, GitHubAdvisory>(file) {
                // Extract npm packages from this advisory
                for affected in &advisory.affected {
                    if affected.package.ecosystem == "npm" {
                        let package_name = &affected.package.name;

                        let malicious_package =
                            self.github_to_malicious_package(&advisory, package_name);
                        let entry = all_packages.entry(package_name.clone()).or_default();
                        entry.push(malicious_package);
                        processed_count += 1;
                    }
                }
            }

            pb.set_position((idx + 1) as u64);

            // Small async yield every 100 files to prevent blocking
            if idx % 100 == 0 {
                tokio::task::yield_now().await;
            }
        }

        pb.finish_and_clear();

        println!("🔍 Processed {processed_count} GitHub advisories");

        let database = VulnerabilityDatabase {
            last_updated: Utc::now(),
            version: "3.0.0".to_string(),
            packages: all_packages,
            total_vulnerabilities: processed_count,
            osv_vulnerabilities: 0,
            github_vulnerabilities: processed_count,
            sources: vec!["GitHub".to_string()],
        };

        Ok(database)
    }

    fn github_to_malicious_package(
        &self,
        advisory: &GitHubAdvisory,
        package_name: &str,
    ) -> MaliciousPackage {
        let discovered = Self::parse_osv_date(&advisory.modified)
            .or_else(|| {
                advisory
                    .published
                    .as_ref()
                    .and_then(|p| Self::parse_osv_date(p))
            })
            .unwrap_or_else(Utc::now);

        let severity = Self::determine_github_severity(advisory);
        let threat_type = Self::determine_github_threat_type(advisory);

        let description = if !advisory.details.is_empty() {
            advisory.details.clone()
        } else {
            advisory.summary.clone()
        };

        let references = advisory
            .references
            .as_ref()
            .map(|refs| refs.iter().map(|r| r.url.clone()).collect())
            .unwrap_or_default();

        let version = Self::extract_version_from_github_advisory(advisory)
            .unwrap_or_else(|| "unknown".to_string());

        let (github_reviewed, github_reviewed_at, nvd_published_at, cwe_ids) =
            if let Some(db_specific) = &advisory.database_specific {
                (
                    db_specific.github_reviewed,
                    db_specific
                        .github_reviewed_at
                        .as_ref()
                        .and_then(|s| Self::parse_osv_date(s)),
                    db_specific
                        .nvd_published_at
                        .as_ref()
                        .and_then(|s| Self::parse_osv_date(s)),
                    db_specific.cwe_ids.clone().unwrap_or_default(),
                )
            } else {
                (None, None, None, vec![])
            };

        let (cvss_score, cvss_vector) = Self::extract_github_cvss(advisory);

        MaliciousPackage {
            name: package_name.to_string(),
            version,
            discovered,
            threat_type,
            description: format!("[{}] {}", advisory.id, description),
            severity,
            references,
            cwe_ids,
            github_reviewed,
            github_reviewed_at,
            nvd_published_at,
            cvss_score,
            cvss_vector,
            source_database: VulnerabilitySource::GitHub,
            aliases: advisory.aliases.clone().unwrap_or_default(),
        }
    }

    fn determine_github_severity(advisory: &GitHubAdvisory) -> Severity {
        // First try database_specific severity
        if let Some(db_specific) = &advisory.database_specific {
            if let Some(severity_str) = &db_specific.severity {
                return match severity_str.to_uppercase().as_str() {
                    "CRITICAL" => Severity::Critical,
                    "HIGH" => Severity::High,
                    "MODERATE" => Severity::Medium,
                    "LOW" => Severity::Low,
                    _ => Severity::Medium,
                };
            }
        }

        // Fallback to CVSS score if available
        if let Some(severity_list) = &advisory.severity {
            for sev in severity_list {
                if sev.severity_type == "CVSS_V3" {
                    if let Ok(score) = sev.score.parse::<f32>() {
                        return match score {
                            s if s >= 9.0 => Severity::Critical,
                            s if s >= 7.0 => Severity::High,
                            s if s >= 4.0 => Severity::Medium,
                            _ => Severity::Low,
                        };
                    }
                }
            }
        }

        Severity::Medium // Default
    }

    fn determine_github_threat_type(advisory: &GitHubAdvisory) -> ThreatType {
        let text = format!("{} {}", advisory.summary, advisory.details).to_lowercase();

        if text.contains("supply chain") || text.contains("malicious package") {
            ThreatType::SupplyChainAttack
        } else if text.contains("credential") || text.contains("token") {
            ThreatType::CredentialTheft
        } else if text.contains("crypto") || text.contains("mining") {
            ThreatType::Cryptojacking
        } else if text.contains("xss") || text.contains("cross-site scripting") {
            ThreatType::CrossSiteScripting
        } else if text.contains("sql injection") || text.contains("sqli") {
            ThreatType::SqlInjection
        } else if text.contains("rce") || text.contains("remote code execution") {
            ThreatType::RemoteCodeExecution
        } else if text.contains("dos") || text.contains("denial of service") {
            ThreatType::DenialOfService
        } else if text.contains("privilege escalation") {
            ThreatType::PrivilegeEscalation
        } else if text.contains("buffer overflow") {
            ThreatType::BufferOverflow
        } else {
            ThreatType::Other
        }
    }

    fn extract_version_from_github_advisory(advisory: &GitHubAdvisory) -> Option<String> {
        for affected in &advisory.affected {
            if let Some(versions) = &affected.versions {
                if let Some(version) = versions.first() {
                    return Some(version.clone());
                }
            }

            if let Some(ranges) = &affected.ranges {
                for range in ranges {
                    for event in &range.events {
                        if let Some(introduced) = &event.introduced {
                            if introduced != "0" {
                                return Some(introduced.clone());
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn extract_github_cvss(advisory: &GitHubAdvisory) -> (Option<f32>, Option<String>) {
        if let Some(severity_list) = &advisory.severity {
            for sev in severity_list {
                if sev.severity_type == "CVSS_V3" || sev.severity_type == "CVSS_V2" {
                    let score = sev.score.parse::<f32>().ok();
                    let vector = if sev.score.starts_with("CVSS:") {
                        Some(sev.score.clone())
                    } else {
                        None
                    };
                    return (score, vector);
                }
            }
        }
        (None, None)
    }

    fn merge_databases(
        &self,
        mut osv_db: VulnerabilityDatabase,
        github_db: VulnerabilityDatabase,
    ) -> VulnerabilityDatabase {
        // Merge GitHub packages into OSV database
        for (package_name, github_vulns) in github_db.packages {
            let entry = osv_db.packages.entry(package_name).or_default();

            for github_vuln in github_vulns {
                // Check for duplicates by ID (avoid adding same GHSA twice)
                let is_duplicate = entry.iter().any(|existing| {
                    existing.aliases.iter().any(|alias| {
                        github_vuln.aliases.contains(alias)
                            || existing
                                .description
                                .contains(github_vuln.description.split(']').next().unwrap_or(""))
                    })
                });

                if !is_duplicate {
                    entry.push(github_vuln);
                }
            }
        }

        VulnerabilityDatabase {
            last_updated: Utc::now(),
            version: "3.0.0".to_string(),
            packages: osv_db.packages,
            total_vulnerabilities: osv_db.total_vulnerabilities + github_db.total_vulnerabilities,
            osv_vulnerabilities: osv_db.osv_vulnerabilities,
            github_vulnerabilities: github_db.github_vulnerabilities,
            sources: vec!["OSV".to_string(), "GitHub".to_string()],
        }
    }

    async fn save_database(&self, database: &VulnerabilityDatabase) -> Result<()> {
        let db_path = self.cache_dir.join("vulnerability_db.json");
        let json_data = serde_json::to_string_pretty(database)?;
        fs::write(&db_path, json_data)?;
        Ok(())
    }

    pub async fn load_database(&self) -> Result<Option<VulnerabilityDatabase>> {
        let db_path = self.cache_dir.join("vulnerability_db.json");

        if !db_path.exists() {
            return Ok(None);
        }

        let json_data = fs::read_to_string(&db_path)?;

        // Try to deserialize as current version first
        match serde_json::from_str::<VulnerabilityDatabase>(&json_data) {
            Ok(database) => {
                // Check if it's a compatible version
                if database.version.starts_with("3.") {
                    Ok(Some(database))
                } else {
                    // Incompatible version, delete old cache and force update
                    print!(
                        "🗑️  Removing incompatible cached database (v{}) ",
                        database.version
                    );
                    let _ = fs::remove_file(&db_path);
                    Ok(None)
                }
            }
            Err(_) => {
                // Failed to parse, likely old format - delete and force update
                print!("🗑️  Removing corrupted cached database ");
                let _ = fs::remove_file(&db_path);
                Ok(None)
            }
        }
    }
}
