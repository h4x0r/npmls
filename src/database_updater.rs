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
}

// Re-use OSVVulnerability from advisory_client
use crate::advisory_client::OSVVulnerability;

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
        print!("{} ", "🔄 Updating vulnerability database...".bright_blue());

        // Always try bulk download - no fallback to legacy method
        let database = self.download_complete_osv_database().await?;
        println!("✅ Complete");
        Ok(database)
    }

    #[allow(clippy::future_not_send)]
    pub async fn update_database_force(&self) -> Result<VulnerabilityDatabase> {
        print!(
            "{} ",
            "🔄 Updating vulnerability database (forced)...".bright_blue()
        );

        // Force update - always download complete database
        let database = self.download_complete_osv_database().await?;
        println!("✅ Complete");
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
        print!("📦 {size_mb:.1}MB ");

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
                .map_or(false, |ext| ext.eq_ignore_ascii_case("json"))
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

        print!("({processed_count} vulns) ");

        let database = VulnerabilityDatabase {
            last_updated: Utc::now(),
            version: "2.0.0".to_string(), // New version for bulk downloads
            packages: all_packages,
            total_vulnerabilities,
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
        } else {
            ThreatType::Backdoor
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
        let database: VulnerabilityDatabase = serde_json::from_str(&json_data)?;

        // Check if database is recent (less than 1 hour old)
        let age = Utc::now().signed_duration_since(database.last_updated);
        if age.num_hours() > 1 {
            print!(
                "⏰ Cached database is {}h old, consider updating ",
                age.num_hours()
            );
        }

        Ok(Some(database))
    }
}
