use anyhow::{Context, Result};
use chrono::Utc;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use serde_json::Value;
use std::fs;
use std::path::Path;

use crate::platform::PlatformScanner;
use crate::threats::{MaliciousPackage, PackageInfo, ScanResult, ThreatDatabase};

pub struct Scanner {
    threat_db: ThreatDatabase,
    verbose: bool,
}

impl Scanner {
    #[allow(clippy::future_not_send)]
    pub async fn new_with_options(verbose: bool, online_mode: bool) -> Result<Self> {
        let mut threat_db = if online_mode {
            ThreatDatabase::new()
        } else {
            ThreatDatabase::new_offline()
        };

        // Load or update database automatically (async)
        if let Err(e) = threat_db.load_or_update_database().await {
            if verbose {
                println!("⚠️  Database update failed: {e}. Using built-in database only.");
            }
        }

        if verbose {
            let mode = if online_mode {
                "online + built-in"
            } else {
                "built-in"
            };
            println!(
                "📊 Loaded {} known malicious package variants ({})",
                threat_db.get_all_malicious_packages().len(),
                mode
            );
        }

        Ok(Self { threat_db, verbose })
    }

    pub async fn scan_system(&self) -> Result<Vec<ScanResult>> {
        println!("🔍 Discovering node_modules directories...");

        let node_modules_paths = PlatformScanner::find_node_modules()
            .await
            .context("Failed to find node_modules directories")?;

        if node_modules_paths.is_empty() {
            println!("✅ No node_modules directories found on this system");
            return Ok(Vec::new());
        }

        println!(
            "📦 Analyzing {} node_modules directories...",
            node_modules_paths.len()
        );

        // Always show progress bar for long-running operations
        let pb = ProgressBar::new(node_modules_paths.len() as u64);
        if self.verbose {
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
                    .unwrap()
                    .progress_chars("#>-"),
            );
        } else {
            pb.set_style(
                ProgressStyle::default_bar()
                    .template(
                        "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len}",
                    )
                    .unwrap()
                    .progress_chars("#>-"),
            );
        }
        pb.set_message("Scanning directories...");

        let mut all_results = Vec::new();

        // Process directories sequentially to show real-time progress
        for (index, node_modules_path) in node_modules_paths.iter().enumerate() {
            match self.scan_node_modules_directory_sync(node_modules_path) {
                Ok(mut results) => {
                    all_results.append(&mut results);
                }
                Err(e) => {
                    if self.verbose {
                        eprintln!(
                            "⚠️  Error scanning directory {}: {}",
                            node_modules_path.display(),
                            e
                        );
                    }
                }
            }
            pb.set_position((index + 1) as u64);
        }

        pb.finish_with_message("✅ Scan complete");

        let total_packages = all_results.len();
        let malicious_count = all_results.iter().filter(|r| r.is_malicious).count();

        println!("\n📊 Scan Results:");
        println!(
            "   • Total packages found: {}",
            total_packages.to_string().bright_white().bold()
        );
        if malicious_count > 0 {
            println!(
                "   • {} {}",
                "MALICIOUS PACKAGES DETECTED:".bright_red().bold(),
                malicious_count.to_string().bright_red().bold()
            );
        } else {
            println!(
                "   • {}",
                "No known malicious packages detected".bright_green()
            );
        }

        Ok(all_results)
    }

    // Synchronous version for parallel processing with rayon
    fn scan_node_modules_directory_sync(
        &self,
        node_modules_path: &Path,
    ) -> Result<Vec<ScanResult>> {
        let mut results = Vec::new();

        // Get the project root (parent of node_modules)
        let project_root = PlatformScanner::get_project_root(node_modules_path);

        // Look for package.json in the project root
        if let Some(package_json_path) = PlatformScanner::find_package_json(&project_root) {
            if let Ok(package_info) = self.parse_package_json(&package_json_path) {
                let threat = self
                    .threat_db
                    .check_package_fast(&package_info.name, &package_info.version);
                let is_malicious = threat.is_some();

                results.push(ScanResult {
                    package: package_info,
                    threat,
                    is_malicious,
                });
            }
        }

        // Also scan individual packages within node_modules
        if let Ok(entries) = fs::read_dir(node_modules_path) {
            for entry in entries.flatten() {
                let package_path = entry.path();
                if package_path.is_dir() {
                    // Skip scoped packages directory traversal for now (could be enhanced)
                    if let Some(name) = package_path.file_name().and_then(|n| n.to_str()) {
                        if name.starts_with('.') {
                            continue; // Skip hidden directories
                        }

                        if name.starts_with('@') {
                            // Handle scoped packages
                            if let Ok(scoped_entries) = fs::read_dir(&package_path) {
                                for scoped_entry in scoped_entries.flatten() {
                                    let scoped_package_path = scoped_entry.path();
                                    if scoped_package_path.is_dir() {
                                        if let Ok(package_info) =
                                            self.scan_individual_package(&scoped_package_path)
                                        {
                                            let threat = self.threat_db.check_package_fast(
                                                &package_info.name,
                                                &package_info.version,
                                            );
                                            let is_malicious = threat.is_some();

                                            results.push(ScanResult {
                                                package: package_info,
                                                threat,
                                                is_malicious,
                                            });
                                        }
                                    }
                                }
                            }
                        } else {
                            // Regular package
                            if let Ok(package_info) = self.scan_individual_package(&package_path) {
                                let threat = self
                                    .threat_db
                                    .check_package_fast(&package_info.name, &package_info.version);
                                let is_malicious = threat.is_some();

                                results.push(ScanResult {
                                    package: package_info,
                                    threat,
                                    is_malicious,
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(results)
    }

    fn scan_individual_package(&self, package_path: &Path) -> Result<PackageInfo> {
        let package_json_path = package_path.join("package.json");
        self.parse_package_json(&package_json_path)
    }

    fn parse_package_json(&self, package_json_path: &Path) -> Result<PackageInfo> {
        let content =
            fs::read_to_string(package_json_path).context("Failed to read package.json")?;

        let json: Value = serde_json::from_str(&content).context("Failed to parse package.json")?;

        let name = json["name"].as_str().unwrap_or("unknown").to_string();

        let version = json["version"].as_str().unwrap_or("unknown").to_string();

        let size_bytes = 4096; // Fast default

        let modified = if let Ok(metadata) = fs::metadata(package_json_path) {
            metadata
                .modified()
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
                .into()
        } else {
            Utc::now()
        };

        Ok(PackageInfo {
            name,
            version,
            path: package_json_path
                .parent()
                .unwrap()
                .to_string_lossy()
                .to_string(),
            size_bytes,
            modified,
        })
    }

    pub fn get_threat_summary(&self) -> Vec<&MaliciousPackage> {
        self.threat_db.get_all_malicious_packages()
    }
}
