use anyhow::Result;
use chrono::Utc;
use colored::Colorize;
use std::fs;
use std::path::PathBuf;

use crate::threats::{ScanResult, Severity};

pub struct Reporter {
    format: String,
    threats_only: bool,
}

impl Reporter {
    pub const fn new(format: String, threats_only: bool) -> Self {
        Self {
            format,
            threats_only,
        }
    }

    pub async fn generate_report(
        &mut self,
        results: &[ScanResult],
        output_file: Option<PathBuf>,
    ) -> Result<()> {
        let filtered_results: Vec<&ScanResult> = if self.threats_only {
            results.iter().filter(|r| r.is_malicious).collect()
        } else {
            results.iter().collect()
        };

        let report_content = match self.format.as_str() {
            "json" => self.generate_json_report(&filtered_results)?,
            "csv" => Self::generate_csv_report(&filtered_results)?,
            _ => self.generate_table_report(&filtered_results)?,
        };

        if let Some(output_path) = output_file {
            fs::write(&output_path, &report_content)?;
            println!("📄 Report saved to: {}", output_path.display());
        } else {
            println!("{report_content}");
        }

        // Always show threat summary if malicious packages found
        let malicious_results: Vec<&ScanResult> =
            results.iter().filter(|r| r.is_malicious).collect();
        if !malicious_results.is_empty() {
            Self::print_threat_summary(&malicious_results);
        }

        Ok(())
    }

    fn generate_table_report(&self, results: &[&ScanResult]) -> Result<String> {
        let mut output = String::new();

        if results.is_empty() {
            if self.threats_only {
                output.push_str(&format!(
                    "\n{}\n",
                    "✅ No malicious packages detected!".bright_green().bold()
                ));
            } else {
                output.push_str(&format!(
                    "\n{}\n",
                    "ℹ️  No npm packages found on this system.".dimmed()
                ));
            }
            return Ok(output);
        }

        // Header
        output.push_str(&format!(
            "\n{}\n",
            "📦 NPM Package Security Scan Results".bright_cyan().bold()
        ));
        output.push_str(&format!(
            "{}\n\n",
            "─"
                .repeat(term_size::dimensions().map_or(120, |(w, _)| w.max(80)))
                .dimmed()
        ));

        // Calculate column widths
        let terminal_width = term_size::dimensions().map_or(120, |(w, _)| w.max(80));
        let package_width = 25;
        let version_width = 12;
        let status_width = 12;
        let threat_width = 15;
        let spacing = 4; // spaces between columns
        let location_width = terminal_width
            .saturating_sub(package_width + version_width + status_width + threat_width + spacing)
            .max(20); // minimum 20 characters for location

        // Table header
        output.push_str(&format!(
            "{:<package_width$} {:<version_width$} {:<status_width$} {:<threat_width$} {}\n",
            "Package Name".bold(),
            "Version".bold(),
            "Status".bold(),
            "Threat Level".bold(),
            "Location".bold(),
            package_width = package_width,
            version_width = version_width,
            status_width = status_width,
            threat_width = threat_width
        ));
        output.push_str(&format!(
            "{}\n",
            "─"
                .repeat(term_size::dimensions().map_or(120, |(w, _)| w.max(80)))
                .dimmed()
        ));

        // Table rows
        for result in results {
            let package = &result.package;
            let status = if result.is_malicious {
                "🚨 MALICIOUS".bright_red().bold()
            } else {
                "✅ Clean".bright_green()
            };

            let threat_level = if let Some(threat) = &result.threat {
                match threat.severity {
                    Severity::Critical => "🔴 Critical".bright_red(),
                    Severity::High => "🟠 High".bright_yellow(),
                    Severity::Medium => "🟡 Medium".yellow(),
                    Severity::Low => "🟢 Low".green(),
                }
            } else {
                "─".dimmed()
            };

            let location = if package.path.len() > location_width - 3 {
                format!("{}...", &package.path[..location_width - 3])
            } else {
                package.path.clone()
            };

            output.push_str(&format!(
                "{:<package_width$} {:<version_width$} {:<status_width$} {:<threat_width$} {}\n",
                if package.name.len() > package_width - 3 {
                    format!("{}...", &package.name[..package_width - 3])
                } else {
                    package.name.clone()
                },
                if package.version.len() > version_width - 3 {
                    format!("{}...", &package.version[..version_width - 3])
                } else {
                    package.version.clone()
                },
                status.to_string(),
                threat_level.to_string(),
                location,
                package_width = package_width,
                version_width = version_width,
                status_width = status_width,
                threat_width = threat_width
            ));
        }

        output.push_str(&format!(
            "\n{}\n",
            "─"
                .repeat(term_size::dimensions().map_or(120, |(w, _)| w.max(80)))
                .dimmed()
        ));

        // Summary
        let total = results.len();
        let malicious = results.iter().filter(|r| r.is_malicious).count();

        output.push_str(&format!(
            "📊 Summary: {} total packages, {} malicious\n",
            total.to_string().bright_white().bold(),
            if malicious > 0 {
                malicious.to_string().bright_red().bold()
            } else {
                malicious.to_string().bright_green().bold()
            }
        ));

        Ok(output)
    }

    fn generate_json_report(&self, results: &[&ScanResult]) -> Result<String> {
        let malicious_results: Vec<_> = results.iter().filter(|r| r.is_malicious).collect();

        // Calculate threat statistics
        let mut severity_counts = std::collections::HashMap::new();
        let mut source_counts = std::collections::HashMap::new();
        let mut threat_type_counts = std::collections::HashMap::new();

        for result in &malicious_results {
            if let Some(threat) = &result.threat {
                *severity_counts
                    .entry(format!("{:?}", threat.severity))
                    .or_insert(0) += 1;
                *source_counts
                    .entry(format!("{:?}", threat.source_database))
                    .or_insert(0) += 1;
                *threat_type_counts
                    .entry(format!("{:?}", threat.threat_type))
                    .or_insert(0) += 1;
            }
        }

        let report = serde_json::json!({
            "timestamp": Utc::now(),
            "scan_type": "npm_security_scan",
            "threats_only": self.threats_only,
            "summary": {
                "total_packages": results.len(),
                "malicious_packages": malicious_results.len(),
                "clean_packages": results.len() - malicious_results.len(),
                "severity_breakdown": severity_counts,
                "source_breakdown": source_counts,
                "threat_type_breakdown": threat_type_counts,
                "packages_with_cvss_scores": malicious_results.iter().filter(|r|
                    r.threat.as_ref().is_some_and(|t| t.cvss_score.is_some())
                ).count(),
                "github_reviewed_packages": malicious_results.iter().filter(|r|
                    r.threat.as_ref().is_some_and(|t| t.github_reviewed == Some(true))
                ).count()
            },
            "results": results
        });

        Ok(serde_json::to_string_pretty(&report)?)
    }

    fn generate_csv_report(results: &[&ScanResult]) -> Result<String> {
        let mut output = String::new();

        // CSV Header
        output.push_str("Package Name,Version,Path,Size (bytes),Is Malicious,Threat Type,Severity,Description,CWE IDs,CVSS Score,CVSS Vector,GitHub Reviewed,GitHub Reviewed At,NVD Published At,Source Database,Aliases,References,Discovered Date\n");

        // CSV Rows
        for result in results {
            let package = &result.package;
            let is_malicious = if result.is_malicious { "true" } else { "false" };

            let (
                threat_type,
                severity,
                description,
                cwe_ids,
                cvss_score,
                cvss_vector,
                github_reviewed,
                github_reviewed_at,
                nvd_published_at,
                source_db,
                aliases,
                references,
                discovered,
            ) = if let Some(threat) = &result.threat {
                (
                    format!("{:?}", threat.threat_type),
                    format!("{:?}", threat.severity),
                    threat.description.replace(',', ";").replace('\n', " "),
                    threat.cwe_ids.join(";"),
                    threat
                        .cvss_score
                        .map_or("N/A".to_string(), |s| s.to_string()),
                    threat.cvss_vector.clone().unwrap_or("N/A".to_string()),
                    threat
                        .github_reviewed
                        .map_or("N/A".to_string(), |r| r.to_string()),
                    threat.github_reviewed_at.map_or("N/A".to_string(), |dt| {
                        dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
                    }),
                    threat.nvd_published_at.map_or("N/A".to_string(), |dt| {
                        dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
                    }),
                    format!("{:?}", threat.source_database),
                    threat.aliases.join(";"),
                    threat.references.join(";"),
                    threat
                        .discovered
                        .format("%Y-%m-%d %H:%M:%S UTC")
                        .to_string(),
                )
            } else {
                (
                    "None".to_string(),
                    "None".to_string(),
                    "No threats detected".to_string(),
                    "N/A".to_string(),
                    "N/A".to_string(),
                    "N/A".to_string(),
                    "N/A".to_string(),
                    "N/A".to_string(),
                    "N/A".to_string(),
                    "N/A".to_string(),
                    "N/A".to_string(),
                    "N/A".to_string(),
                    "N/A".to_string(),
                )
            };

            output.push_str(&format!(
                "{},{},{},{},{},{},{},\"{}\",\"{}\",{},\"{}\",{},{},{},\"{}\",\"{}\",\"{}\",{}\n",
                package.name.replace(',', ";"),
                package.version,
                package.path.replace(',', ";"),
                package.size_bytes,
                is_malicious,
                threat_type,
                severity,
                description,
                cwe_ids,
                cvss_score,
                cvss_vector,
                github_reviewed,
                github_reviewed_at,
                nvd_published_at,
                source_db,
                aliases,
                references,
                discovered
            ));
        }

        Ok(output)
    }

    fn print_threat_summary(malicious_results: &[&ScanResult]) {
        println!(
            "\n{}",
            "🚨 SECURITY ALERT - MALICIOUS PACKAGES DETECTED"
                .bright_red()
                .bold()
        );
        println!("{}", "═".repeat(60).bright_red());

        for result in malicious_results {
            if let Some(threat) = &result.threat {
                println!(
                    "\n{} {}",
                    "📦 Package:".bright_white().bold(),
                    format!("{}@{}", result.package.name, result.package.version)
                        .bright_red()
                        .bold()
                );
                println!(
                    "{} {}",
                    "📍 Location:".bright_white().bold(),
                    result.package.path.dimmed()
                );
                println!(
                    "{} {}",
                    "⚡ Threat Type:".bright_white().bold(),
                    format!("{:?}", threat.threat_type).bright_yellow()
                );
                println!(
                    "{} {}",
                    "🔥 Severity:".bright_white().bold(),
                    match threat.severity {
                        Severity::Critical => "CRITICAL".bright_red().bold(),
                        Severity::High => "HIGH".bright_yellow().bold(),
                        Severity::Medium => "MEDIUM".yellow().bold(),
                        Severity::Low => "LOW".green().bold(),
                    }
                );
                println!(
                    "{} {}",
                    "📝 Description:".bright_white().bold(),
                    threat.description.bright_white()
                );

                if !threat.cwe_ids.is_empty() {
                    println!(
                        "{} {}",
                        "🏷️  CWE IDs:".bright_white().bold(),
                        threat.cwe_ids.join(", ").bright_magenta()
                    );
                }

                if let Some(cvss_score) = threat.cvss_score {
                    println!(
                        "{} {}",
                        "📊 CVSS Score:".bright_white().bold(),
                        format!("{:.1}", cvss_score).bright_cyan()
                    );
                }

                if let Some(reviewed) = threat.github_reviewed {
                    println!(
                        "{} {}",
                        "✅ GitHub Reviewed:".bright_white().bold(),
                        if reviewed {
                            "Yes".bright_green()
                        } else {
                            "No".bright_red()
                        }
                    );
                }

                println!(
                    "{} {}",
                    "📊 Source:".bright_white().bold(),
                    format!("{:?}", threat.source_database).bright_blue()
                );

                if !threat.aliases.is_empty() {
                    println!(
                        "{} {}",
                        "🆔 Aliases:".bright_white().bold(),
                        threat.aliases.join(", ").bright_yellow()
                    );
                }

                if !threat.references.is_empty() {
                    println!(
                        "{} {}",
                        "🔗 References:".bright_white().bold(),
                        threat.references.join(", ").bright_blue().underline()
                    );
                }
                println!("{}", "─".repeat(60).dimmed());
            }
        }

        println!("\n{}", "🛡️  RECOMMENDED ACTIONS:".bright_yellow().bold());
        println!(
            "   1. {} Immediately remove or downgrade affected packages",
            "🚫".bright_red()
        );
        println!(
            "   2. {} Check your package-lock.json for these versions",
            "🔍".bright_yellow()
        );
        println!(
            "   3. {} Audit your project dependencies: npm audit",
            "🔧".bright_cyan()
        );
        println!(
            "   4. {} Consider using npm audit fix for automated fixes",
            "🔧".bright_cyan()
        );
        println!(
            "   5. {} Monitor your systems for signs of compromise",
            "👁️ ".bright_magenta()
        );
        println!(
            "   6. {} Update to latest secure versions when available",
            "⬆️ ".bright_green()
        );

        println!(
            "\n{}",
            "For more information about these threats, visit the provided references.".dimmed()
        );
    }
}
