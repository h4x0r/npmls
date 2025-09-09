use clap::{Arg, Command};
use colored::Colorize;
use std::path::PathBuf;

mod advisory_client;
mod database_updater;
mod platform;
mod reporter;
mod scanner;
mod threats;

use reporter::Reporter;
use scanner::Scanner;
use std::collections::HashMap;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let matches = Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .help("Output results to file (CSV format by default)")
        )
        .arg(
            Arg::new("format")
                .long("format")
                .value_name("FORMAT")
                .default_value("table")
                .help("Output format: table (console), json, csv. When used with -o, affects the output file format")
        )
        .arg(
            Arg::new("threats-only")
                .short('t')
                .long("threats-only")
                .action(clap::ArgAction::SetTrue)
                .help("Only show packages matching known malicious versions")
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(clap::ArgAction::SetTrue)
                .help("Verbose output with detailed scan progress")
        )
        .arg(
            Arg::new("offline")
                .long("offline")
                .action(clap::ArgAction::SetTrue)
                .help("Offline mode - only use built-in threat database")
        )
        .arg(
            Arg::new("update-db")
                .long("update-db")
                .action(clap::ArgAction::SetTrue)
                .help("Update vulnerability database from online sources and exit")
        )
        .arg(
            Arg::new("list-threats")
                .long("list-threats")
                .action(clap::ArgAction::SetTrue)
                .help("List all known vulnerable packages and versions, then exit")
        )
        .get_matches();

    println!(
        "{} {}",
        "🔍 NPM Security Scanner v0.1.0".bright_cyan().bold(),
        "- By Albert Hui <albert@securityronin.com>".dimmed()
    );
    println!(
        "{}",
        "Scan entire file system for malicious npm packages and modules\n".dimmed()
    );

    let verbose = matches.get_flag("verbose");
    let threats_only = matches.get_flag("threats-only");
    let offline_mode = matches.get_flag("offline");
    let update_db = matches.get_flag("update-db");
    let list_threats = matches.get_flag("list-threats");
    let output_file = matches.get_one::<String>("output").map(PathBuf::from);
    let format_raw = matches.get_one::<String>("format").unwrap();

    // When -o is specified and format is still the default "table", switch to CSV for file output
    let format = if output_file.is_some() && format_raw == "table" {
        "csv"
    } else {
        format_raw
    };

    // Handle manual database update mode (always force update)
    if update_db {
        use database_updater::DatabaseUpdater;

        let updater = DatabaseUpdater::new()?;

        // Always update when --update-db is used
        let _database = updater.update_database_force().await?;

        println!(
            "{}",
            "✅ Vulnerability database updated successfully!"
                .bright_green()
                .bold()
        );
        return Ok(());
    }

    // Handle list threats mode
    if list_threats {
        use scanner::Scanner;

        let scanner = Scanner::new_with_options(verbose, !offline_mode).await?;
        let threat_summary = scanner.get_threat_summary();

        if threat_summary.is_empty() {
            println!("{}", "No known threats in database".yellow());
            return Ok(());
        }

        println!("{}", "🚨 Known Vulnerable NPM Packages".bright_red().bold());
        println!("{}", "═".repeat(80).dimmed());
        println!();

        // Group threats by package name
        let mut grouped_threats: HashMap<String, Vec<&crate::threats::MaliciousPackage>> =
            HashMap::new();
        for threat in &threat_summary {
            grouped_threats
                .entry(threat.name.clone())
                .or_default()
                .push(threat);
        }

        let mut sorted_packages: Vec<_> = grouped_threats.keys().collect();
        sorted_packages.sort();

        for package_name in sorted_packages {
            let threats = grouped_threats.get(package_name).unwrap();

            println!("📦 {}", package_name.bright_white().bold());
            for threat in threats {
                let severity_icon = match threat.severity {
                    crate::threats::Severity::Critical => "🔴",
                    crate::threats::Severity::High => "🟠",
                    crate::threats::Severity::Medium => "🟡",
                    crate::threats::Severity::Low => "🔵",
                };

                let threat_type_str = match threat.threat_type {
                    crate::threats::ThreatType::SupplyChainAttack => "Supply Chain Attack",
                    crate::threats::ThreatType::Cryptojacking => "Cryptojacking",
                    crate::threats::ThreatType::CredentialTheft => "Credential Theft",
                    crate::threats::ThreatType::Backdoor => "Backdoor",
                    crate::threats::ThreatType::DataExfiltration => "Data Exfiltration",
                    crate::threats::ThreatType::Ransomware => "Ransomware",
                };

                println!(
                    "  {} Version: {} | {} {} | {}",
                    severity_icon,
                    threat.version.bright_red().bold(),
                    format!("{:?}", threat.severity).bright_magenta(),
                    threat_type_str.dimmed(),
                    threat.discovered.format("%Y-%m-%d").to_string().dimmed()
                );

                if !threat.description.is_empty() {
                    println!(
                        "     {}",
                        threat
                            .description
                            .chars()
                            .take(120)
                            .collect::<String>()
                            .dimmed()
                    );
                }
            }
            println!();
        }

        println!("{}", "═".repeat(80).dimmed());
        println!(
            "📊 {} Total: {} vulnerable packages, {} threat variants",
            "Summary:".bright_green().bold(),
            grouped_threats.len().to_string().bright_white().bold(),
            threat_summary.len().to_string().bright_white().bold()
        );

        return Ok(());
    }

    if offline_mode && verbose {
        println!(
            "{}",
            "🔒 Running in offline mode - using built-in threat database only".yellow()
        );
    } else if verbose {
        println!(
            "{}",
            "🌐 Online mode - automatic database updates enabled".green()
        );
    }

    let scanner = Scanner::new_with_options(verbose, !offline_mode).await?;
    let scan_results = scanner.scan_system().await?;

    // Deduplicate and sort packages by name and version
    let mut unique_results: HashMap<(String, String), crate::threats::ScanResult> = HashMap::new();
    for result in scan_results {
        let key = (result.package.name.clone(), result.package.version.clone());
        unique_results.insert(key, result);
    }

    let mut deduplicated_results: Vec<crate::threats::ScanResult> =
        unique_results.into_values().collect();
    deduplicated_results.sort_by(|a, b| {
        a.package
            .name
            .cmp(&b.package.name)
            .then_with(|| a.package.version.cmp(&b.package.version))
    });

    let mut reporter = Reporter::new(format.to_string(), threats_only);
    reporter
        .generate_report(&deduplicated_results, output_file)
        .await?;

    Ok(())
}
