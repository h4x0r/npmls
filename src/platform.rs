use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tokio::process::Command as TokioCommand;

#[cfg(target_os = "windows")]
use winapi::um::fileapi::{GetDriveTypeA, GetLogicalDrives};

pub struct PlatformScanner;

impl PlatformScanner {
    pub async fn find_node_modules() -> Result<Vec<PathBuf>> {
        #[cfg(target_os = "macos")]
        {
            Self::macos_mdfind().await
        }
        #[cfg(target_os = "linux")]
        {
            Self::linux_locate().await
        }
        #[cfg(target_os = "windows")]
        {
            Self::windows_mft_scan().await
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            Self::fallback_find().await
        }
    }

    #[cfg(target_os = "macos")]
    async fn macos_mdfind() -> Result<Vec<PathBuf>> {
        println!("🍎 Using macOS Spotlight (mdfind) for fast scanning...");

        let output = TokioCommand::new("mdfind")
            .arg("-name")
            .arg("node_modules")
            .output()
            .await
            .context("Failed to execute mdfind command")?;

        if !output.status.success() {
            // Fallback to more specific spotlight query
            let output = TokioCommand::new("mdfind")
                .arg("kMDItemFSName == 'node_modules' && kMDItemContentType == 'public.folder'")
                .output()
                .await
                .context("Failed to execute mdfind with Spotlight query")?;

            if !output.status.success() {
                return Self::fallback_find().await;
            }
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut paths = Vec::new();

        for line in stdout.lines() {
            let path = PathBuf::from(line.trim());
            if path.exists()
                && path.is_dir()
                && path.file_name().unwrap_or_default() == "node_modules"
            {
                paths.push(path);
            }
        }

        println!("✅ Found {} node_modules directories", paths.len());
        Ok(paths)
    }

    #[cfg(target_os = "linux")]
    async fn linux_locate() -> Result<Vec<PathBuf>> {
        println!("🐧 Using Linux locate database for fast scanning...");

        // First try to update the locate database
        let _ = TokioCommand::new("sudo").arg("updatedb").output().await;

        let output = TokioCommand::new("locate")
            .arg("-r")
            .arg("/node_modules$")
            .output()
            .await;

        let paths = match output {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut paths = Vec::new();

                for line in stdout.lines() {
                    let path = PathBuf::from(line.trim());
                    if path.exists() && path.is_dir() {
                        paths.push(path);
                    }
                }
                paths
            }
            _ => {
                println!("⚠️  locate failed or not available, falling back to find command...");
                return Self::fallback_find().await;
            }
        };

        println!("✅ Found {} node_modules directories", paths.len());
        Ok(paths)
    }

    #[cfg(target_os = "windows")]
    async fn windows_mft_scan() -> Result<Vec<PathBuf>> {
        println!("🪟 Using Windows MFT (Master File Table) scanning for ultra-fast directory enumeration...");

        // Get all drives
        let drives = Self::get_windows_drives()?;
        let mut all_paths = Vec::new();

        for drive in drives {
            println!("   Scanning drive {} with MFT lookup...", drive);
            let paths = Self::scan_drive_for_node_modules(&drive).await?;
            all_paths.extend(paths);
        }

        println!("✅ Found {} node_modules directories", all_paths.len());
        Ok(all_paths)
    }

    #[cfg(target_os = "windows")]
    fn get_windows_drives() -> Result<Vec<String>> {
        use std::ffi::CString;

        let mut drives = Vec::new();
        unsafe {
            let logical_drives = GetLogicalDrives();
            for i in 0..26 {
                if logical_drives & (1 << i) != 0 {
                    let drive_letter = (b'A' + i as u8) as char;
                    let drive_path = format!("{}:\\", drive_letter);

                    // Check if it's a fixed drive (hard disk)
                    let c_drive_path = CString::new(drive_path.clone()).unwrap();
                    let drive_type = GetDriveTypeA(c_drive_path.as_ptr());

                    // Only scan fixed drives and network drives
                    if drive_type == 3 || drive_type == 4 {
                        // DRIVE_FIXED or DRIVE_REMOTE
                        drives.push(drive_path);
                    }
                }
            }
        }
        Ok(drives)
    }

    #[cfg(target_os = "windows")]
    async fn scan_drive_for_node_modules(drive: &str) -> Result<Vec<PathBuf>> {
        // Try MFT scanning first for maximum performance
        match Self::mft_scan_drive(drive).await {
            Ok(paths) => Ok(paths),
            Err(_) => {
                // Fallback to PowerShell if MFT fails
                Self::powershell_scan_drive(drive).await
            }
        }
    }

    #[cfg(target_os = "windows")]
    #[allow(clippy::manual_map)]
    async fn mft_scan_drive(drive: &str) -> Result<Vec<PathBuf>> {
        #[allow(unused_imports)]
        use ntfs_reader::{file_info::FileInfo, mft::Mft, volume::Volume};
        use std::sync::{Arc, Mutex};

        let paths = Arc::new(Mutex::new(Vec::new()));
        let drive_letter = drive.chars().next().unwrap();
        let volume_path = format!("\\\\.\\{}:", drive_letter);
        let drive_owned = drive.to_string(); // Clone drive for move into closure

        tokio::task::spawn_blocking({
            let paths = Arc::clone(&paths);
            move || -> Result<()> {
                let volume = Volume::new(&volume_path)
                    .map_err(|e| anyhow::anyhow!("Failed to open volume {}: {}", volume_path, e))?;

                let mft =
                    Mft::new(volume).map_err(|e| anyhow::anyhow!("Failed to read MFT: {}", e))?;

                mft.iterate_files(|file| {
                    #[allow(unused_variables)]
                    let info = FileInfo::new(&mft, file);

                    // Check if this is a directory named "node_modules"
                    if info.is_directory && info.name == "node_modules" {
                        let path_str = info.path.to_string_lossy();
                        let full_path = PathBuf::from(format!(
                            "{}\\{}",
                            drive_owned.trim_end_matches('\\'),
                            path_str.trim_start_matches('\\')
                        ));
                        if full_path.exists() {
                            if let Ok(mut locked_paths) = paths.lock() {
                                locked_paths.push(full_path);
                            }
                        }
                    }
                });

                Ok(())
            }
        })
        .await??;

        let result = paths
            .lock()
            .map_err(|_| anyhow::anyhow!("Failed to access MFT scan results"))?
            .clone();

        Ok(result)
    }

    #[cfg(target_os = "windows")]
    async fn powershell_scan_drive(drive: &str) -> Result<Vec<PathBuf>> {
        // Use PowerShell for directory enumeration (fallback)
        let output = TokioCommand::new("powershell")
            .arg("-Command")
            .arg(format!(
                "Get-ChildItem -Path '{}' -Name 'node_modules' -Directory -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName",
                drive
            ))
            .output()
            .await?;

        if !output.status.success() {
            // Fallback to dir command
            return Self::windows_dir_fallback(drive).await;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let paths: Vec<PathBuf> = stdout
            .lines()
            .map(|line| PathBuf::from(line.trim()))
            .filter(|path| path.exists() && path.is_dir())
            .collect();

        Ok(paths)
    }

    #[cfg(target_os = "windows")]
    async fn windows_dir_fallback(drive: &str) -> Result<Vec<PathBuf>> {
        let output = TokioCommand::new("cmd")
            .arg("/C")
            .arg(format!("dir \"{}node_modules\" /s /b /ad", drive))
            .output()
            .await?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let paths: Vec<PathBuf> = stdout
            .lines()
            .map(|line| PathBuf::from(line.trim()))
            .filter(|path| path.exists() && path.is_dir())
            .collect();

        Ok(paths)
    }

    // Fallback method using built-in fast filesystem scanner (fd algorithm implementation)
    async fn fallback_find() -> Result<Vec<PathBuf>> {
        println!("⚡ Using built-in ultra-fast filesystem scanner...");

        // Get multiple search roots for comprehensive coverage
        let search_roots = Self::get_search_roots();

        // Use our built-in parallel fd-like scanner
        let paths = Self::fast_directory_scan(&search_roots, "node_modules", 15).await?;

        println!("✅ Found {} node_modules directories", paths.len());
        Ok(paths)
    }

    // Get intelligent search roots based on the platform
    fn get_search_roots() -> Vec<PathBuf> {
        let mut roots = Vec::new();

        // Always include user's home directory
        if let Some(home) = dirs::home_dir() {
            roots.push(home);
        }

        // Platform-specific common locations
        #[cfg(target_os = "macos")]
        {
            roots.extend([
                PathBuf::from("/Applications"),
                PathBuf::from("/usr/local"),
                PathBuf::from("/opt"),
            ]);
        }

        #[cfg(target_os = "linux")]
        {
            roots.extend([
                PathBuf::from("/usr/local"),
                PathBuf::from("/opt"),
                PathBuf::from("/var/www"),
                PathBuf::from("/srv"),
            ]);
        }

        #[cfg(target_os = "windows")]
        {
            roots.extend([
                PathBuf::from("C:\\Users"),
                PathBuf::from("C:\\Program Files"),
                PathBuf::from("C:\\Program Files (x86)"),
                PathBuf::from("C:\\ProgramData"),
            ]);
        }

        // Filter to only include existing, accessible directories
        roots
            .into_iter()
            .filter(|path| path.exists() && path.is_dir())
            .collect()
    }

    // High-performance parallel directory scanner implementing fd-like algorithm
    async fn fast_directory_scan(
        roots: &[PathBuf],
        target_name: &str,
        max_depth: usize,
    ) -> Result<Vec<PathBuf>> {
        use ignore::WalkBuilder;
        use std::sync::{Arc, Mutex};

        let found_paths = Arc::new(Mutex::new(Vec::new()));

        // Process each root in parallel
        let tasks: Vec<_> = roots
            .iter()
            .map(|root| {
                let root = root.clone();
                let target_name = target_name.to_string();
                let found_paths = Arc::clone(&found_paths);

                tokio::task::spawn_blocking(move || {
                    // Create high-performance walker with smart defaults
                    let mut builder = WalkBuilder::new(&root);
                    builder
                        .max_depth(Some(max_depth))
                        .follow_links(true)
                        .hidden(false) // Skip hidden directories for performance
                        .parents(false) // Don't traverse parent directories
                        .ignore(true) // Respect .gitignore files for performance
                        .git_ignore(true)
                        .git_exclude(true)
                        .threads(num_cpus::get().min(4)); // Limit threads to avoid overwhelming system

                    let walker = builder.build_parallel();
                    let found_paths_clone = Arc::clone(&found_paths);

                    walker.run(|| {
                        let target_name = target_name.clone();
                        let found_paths = Arc::clone(&found_paths_clone);

                        Box::new(move |entry| {
                            use ignore::WalkState;

                            match entry {
                                Ok(entry) => {
                                    let path = entry.path();

                                    // Check if this is a directory named "node_modules"
                                    if path.is_dir() {
                                        if let Some(name) = path.file_name() {
                                            if name == target_name.as_str() {
                                                if let Ok(mut paths) = found_paths.lock() {
                                                    paths.push(path.to_path_buf());
                                                }

                                                // Skip traversing into node_modules to avoid nested scanning
                                                return WalkState::Skip;
                                            }
                                        }
                                    }

                                    // Performance optimization: skip certain directories entirely
                                    if path.is_dir() {
                                        if let Some(name) =
                                            path.file_name().and_then(|n| n.to_str())
                                        {
                                            match name {
                                                ".git" | ".svn" | ".hg" | ".bzr" => {
                                                    return WalkState::Skip
                                                }
                                                "target" | "build" | "dist" | "out" => {
                                                    // Skip common build directories unless they might contain npm projects
                                                    if !Self::might_contain_npm_projects(path) {
                                                        return WalkState::Skip;
                                                    }
                                                }
                                                _ => {}
                                            }
                                        }
                                    }

                                    WalkState::Continue
                                }
                                Err(_) => WalkState::Continue, // Skip inaccessible entries
                            }
                        })
                    });
                })
            })
            .collect();

        // Wait for all parallel scans to complete
        for task in tasks {
            let _ = task.await; // Ignore individual task errors
        }

        // Extract and deduplicate results
        let paths = found_paths
            .lock()
            .map_err(|_| anyhow::anyhow!("Failed to access scan results"))?;

        // Remove duplicates and sort by path for consistent output
        let mut unique_paths: Vec<PathBuf> = paths.clone();
        unique_paths.sort();
        unique_paths.dedup();

        Ok(unique_paths)
    }

    // Heuristic to determine if a directory might contain npm projects
    fn might_contain_npm_projects(path: &Path) -> bool {
        // Check for common indicators that suggest npm projects might be present
        let indicators = [
            "package.json",
            "node_modules",
            ".npmrc",
            "yarn.lock",
            "pnpm-lock.yaml",
        ];

        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten().take(20) {
                // Limit check to first 20 entries for performance
                if let Some(name) = entry.file_name().to_str() {
                    if indicators.contains(&name) {
                        return true;
                    }
                }
            }
        }

        false
    }

    pub fn get_project_root(node_modules_path: &Path) -> PathBuf {
        node_modules_path
            .parent()
            .unwrap_or(node_modules_path)
            .to_path_buf()
    }

    pub fn find_package_json(project_root: &Path) -> Option<PathBuf> {
        let package_json_path = project_root.join("package.json");
        if package_json_path.exists() {
            Some(package_json_path)
        } else {
            None
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
compile_error!("This platform is not supported. Supported platforms: macOS, Linux, Windows");
