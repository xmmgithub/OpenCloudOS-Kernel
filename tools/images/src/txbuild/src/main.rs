mod config;
mod gen;

use config::ConfigInfo;
use config::SupportedArch;
use gen::PackageProducer;
use gen::TargetProducer;
use serde::Deserialize;
use std::env;
use std::path::PathBuf;
use std::process;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Command {
    GenerateTarget,
    GeneratePackage,
}

fn usage() -> ! {
    eprintln!(
        "\
USAGE:
    txbuild <SUBCOMMAND>

SUBCOMMANDS:
    generate-package     Generate RPMs from a spec file.
    generate-target      Generate filesystem and disk images from RPMs."
    );
    process::exit(1)
}

macro_rules! get_env {
    ($var:expr) => {
        match get_environment($var) {
            Err(_) => return false,
            Ok(value) => value,
        }
    };
}

fn get_environment(var: &str) -> Result<String, bool> {
    let value = match env::var(var) {
        Err(_) => {
            eprintln!("Missing environment variable '{}'", var);
            return Err(false);
        }
        Ok(v) => v,
    };

    return Ok(value);
}

fn is_supported_arch(config: &ConfigInfo) -> bool {
    let arch = get_env!("TENCENT_ARCH");

    let current_arch: SupportedArch = if let Ok(value) = serde_plain::from_str(&arch) {
        value
    } else {
        eprintln!("Unknown architecture: '{}'", arch);
        return false;
    };

    if let Some(supported_arches) = config.get_supported_arches() {
        if !supported_arches.contains(&current_arch) {
            eprintln!("Unsupported architecture {}", arch);
            return false;
        }
    }
    return true;
}

fn generate_package(config_name: &str) -> bool {
    let arch = get_env!("TENCENT_ARCH");
    let target = get_env!("TENCENT_TARGET");
    let root_dir: PathBuf = get_env!("TENCENT_ROOT_DIR").into();
    let config_dir: PathBuf = get_env!("CARGO_MANIFEST_DIR").into();

    let target_config_path = root_dir.join("targets").join(target).join(config_name);
    let target_config = match ConfigInfo::new(target_config_path) {
        Err(_) => return false,
        Ok(config) => config,
    };

    if !is_supported_arch(&target_config) {
        return false;
    }

    let config = match ConfigInfo::new(config_dir.join(config_name)) {
        Err(_) => return false,
        Ok(config) => config,
    };

    let cargo_package = get_env!("CARGO_PKG_NAME");
    let package = if let Some(name_override) = config.get_package() {
        name_override.clone()
    } else {
        cargo_package
    };

    if PackageProducer::generate(&package, &arch) {
        return true;
    }
    eprintln!("generate {} failed", package);

    return false;
}

fn generate_target(config_name: &str) -> bool {
    let config_dir: PathBuf = get_env!("CARGO_MANIFEST_DIR").into();
    let config = match ConfigInfo::new(config_dir.join(config_name)) {
        Err(_) => return false,
        Ok(config) => config,
    };

    if !is_supported_arch(&config) {
        return false;
    }

    if let Some(kernel_version) = config.get_kversion() {
        if let Some(packages) = config.get_packages() {
            let image_format = config.get_format();
            if TargetProducer::generate(&packages, image_format, kernel_version) {
                return true;
            }
            eprintln!("generate target failed");
        } else {
            println!("cargo:warning=No included packages in config. Skipping.");
        }
    } else {
        println!("cargo:warning=No kernel_version in config.");
    }

    return false;
}

fn run_task() -> bool {
    let config_file = "Cargo.toml";
    let command_str = std::env::args().nth(1).unwrap_or_else(|| usage());
    let command = serde_plain::from_str::<Command>(&command_str).unwrap_or_else(|_| usage());

    match command {
        Command::GenerateTarget => return generate_target(&config_file),
        Command::GeneratePackage => return generate_package(&config_file),
    }
}

fn main() {
    if !run_task() {
        process::exit(1);
    }
}
