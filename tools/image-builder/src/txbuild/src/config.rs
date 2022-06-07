use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct ConfigInfo {
    package: Package,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
struct Package {
    metadata: Option<Metadata>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
struct Metadata {
    build_target: Option<BuildTarget>,
    build_package: Option<BuildPackage>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct BuildPackage {
    pub(crate) package_name: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct BuildTarget {
    pub(crate) kernel_version: Option<String>,
    pub(crate) image_format: Option<ImageFormat>,
    pub(crate) included_packages: Option<Vec<String>>,
    pub(crate) supported_arches: Option<HashSet<SupportedArch>>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ImageFormat {
    Raw,
    Vmdk,
    Qcow2,
}

#[derive(Deserialize, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SupportedArch {
    X86_64,
    Aarch64,
}

impl ConfigInfo {
    pub(crate) fn new<P: AsRef<Path>>(path: P) -> Result<Self, i32> {
        let path = path.as_ref();

        let config_data = match fs::read_to_string(path) {
            Err(e) => {
                eprintln!("Failed to read file '{}': {}", path.display(), e);
                return Err(1);
            }
            Ok(file_data) => file_data,
        };

        let config = match toml::from_str(&config_data) {
            Err(e) => {
                eprintln!("Failed to load toml file '{}': {}", path.display(), e);
                return Err(2);
            }
            Ok(toml_data) => toml_data,
        };

        return Ok(config);
    }

    fn build_package(&self) -> Option<&BuildPackage> {
        self.package
            .metadata
            .as_ref()
            .and_then(|m| m.build_package.as_ref())
    }

    fn build_target(&self) -> Option<&BuildTarget> {
        self.package
            .metadata
            .as_ref()
            .and_then(|m| m.build_target.as_ref())
    }

    pub(crate) fn get_package(&self) -> Option<&String> {
        self.build_package().and_then(|b| b.package_name.as_ref())
    }

    pub(crate) fn get_kversion(&self) -> Option<&String> {
        self.build_target().and_then(|b| b.kernel_version.as_ref())
    }

    pub(crate) fn get_packages(&self) -> Option<&Vec<String>> {
        self.build_target()
            .and_then(|b| b.included_packages.as_ref())
    }

    pub(crate) fn get_format(&self) -> Option<&ImageFormat> {
        self.build_target().and_then(|b| b.image_format.as_ref())
    }

    pub(crate) fn get_supported_arches(&self) -> Option<&HashSet<SupportedArch>> {
        self.build_target()
            .and_then(|b| b.supported_arches.as_ref())
    }
}
