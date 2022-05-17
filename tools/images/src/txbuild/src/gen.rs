use crate::config::ImageFormat;
use duct::cmd;
use std::env;
use std::fs;
use std::fs::File;
use std::path::Path;
use std::path::PathBuf;
use std::str;
use std::time::{SystemTime, UNIX_EPOCH};
use walkdir::{DirEntry, WalkDir};

enum GenType {
    Target,
    Package,
}

pub(crate) struct TargetProducer;
pub(crate) struct PackageProducer;
const TX_EXTENSION: &str = ".txbuild_marker";

macro_rules! get_env {
    ($var:expr) => {
        match get_environment($var) {
            Err(_) => return false,
            Ok(value) => value,
        }
    };
}

trait SplitString {
    fn split_string(&self) -> Vec<String>;
}

impl<S> SplitString for S
where
    S: AsRef<str>,
{
    fn split_string(&self) -> Vec<String> {
        self.as_ref().split(' ').map(String::from).collect()
    }
}

trait GenArg {
    fn add_arg<S1, S2>(&mut self, key: S1, value: S2)
    where
        S1: AsRef<str>,
        S2: AsRef<str>;
}

impl GenArg for Vec<String> {
    fn add_arg<S1, S2>(&mut self, key: S1, value: S2)
    where
        S1: AsRef<str>,
        S2: AsRef<str>,
    {
        self.push("--build-arg".to_string());
        self.push(format!("{}={}", key.as_ref(), value.as_ref()));
    }
}

fn get_environment(var: &str) -> Result<String, i32> {
    let value = match env::var(var) {
        Err(_) => {
            eprintln!("Missing environment variable '{}'", var);
            return Err(1);
        }
        Ok(v) => v,
    };

    return Ok(value);
}

fn get_files<P>(
    dir: P,
    filter: for<'r> fn(&'r walkdir::DirEntry) -> bool,
) -> impl Iterator<Item = PathBuf>
where
    P: AsRef<Path>,
{
    WalkDir::new(&dir)
        .follow_links(false)
        .same_file_system(true)
        .min_depth(1)
        .max_depth(1)
        .into_iter()
        .filter_entry(move |e| filter(e))
        .flat_map(|e| e)
        .map(|e| e.into_path())
}

fn docker_run(args: &[String]) -> bool {
    println!("docker {}", args.join(" "));
    let output = cmd("docker", args)
        .env("DOCKER_BUILDKIT", "1")
        .stderr_to_stdout()
        .stdout_capture()
        .unchecked()
        .run();

    if let Ok(out) = output {
        println!("{}", &String::from_utf8_lossy(&out.stdout));
        if out.status.success() {
            return true;
        }
        return false;
    } else {
        eprintln!("Failed to execute command: 'docker {}'", args.join(" "));
        return false;
    };
}

fn build_dir_init(kind: &GenType, name: &str) -> Result<PathBuf, i32> {
    let prefix = match kind {
        GenType::Target => "targets",
        GenType::Package => "packages",
    };

    let path: PathBuf = [&get_environment("TENCENT_STATE_DIR")?, prefix, name]
        .iter()
        .collect();

    if let Err(e) = fs::create_dir_all(&path) {
        eprintln!(
            "Failed to create directory '{}': {}",
            &path.as_path().display(),
            e
        );
        return Err(1);
    }

    Ok(path)
}

fn post_setup<P>(build_dir: P, output_dir: P) -> bool
where
    P: AsRef<Path>,
{
    /* find the rpm package that without txbuild_marker*/
    fn is_artifact(entry: &DirEntry) -> bool {
        entry.file_type().is_file()
            && entry
                .file_name()
                .to_str()
                .map(|s| !s.ends_with(TX_EXTENSION))
                .unwrap_or(false)
    }

    /* artifact is pathBuf */
    for artifact in get_files(&build_dir, is_artifact) {
        let mut marker = artifact.clone().into_os_string();

        /* create txbuild_marker */
        marker.push(TX_EXTENSION);
        let filename = if let Ok(filename) = marker.into_string() {
            filename
        } else {
            eprintln!("create marker:{} name failed", artifact.as_path().display());
            return false;
        };

        let marker_file = Path::new(&filename);
        if let Err(e) = File::create(&marker_file) {
            eprintln!("create marker file {} failed: {}", marker_file.display(), e);
        }

        /* get rpm path */
        let mut output_file: PathBuf = output_dir.as_ref().into();
        if let Some(os_str) = artifact.as_path().file_name() {
            if let Some(artifact_file) = os_str.to_str() {
                output_file.push(artifact_file);
            }
        }

        /* move rpm package to destination */
        if let Err(e) = fs::rename(&artifact.as_path(), &output_file) {
            eprintln!(
                "move rpm {} to {} failed: {}",
                artifact.as_path().display(),
                output_file.as_path().display(),
                e
            );
        }
    }

    return true;
}

fn pre_setup<P>(build_dir: P, output_dir: P) -> bool
where
    P: AsRef<Path>,
{
    /* find the file that end with txbuild_marker */
    fn is_marker(entry: &DirEntry) -> bool {
        entry
            .file_name()
            .to_str()
            .map(|s| s.ends_with(TX_EXTENSION))
            .unwrap_or(false)
    }

    /* fearch build/state/{package/targets} to find txbuild_marker */
    for marker in get_files(&build_dir, is_marker) {
        let mut output_file: PathBuf = output_dir.as_ref().into();

        /* if rpm exists, remove it */
        if let Some(os_str) = marker.as_path().file_name() {
            if let Some(marker_file) = os_str.to_str() {
                output_file.push(marker_file);
                output_file.set_extension("");

                /* remove rpm */
                if output_file.exists() {
                    if let Err(e) = std::fs::remove_file(&output_file) {
                        eprintln!(
                            "remove file '{}' failed: {}",
                            output_file.as_path().display(),
                            e
                        );
                    }
                }
            }
        }

        /* remove txbuild_marker */
        if let Err(e) = std::fs::remove_file(&marker.as_path()) {
            eprintln!("remove file '{}' failed: {}", marker.as_path().display(), e);
        }
    }

    return true;
}

fn docker_start(
    kind: GenType,
    what: &str,
    add_args: Vec<String>,
    tag: &str,
    output_dir: &PathBuf,
) -> bool {
    let sdk = get_env!("TENCENT_SDK_IMAGE");
    let root = get_env!("TENCENT_ROOT_DIR");
    let ssh_key = get_env!("TENCENT_GIT_SSH_KEY");
    let dockerfile = get_env!("TENCENT_DOCKERFILE");

    let target = match kind {
        GenType::Target => "target",
        GenType::Package => "package",
    };

    if let Err(e) = env::set_current_dir(&root) {
        eprintln!("Can't change current dir '{}' {}\n", root, e);
        return false;
    }

    let token = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(n) => n.as_secs().to_string(),
        Err(_) => return false,
    };

    let build_dir = match build_dir_init(&kind, &what) {
        Ok(dir) => dir,
        Err(_) => return false,
    };

    let tag = format!("{}-{}", tag, token);
    let mut build = format!(
        "buildx \
        build -f {dockerfile} . \
        --network host \
        --allow security.insecure \
        --load \
        --ssh git_code={ssh_key} \
        --target {target} \
        --tag {tag}",
        dockerfile = dockerfile,
        ssh_key = ssh_key,
        target = target,
        tag = tag,
    )
    .split_string();

    build.extend(add_args);
    build.add_arg("SDK", sdk);
    build.add_arg("TOKEN", token);

    let rm = format!("rm --force {}", tag).split_string();
    let rmi = format!("rmi --force {}", tag).split_string();
    let create = format!("create --name {} {} true", tag, tag).split_string();
    let cp = format!("cp {}:/output/. {}", tag, build_dir.display()).split_string();

    pre_setup(&build_dir, &output_dir);

    docker_run(&rm);
    docker_run(&rmi);
    if !docker_run(&build) {
        return false;
    }

    if !docker_run(&create) {
        return false;
    }
    if !docker_run(&cp) {
        return false;
    }

    docker_run(&rm);
    docker_run(&rmi);

    if !post_setup(&build_dir, &output_dir) {
        return false;
    }

    return true;
}

impl PackageProducer {
    pub(crate) fn generate(package: &str, arch: &str) -> bool {
        let mut args = Vec::new();
        let target = get_env!("TENCENT_TARGET");
        let arch2arch: String = get_env!("TENCENT_ARCH2ARCH").into();
        let output_dir: PathBuf = get_env!("TENCENT_RPM_PACKAGES").into();

        args.add_arg("ARCH", arch);
        args.add_arg("TARGET", target);
        args.add_arg("PACKAGE", package);
        args.add_arg("ARCH2ARCH", arch2arch);

        let tag = format!(
            "{arch}-txbuild-pkg-{package}",
            package = package,
            arch = arch,
        );
        let safe_tag = str::replace(tag.as_ref(), "+", "-");

        if !docker_start(GenType::Package, &package, args, &safe_tag, &output_dir) {
            return false;
        }

        return true;
    }
}

impl TargetProducer {
    pub(crate) fn generate(
        packages: &[String],
        image_format: Option<&ImageFormat>,
        kversion: &String,
    ) -> bool {
        let mut args = Vec::new();
        let arch = get_env!("TENCENT_ARCH");
        let target = get_env!("TENCENT_TARGET");
        let tencent_name = get_env!("TENCENT_NAME");
        let tencent_pname = get_env!("TENCENT_PRETTY_NAME");
        let tencent_version = get_env!("TENCENT_VERSION_IMAGE");
        let output_dir: PathBuf = get_env!("TENCENT_OUTPUT_DIR").into();

        let img_format = match image_format {
            Some(ImageFormat::Vmdk) => "vmdk",
            Some(ImageFormat::Qcow2) => "qcow2",
            Some(ImageFormat::Raw) | None => "raw",
        };

        args.add_arg("ARCH", &arch);
        args.add_arg("TARGET", &target);
        args.add_arg("IMAGE_FORMAT", img_format);
        args.add_arg("KERNEL_VERSION", kversion);
        args.add_arg("IMAGE_NAME", tencent_name);
        args.add_arg("PRETTY_NAME", tencent_pname);
        args.add_arg("VERSION_ID", tencent_version);
        args.add_arg("PACKAGES", packages.join(" "));

        let tag = format!("{arch}-txbuild-{target}", target = target, arch = arch);
        let safe_tag = str::replace(tag.as_ref(), "+", "-");

        if !docker_start(GenType::Target, &target, args, &safe_tag, &output_dir) {
            return false;
        }

        return true;
    }
}
