#!/usr/bin/env run-cargo-script
//! ```cargo
//! [dependencies]
//! cc = "=1.0.22"
//! clap = "=2.27.1"
//! colored = "1.6.0"
//! flate2 = "1.0.7"
//! heck = "0.3.0"
//! tar = "0.4.22"
//! toml = "0.4.5"
//! walkdir = "2.0.1"
//! zip = "=0.2.6"
//! ```
extern crate clap;
extern crate colored;
extern crate flate2;
extern crate heck;
extern crate tar;
extern crate toml;
extern crate walkdir;
extern crate zip;

use clap::{App, Arg};
use colored::*;
use flate2::write::GzEncoder;
use flate2::Compression;
use heck::ShoutySnakeCase;
use std::env;
use std::fs::File;
use std::io::{self, Read};
use std::iter;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str;
use walkdir::WalkDir;
use zip::write::FileOptions;
use zip::ZipWriter;

const TARGET_LINUX_X86: &str = "i686-unknown-linux-gnu";
const TARGET_LINUX_X64: &str = "x86_64-unknown-linux-gnu";
const TARGET_OSX_X86: &str = "i686-apple-darwin";
const TARGET_OSX_X64: &str = "x86_64-apple-darwin";
const TARGET_WINDOWS_X86: &str = "i686-pc-windows-gnu";
const TARGET_WINDOWS_X64: &str = "x86_64-pc-windows-gnu";
const TARGET_IOS_X64: &str = "x86_64-apple-ios";
const TARGET_IOS_ARM64: &str = "aarch64-apple-ios";
const TARGET_ANDROID_X86: &str = "i686-linux-android";
const TARGET_ANDROID_ARMEABIV7A: &str = "armv7-linux-androideabi";

const CRATES: &[&str] = &["safe_app", "safe_authenticator"];

const ARCHS: &[Arch] = &[
    Arch {
        name: "linux-x86",
        target: TARGET_LINUX_X86,
        toolchain: "",
    },
    Arch {
        name: "linux-x64",
        target: TARGET_LINUX_X64,
        toolchain: "",
    },
    Arch {
        name: "osx-x86",
        target: TARGET_OSX_X86,
        toolchain: "",
    },
    Arch {
        name: "osx-x64",
        target: TARGET_OSX_X64,
        toolchain: "",
    },
    Arch {
        name: "win-x86",
        target: TARGET_WINDOWS_X86,
        toolchain: "",
    },
    Arch {
        name: "win-x64",
        target: TARGET_WINDOWS_X64,
        toolchain: "",
    },
    Arch {
        name: "android-armeabiv7a",
        target: TARGET_ANDROID_ARMEABIV7A,
        toolchain: "arm-linux-androideabi-",
    },
    Arch {
        name: "android-x86",
        target: TARGET_ANDROID_X86,
        toolchain: "i686-linux-android-",
    },
    Arch {
        name: "ios-arm64",
        target: TARGET_IOS_ARM64,
        toolchain: "",
    },
    Arch {
        name: "ios-x86_64",
        target: TARGET_IOS_X64,
        toolchain: "",
    },
];

#[cfg(all(target_os = "linux", target_arch = "x86"))]
const HOST_ARCH_NAME: &str = "linux-x86";
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const HOST_ARCH_NAME: &str = "linux-x64";
#[cfg(all(target_os = "macos", target_arch = "x86"))]
const HOST_ARCH_NAME: &str = "osx-x86";
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
const HOST_ARCH_NAME: &str = "osx-x64";
#[cfg(all(target_os = "windows", target_arch = "x86"))]
const HOST_ARCH_NAME: &str = "win-x86";
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
const HOST_ARCH_NAME: &str = "win-x64";

const BINDINGS_LANGS: &[&str] = &["csharp"];

const COMMIT_HASH_LEN: usize = 7;

fn main() {
    let arch_names: Vec<_> = ARCHS
        .into_iter()
        .map(|args| args.name)
        .chain(iter::once("ios"))
        .collect();

    // Parse command line arguments.
    let matches = App::new("safe_client_libs packaging tool")
        .arg(
            Arg::with_name("NAME")
                .short("n")
                .long("name")
                .takes_value(true)
                .possible_values(CRATES)
                .required(true)
                .help("Name of the crate to package"),
        )
        .arg(Arg::with_name("COMMIT").short("c").long("commit").help(
            "Uses commit hash instead of version string in the package name",
        ))
        .arg(
            Arg::with_name("REBUILD")
                .short("r")
                .long("rebuild")
                .takes_value(false)
                .required(false)
                .help("If true a cargo build will run and output the artifacts to target/<arch>")
        )
        .arg(
            Arg::with_name("ARCH")
                .short("a")
                .long("arch")
                .takes_value(true)
                .possible_values(&arch_names)
                .help("Target platform and architecture"),
        )
        .arg(Arg::with_name("LIB").short("l").long("lib").help(
            "Generates library package",
        ))
        .arg(
            Arg::with_name("BINDINGS")
                .short("b")
                .long("bindings")
                .help("Generates bindings package"),
        )
        .arg(Arg::with_name("MOCK").short("m").long("mock").help(
            "Generates mock version of the library",
        ))
        .arg(
            Arg::with_name("TOOLCHAIN")
                .short("t")
                .long("toolchain")
                .takes_value(true)
                .help("Path to the toolchain (for cross-compilation)"),
        )
        .arg(
            Arg::with_name("DEST")
                .short("d")
                .long("dest")
                .takes_value(true)
                .help("Destination directory (uses current dir by default)"),
        )
        .arg(
            Arg::with_name("STRIP")
                .short("s")
                .long("strip")
                .takes_value(false)
                .help("Specify this flag for running GNU strip on the binaries before they are packaged.")
        )
        .arg(
            Arg::with_name("ARTIFACTS")
                .short("a")
                .long("artifacts")
                .takes_value(true)
                .help("Directory containing the artifacts to package. If not specified, the CARGO_TARGET_DIR
                      variable will be queried for its value, and if that's not set, we will assume the 'target'
                      directory in the current directory."),
        )
        .get_matches();

    let krate = matches.value_of("NAME").unwrap();
    let rebuild = matches.is_present("REBUILD");
    let version_string = get_version_string(krate, matches.is_present("COMMIT"));

    let arch_name = matches.value_of("ARCH").unwrap_or(HOST_ARCH_NAME);
    let arch = find_arch(arch_name);

    let dest_dir = matches.value_of("DEST").unwrap_or(".");
    let bindings = matches.is_present("BINDINGS");
    let lib = matches.is_present("LIB");
    let mock = matches.is_present("MOCK");
    let strip = matches.is_present("STRIP");

    let toolchain_path = matches.value_of("TOOLCHAIN");
    let target_dir = if matches.is_present("ARTIFACTS") {
        matches.value_of("ARTIFACTS").unwrap().to_string()
    } else {
        env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string())
    };

    let file_options = FileOptions::default();

    setup_env(toolchain_path, arch);

    // Gather features.
    let mut features = vec![];
    if mock {
        features.push("use-mock-routing");
        features.push("testing");
    }
    if matches.is_present("BINDINGS") {
        features.push("bindings");
    }

    // Run the build.
    let mut libs = Vec::new();
    if arch_name == "ios" {
        // iOS fat library.
        let mut arch_libs = ["ios-arm64", "ios-x86_64"]
            .into_iter()
            .flat_map(|arch_name| {
                let arch = find_arch(arch_name).unwrap();
                let target = &arch.target;

                if rebuild {
                    if !build(krate, &features, Some(target)) {
                        return Vec::new();
                    }
                }

                if !lib {
                    return Vec::new();
                }

                let libs = if rebuild {
                    find_libs(krate, Some(target), &target_dir)
                } else {
                    find_libs(krate, None, &target_dir)
                };
                if strip {
                    strip_libs(toolchain_path, Some(arch), &libs);
                }
                libs
            }).peekable();

        if arch_libs.peek().is_some() {
            let lib_name = format!("lib{}.a", krate);
            lipo(arch_libs, &lib_name);
            libs.push(PathBuf::from(lib_name));
        }
    } else {
        // Normal library
        let target = arch.map(|arch| arch.target);
        if rebuild {
            if !build(krate, &features, target) {
                return;
            }
        }

        if lib {
            let arch_libs = if rebuild {
                find_libs(krate, target, &target_dir)
            } else {
                find_libs(krate, None, &target_dir)
            };
            if strip {
                strip_libs(toolchain_path, arch, &arch_libs);
            }
            libs.extend_from_slice(&arch_libs)
        }
    }

    if !libs.is_empty() {
        package_artifacts_as_zip(
            &arch_name,
            &krate,
            &dest_dir,
            &libs,
            &version_string,
            mock,
            file_options,
        );
        package_artifacts_as_tar_gz(&arch_name, &krate, &dest_dir, &libs, &version_string, mock);
    }

    // Create bindings archive.
    if bindings {
        let archive_name = format!("{}-bindings-{}.zip", krate, version_string);
        let path: PathBuf = [dest_dir, &archive_name].iter().collect();

        let file = File::create(path).unwrap();
        let mut archive = ZipWriter::new(file);

        for lang in BINDINGS_LANGS {
            let source_prefix = Path::new("bindings").join(lang).join(krate);
            let target_prefix = Path::new(lang);

            for entry in WalkDir::new(&source_prefix) {
                let entry = entry.unwrap();
                let target_path =
                    target_prefix.join(entry.path().strip_prefix(&source_prefix).unwrap());
                let target_path = path_into_string(target_path);

                if entry.file_type().is_dir() {
                    archive.add_directory(target_path, file_options).unwrap();
                } else {
                    archive.start_file(target_path, file_options).unwrap();

                    let mut file = File::open(entry.path()).unwrap();
                    io::copy(&mut file, &mut archive).unwrap();
                }
            }
        }
    }
}

struct Arch {
    name: &'static str,
    target: &'static str,
    toolchain: &'static str,
}

fn package_artifacts_as_zip(
    arch_name: &str,
    krate: &str,
    dest_dir: &str,
    libs: &[PathBuf],
    version_string: &str,
    mock: bool,
    file_options: FileOptions,
) {
    let archive_name = get_archive_name(&arch_name, &krate, "zip", &version_string, mock);
    let path: PathBuf = [dest_dir, &archive_name].iter().collect();
    let file = File::create(path).unwrap();
    let mut archive = ZipWriter::new(file);
    for path in libs {
        println!("Adding {:?} to {:?}", path, archive_name);
        archive
            .start_file(path.file_name().unwrap().to_string_lossy(), file_options)
            .unwrap();
        let mut file = File::open(path).unwrap();
        io::copy(&mut file, &mut archive).unwrap();
    }
}

fn package_artifacts_as_tar_gz(
    arch_name: &str,
    krate: &str,
    dest_dir: &str,
    libs: &[PathBuf],
    version_string: &str,
    mock: bool,
) {
    let archive_name = get_archive_name(&arch_name, &krate, "tar.gz", &version_string, mock);
    let path: PathBuf = [dest_dir, &archive_name].iter().collect();
    let file = File::create(path).unwrap();
    let enc = GzEncoder::new(file, Compression::default());
    let mut archive = tar::Builder::new(enc);
    for path in libs {
        println!("Adding {:?} to {:?}", path, archive_name);
        archive
            .append_path_with_name(path, Path::new(path).file_name().unwrap().to_str().unwrap())
            .unwrap();
    }
}

fn get_archive_name(
    arch_name: &str,
    krate: &str,
    archive_type: &str,
    version_string: &str,
    mock: bool,
) -> String {
    let mock = if mock { "-mock" } else { "" };
    format!(
        "{}{}-{}-{}.{}",
        krate, mock, version_string, arch_name, archive_type
    )
}

fn get_version_string(krate: &str, commit: bool) -> String {
    if commit {
        // Get the current commit hash.
        let output = Command::new("git")
            .arg("rev-parse")
            .arg("HEAD")
            .output()
            .expect("failed to run git");

        str::from_utf8(&output.stdout).unwrap().trim()[0..COMMIT_HASH_LEN].to_string()
    } else {
        // Extract the version string from Cargo.toml
        use toml::Value;

        let mut file =
            File::open(Path::new(krate).join("Cargo.toml")).expect("failed to open Cargo.toml");
        let mut content = String::new();
        file.read_to_string(&mut content)
            .expect("failed to read Cargo.toml");

        let toml = content
            .parse::<Value>()
            .expect("failed to parse Cargo.toml");
        toml["package"]["version"]
            .as_str()
            .expect("failed to read package version from Cargo.toml")
            .to_string()
    }
}

fn get_toolchain_bin(toolchain_path: Option<&str>, arch: Option<&Arch>, bin: &str) -> String {
    let mut result = PathBuf::new();

    if let Some(path) = toolchain_path {
        result.push(path);
        result.push("bin");
    }

    let prefix = arch.map(|arch| arch.toolchain).unwrap_or("");

    result.push(format!("{}{}", prefix, bin));
    result.into_os_string().into_string().unwrap()
}

fn find_arch(name: &str) -> Option<&Arch> {
    ARCHS.into_iter().find(|arch| arch.name == name)
}

fn setup_env(toolchain_path: Option<&str>, arch: Option<&Arch>) {
    let arch = if let Some(arch) = arch { arch } else { return };

    let name = format!("CARGO_TARGET_{}_LINKER", arch.target.to_shouty_snake_case());

    let value = if let Some(toolchain_path) = toolchain_path {
        let value = get_toolchain_bin(Some(toolchain_path), Some(arch), "gcc");

        println!(
            "{}: setting environment variable {} to {}",
            "notice".green().bold(),
            name.bold(),
            value.bold()
        );

        env::set_var(&name, &value);
        Some(value)
    } else {
        env::var(&name).ok()
    };

    if let Some(value) = value {
        if !Path::new(&value).exists() {
            println!(
                "{}: the environment variable {} is set, but points to \
                 non-existing file {}. This might cause linker failures.",
                "warning".yellow().bold(),
                name.bold(),
                value.bold(),
            );
        }
    } else {
        println!(
            "{}: the environment variable {} is not set. \
             This might cause linker failure.",
            "warning".yellow().bold(),
            name.bold()
        );
    }
}

fn build(krate: &str, features: &[&str], target: Option<&str>) -> bool {
    let mut command = Command::new("cargo");
    command
        .arg("build")
        .arg("--verbose")
        .arg("--release")
        .arg("--manifest-path")
        .arg(format!("{}/Cargo.toml", krate));

    if !features.is_empty() {
        command.arg("--features").arg(features.join(","));
    }

    if let Some(target) = target {
        command.arg("--target").arg(target);
    }

    command.status().unwrap().success()
}

fn find_libs(krate: &str, target: Option<&str>, target_dir: &str) -> Vec<PathBuf> {
    let mut prefix = PathBuf::from(target_dir);
    if let Some(target) = target {
        prefix = prefix.join(target);
    }
    prefix = prefix.join("release");

    let mut result = Vec::with_capacity(1);

    // linux,osx - static
    let path = prefix.join(format!("lib{}.a", krate));
    if path.exists() && is_static_lib_required(target) {
        result.push(path);
    }

    // linux - dynamic
    let path = prefix.join(format!("lib{}.so", krate));
    if path.exists() {
        result.push(path);
    }

    // osx - dynamic
    let path = prefix.join(format!("lib{}.dylib", krate));
    if path.exists() {
        result.push(path);
    }

    // windows - dynamic
    let path = prefix.join(format!("{}.dll", krate));
    if path.exists() {
        result.push(path);
    }

    if result.is_empty() {
        panic!("No libs found in {}/release", target_dir)
    }

    result
}

fn strip_libs(toolchain_path: Option<&str>, arch: Option<&Arch>, libs: &[PathBuf]) {
    let strip_bin = get_toolchain_bin(toolchain_path, arch, "strip");

    for path in libs {
        strip_lib(&strip_bin, path);
    }
}

fn strip_lib(strip_bin: &str, lib_path: &Path) {
    let mut command = Command::new(strip_bin);

    // On OS X `strip` does not remove global symbols without this flag.
    if cfg!(target_os = "macos") {
        command.arg("-x");
    }

    command.arg(lib_path);

    if !command.status().expect("failed to run strip").success() {
        panic!("failed to strip {}", lib_path.display());
    }
}

fn lipo<I: IntoIterator<Item = PathBuf>>(libs: I, output: &str) {
    let mut command = Command::new("lipo");
    command.arg("-create");

    for lib in libs {
        command.arg(lib);
    }

    if !command
        .arg("-output")
        .arg(output)
        .status()
        .expect("failed to run lipo")
        .success()
    {
        panic!("failed to run lipo");
    }
}

fn path_into_string(path: PathBuf) -> String {
    path.into_os_string()
        .into_string()
        .unwrap()
        .replace('\\', "/")
}

fn is_static_lib_required(target: Option<&str>) -> bool {
    match target {
        Some(TARGET_IOS_ARM64) | Some(TARGET_IOS_X64) => true,
        Some(_) | None => false,
    }
}
