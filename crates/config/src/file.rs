//! Layered file loading: parse a YAML or JSON file into a caller-supplied
//! type, with field-pathed error messages courtesy of `serde_path_to_error`
//! (so "which nested field was wrong" survives into the error instead of
//! collapsing to a bare `serde_yaml`/`serde_json` message), plus the
//! resolved base directory so callers can locate sibling files referenced
//! relative to the config (e.g. a TLS bundle path, a contract file).
//!
//! This generalizes limen's `config::load::load` (which hardcoded one
//! `Config` type and one format, YAML) over any `DeserializeOwned` type and
//! exposes both YAML and JSON as separate functions — no by-extension format
//! dispatch, so there is no surprise when a `.yml` file is fed to the JSON
//! loader or vice versa.

use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use thiserror::Error;

/// A value deserialized from a file, plus the directory the file lived in.
#[derive(Debug, Clone)]
pub struct Loaded<T> {
    /// The deserialized value.
    pub value: T,
    /// The directory containing the loaded file: `path.parent()`, or `.` if
    /// the path has no parent component (e.g. a bare filename).
    pub base_dir: PathBuf,
}

/// Errors from loading a config file.
#[derive(Debug, Error)]
pub enum FileError {
    /// The file could not be read.
    #[error("cannot read {path}: {source}")]
    Io {
        /// The path that failed to read.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// The file's contents did not deserialize into the target type.
    #[error("invalid {path}: {message}")]
    Parse {
        /// The path that failed to parse.
        path: PathBuf,
        /// A field-pathed message from `serde_path_to_error`.
        message: String,
    },
}

/// Load and parse a YAML file into `T`.
///
/// Note: any valid JSON document is also valid YAML 1.2, so a JSON file fed
/// to `load_yaml` parses successfully — that is a property of YAML, not a
/// dispatch bug. The separate functions exist so callers state the *intended*
/// format explicitly; use [`load_json`] when JSON-specific strictness
/// (trailing-content rejection) matters.
pub fn load_yaml<T: DeserializeOwned>(path: &Path) -> Result<Loaded<T>, FileError> {
    load_with(path, |text| {
        let de = serde_yaml::Deserializer::from_str(text);
        serde_path_to_error::deserialize(de).map_err(|e| e.to_string())
    })
}

/// Load and parse a JSON file into `T`. The entire file must be one JSON
/// document — trailing content after it is a parse error (`Deserializer::end`).
pub fn load_json<T: DeserializeOwned>(path: &Path) -> Result<Loaded<T>, FileError> {
    load_with(path, |text| {
        let mut de = serde_json::Deserializer::from_str(text);
        let value = serde_path_to_error::deserialize(&mut de).map_err(|e| e.to_string())?;
        de.end().map_err(|e| e.to_string())?;
        Ok(value)
    })
}

fn load_with<T>(
    path: &Path,
    parse: impl FnOnce(&str) -> Result<T, String>,
) -> Result<Loaded<T>, FileError> {
    let text = std::fs::read_to_string(path).map_err(|source| FileError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let value = parse(&text).map_err(|message| FileError::Parse {
        path: path.to_path_buf(),
        message,
    })?;
    Ok(Loaded {
        value,
        base_dir: resolve_base_dir(path),
    })
}

/// `path.parent()`, or `.` if the path has no parent component (e.g. a bare
/// filename like `config.yaml`, whose "parent" is an empty `PathBuf`).
fn resolve_base_dir(path: &Path) -> PathBuf {
    path.parent()
        .map(Path::to_path_buf)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq)]
    struct Nested {
        port: u16,
    }

    #[derive(Debug, Deserialize, PartialEq)]
    struct Sample {
        name: String,
        nested: Nested,
    }

    #[test]
    fn load_yaml_success_records_base_dir() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(&path, "name: svc\nnested:\n  port: 8080\n").unwrap();

        let loaded: Loaded<Sample> = load_yaml(&path).unwrap();
        assert_eq!(loaded.value.name, "svc");
        assert_eq!(loaded.value.nested.port, 8080);
        assert_eq!(loaded.base_dir, dir.path());
    }

    #[test]
    fn load_json_success_records_base_dir() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(&path, r#"{"name": "svc", "nested": {"port": 8080}}"#).unwrap();

        let loaded: Loaded<Sample> = load_json(&path).unwrap();
        assert_eq!(loaded.value.name, "svc");
        assert_eq!(loaded.value.nested.port, 8080);
        assert_eq!(loaded.base_dir, dir.path());
    }

    #[test]
    fn load_json_rejects_trailing_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(
            &path,
            r#"{"name": "svc", "nested": {"port": 8080}} trailing"#,
        )
        .unwrap();

        let err = load_json::<Sample>(&path).unwrap_err();
        assert!(matches!(err, FileError::Parse { .. }));
    }

    #[test]
    fn base_dir_defaults_to_dot_for_bare_filename() {
        // A relative path with no parent component (e.g. just "config.yaml")
        // should resolve to "." rather than an empty PathBuf. Exercised via
        // the pure helper directly (not load_yaml) so the test never has to
        // mutate the process-wide current directory.
        assert_eq!(resolve_base_dir(Path::new("bare.yaml")), PathBuf::from("."));
        assert_eq!(
            resolve_base_dir(Path::new("/a/b/config.yaml")),
            PathBuf::from("/a/b")
        );
    }

    #[test]
    fn nested_field_parse_failure_reports_field_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.yaml");
        // `nested.port` should be a number; giving it a string trips a parse
        // error whose message must carry the `nested.port` path.
        std::fs::write(&path, "name: svc\nnested:\n  port: \"not-a-number\"\n").unwrap();

        let err = load_yaml::<Sample>(&path).unwrap_err();
        match err {
            FileError::Parse { message, .. } => {
                assert!(
                    message.contains("nested") && message.contains("port"),
                    "message did not contain field path: {message}"
                );
            }
            other => panic!("expected Parse error, got {other:?}"),
        }
    }

    #[test]
    fn missing_file_is_io_error() {
        let path = PathBuf::from("/nonexistent/path/that/should/not/exist.yaml");
        let err = load_yaml::<Sample>(&path).unwrap_err();
        assert!(matches!(err, FileError::Io { .. }));
    }
}
