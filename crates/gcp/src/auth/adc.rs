//! The enumerated Application Default Credentials subset: which source
//! `TokenProvider::from_environment` picks, and how a credential file parses.
//!
//! Everything here is local and synchronous — env vars and file reads only.
//! No source is contacted until the first `token()`.

use std::io;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::DecodePaddingMode;
use base64::Engine as _;
use serde_json::{Map, Value};

use super::error::GcpAuthError;
use super::user::AuthorizedUser;
use super::{CredentialSource, Source};

/// The env var naming a credential file (google-auth's `CREDENTIALS`).
pub const GOOGLE_APPLICATION_CREDENTIALS: &str = "GOOGLE_APPLICATION_CREDENTIALS";
/// The env var that overrides a credential file's `quota_project_id`.
pub const GOOGLE_CLOUD_QUOTA_PROJECT: &str = "GOOGLE_CLOUD_QUOTA_PROJECT";
/// The env var gcloud reads its configuration directory from, when set.
pub const CLOUDSDK_CONFIG: &str = "CLOUDSDK_CONFIG";
/// The ADC file's name inside gcloud's configuration directory.
const WELL_KNOWN_FILE: &str = "application_default_credentials.json";

/// Where `TokenProvider::from_environment_with` reads env vars and files.
///
/// The seam that keeps tests off the process environment (`set_var` in a
/// test races every other test in the binary — see the workspace
/// CLAUDE.md). [`ProcessEnvironment`] is the real one.
pub trait AdcEnvironment {
    /// The value of env var `name`, or `None` when unset. `Some("")` is a
    /// set-but-empty variable: for `GOOGLE_APPLICATION_CREDENTIALS` that is a
    /// configured, broken source (google-auth tests `is None` too); for the
    /// directory and quota variables it counts as unset.
    fn var(&self, name: &str) -> Option<String>;

    /// The contents of the file at `path`. An [`io::ErrorKind::NotFound`]
    /// error means "absent" for the gcloud well-known file (the chain moves
    /// on) and "broken" for a file an env var names (construction fails).
    fn read_file(&self, path: &Path) -> io::Result<Vec<u8>>;
}

/// [`AdcEnvironment`] over the real process: `std::env` and `std::fs`.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessEnvironment;

impl AdcEnvironment for ProcessEnvironment {
    fn var(&self, name: &str) -> Option<String> {
        // Lossy rather than `std::env::var(..).ok()`: a set-but-non-UTF-8
        // value must not read as unset, or a GOOGLE_APPLICATION_CREDENTIALS
        // path that cannot be represented would fall through to another
        // identity. Lossy, it names a file that does not exist, and
        // construction fails.
        std::env::var_os(name).map(|value| value.to_string_lossy().into_owned())
    }

    fn read_file(&self, path: &Path) -> io::Result<Vec<u8>> {
        std::fs::read(path)
    }
}

/// A parsed credential, before any network I/O.
pub(crate) struct Resolved {
    pub(crate) source: Source,
    pub(crate) origin: CredentialSource,
    pub(crate) quota_project: Option<String>,
}

/// Walk the chain: explicit base64, `GOOGLE_APPLICATION_CREDENTIALS`, the
/// gcloud well-known file, the metadata server. An absent source moves on; a
/// configured one that fails stops the walk with its error.
///
/// "Configured" is `Some` for the argument and set for the env var — an
/// empty value included. Mapping an empty env var of its own to `None` is the
/// caller's business; here an empty value is a mistake, not an absence.
pub(crate) fn resolve(
    explicit_b64: Option<&str>,
    env: &dyn AdcEnvironment,
) -> Result<Resolved, GcpAuthError> {
    let file = if let Some(b64) = explicit_b64 {
        let origin = "explicit base64 credentials";
        if b64.trim().is_empty() {
            return Err(GcpAuthError::invalid(origin, "is set but empty"));
        }
        let json =
            decode_base64(b64).ok_or_else(|| GcpAuthError::invalid(origin, "not valid base64"))?;
        Some((
            parse_credentials(&json, origin)?,
            CredentialSource::ExplicitBase64,
        ))
    } else if let Some(path) = env.var(GOOGLE_APPLICATION_CREDENTIALS) {
        if path.trim().is_empty() {
            return Err(GcpAuthError::invalid(
                GOOGLE_APPLICATION_CREDENTIALS,
                "is set but empty",
            ));
        }
        let origin = format!("{GOOGLE_APPLICATION_CREDENTIALS} file {path}");
        let json = env
            .read_file(Path::new(&path))
            .map_err(|error| GcpAuthError::invalid(&origin, read_failure(&error)))?;
        Some((
            parse_credentials(&json, &origin)?,
            CredentialSource::ApplicationCredentials,
        ))
    } else if let Some(path) = well_known_file(env) {
        let origin = format!("gcloud ADC file {}", path.display());
        match env.read_file(&path) {
            Ok(json) => Some((
                parse_credentials(&json, &origin)?,
                CredentialSource::GcloudDefault,
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(GcpAuthError::invalid(&origin, read_failure(&error))),
        }
    } else {
        None
    };

    let (source, origin, file_quota) = match file {
        Some((parsed, origin)) => (parsed.source, origin, parsed.quota_project),
        None => (Source::Metadata, CredentialSource::MetadataServer, None),
    };
    Ok(Resolved {
        source,
        origin,
        // google-auth's precedence: the env var beats the file, and it
        // applies to metadata-server credentials too (`_apply_quota_project_id`).
        quota_project: non_empty(env.var(GOOGLE_CLOUD_QUOTA_PROJECT)).or(file_quota),
    })
}

/// gcloud's ADC file: `$CLOUDSDK_CONFIG/application_default_credentials.json`
/// when `CLOUDSDK_CONFIG` is set (gcloud writes it there), else
/// `$HOME/.config/gcloud/application_default_credentials.json`. Unix layout
/// only: Windows' `%APPDATA%\gcloud` is not consulted, so on Windows the
/// chain goes from `GOOGLE_APPLICATION_CREDENTIALS` to the metadata server
/// unless `CLOUDSDK_CONFIG` is set.
fn well_known_file(env: &dyn AdcEnvironment) -> Option<PathBuf> {
    if let Some(config) = non_empty(env.var(CLOUDSDK_CONFIG)) {
        return Some(Path::new(&config).join(WELL_KNOWN_FILE));
    }
    let home = non_empty(env.var("HOME"))?;
    Some(
        Path::new(&home)
            .join(".config")
            .join("gcloud")
            .join(WELL_KNOWN_FILE),
    )
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.trim().is_empty())
}

/// An `io::Error`'s kind and OS message ("Permission denied (os error 13)"),
/// which name the failure and nothing of the file.
fn read_failure(error: &io::Error) -> String {
    if error.kind() == io::ErrorKind::NotFound {
        "the file does not exist".to_owned()
    } else {
        format!("the file cannot be read: {error}")
    }
}

/// Standard-alphabet base64, padding optional, ASCII whitespace ignored —
/// `base64 key.json` on Linux wraps at 76 columns, and Python's
/// `b64decode` (what imgmcp used) discards the newlines too. `None` on
/// failure: the decoder's error names a byte and an offset of the secret.
fn decode_base64(text: &str) -> Option<Vec<u8>> {
    const LENIENT: GeneralPurpose = GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
    let compact: String = text
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect();
    LENIENT.decode(compact).ok()
}

/// A credential file's contents, parsed and dispatched on its `type`.
pub(crate) struct ParsedCredentials {
    pub(crate) source: Source,
    pub(crate) quota_project: Option<String>,
}

/// Parse `json` as a credential of a supported `type`. `origin` names the
/// source in errors.
pub(crate) fn parse_credentials(
    json: &[u8],
    origin: &str,
) -> Result<ParsedCredentials, GcpAuthError> {
    let value: Value = serde_json::from_slice(json).map_err(|error| {
        GcpAuthError::invalid(
            origin,
            format!("not valid JSON ({})", crate::util::json_failure(&error)),
        )
    })?;
    let Value::Object(object) = value else {
        return Err(GcpAuthError::invalid(origin, "not a JSON object"));
    };
    let fields = Fields {
        object: &object,
        origin,
    };
    let kind = fields
        .optional("type")?
        .ok_or_else(|| GcpAuthError::invalid(origin, "has no `type` field"))?;
    let quota_project = fields.optional("quota_project_id")?;

    let source = match kind.as_str() {
        "authorized_user" => Source::AuthorizedUser(AuthorizedUser::parse(&fields)?),
        "service_account" => service_account(&fields)?,
        other => {
            return Err(GcpAuthError::Unsupported(format!(
                "credential type \"{}\" in {origin} is not supported (supported: service_account, authorized_user)",
                quotable_type(other)
            )))
        }
    };
    Ok(ParsedCredentials {
        source,
        quota_project,
    })
}

/// A credential `type` as it may appear in an error: itself when it is a
/// plain `[a-z_]{1,64}` name (`external_account`, …), else a placeholder —
/// a file whose `type` is something else may not be what it claims at all.
fn quotable_type(kind: &str) -> &str {
    let plain = (1..=64).contains(&kind.len())
        && kind
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_');
    if plain {
        kind
    } else {
        "<unrecognized>"
    }
}

#[cfg(feature = "service-account-key")]
fn service_account(fields: &Fields<'_>) -> Result<Source, GcpAuthError> {
    Ok(Source::ServiceAccount(super::sa::ServiceAccountKey::parse(
        fields,
    )?))
}

#[cfg(not(feature = "service-account-key"))]
fn service_account(_fields: &Fields<'_>) -> Result<Source, GcpAuthError> {
    Err(GcpAuthError::Unsupported(
        super::SERVICE_ACCOUNT_NOT_COMPILED_IN.to_owned(),
    ))
}

/// Typed access to a credential object's string fields, with errors that
/// name the field and never its value.
pub(crate) struct Fields<'a> {
    object: &'a Map<String, Value>,
    pub(crate) origin: &'a str,
}

impl Fields<'_> {
    /// The field's value; absent, `null` or empty is `None`.
    pub(crate) fn optional(&self, field: &str) -> Result<Option<String>, GcpAuthError> {
        match self.object.get(field) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(value)) if value.is_empty() => Ok(None),
            Some(Value::String(value)) => Ok(Some(value.clone())),
            Some(_) => Err(GcpAuthError::invalid(
                self.origin,
                format!("field `{field}` is not a string"),
            )),
        }
    }

    /// The field's value, which must be a non-empty string.
    pub(crate) fn required(&self, field: &str) -> Result<String, GcpAuthError> {
        self.optional(field)?.ok_or_else(|| {
            GcpAuthError::invalid(self.origin, format!("field `{field}` is missing or empty"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_tolerates_wrapping_and_missing_padding() {
        assert_eq!(decode_base64("e30=").as_deref(), Some(&b"{}"[..]));
        assert_eq!(decode_base64("e30").as_deref(), Some(&b"{}"[..]));
        assert_eq!(decode_base64(" e3\n0=\r\n").as_deref(), Some(&b"{}"[..]));
        assert_eq!(decode_base64("!!!"), None);
        // URL-safe characters are not the standard alphabet.
        assert_eq!(decode_base64("-_-_"), None);
    }

    #[test]
    fn the_well_known_file_follows_cloudsdk_config_then_home() {
        struct Env(Vec<(&'static str, &'static str)>);
        impl AdcEnvironment for Env {
            fn var(&self, name: &str) -> Option<String> {
                self.0
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| (*value).to_owned())
            }
            fn read_file(&self, _: &Path) -> io::Result<Vec<u8>> {
                unreachable!()
            }
        }

        assert_eq!(
            well_known_file(&Env(vec![("HOME", "/home/u")])),
            Some(PathBuf::from(
                "/home/u/.config/gcloud/application_default_credentials.json"
            ))
        );
        assert_eq!(
            well_known_file(&Env(vec![("HOME", "/home/u"), ("CLOUDSDK_CONFIG", "/cfg")])),
            Some(PathBuf::from("/cfg/application_default_credentials.json"))
        );
        assert_eq!(well_known_file(&Env(vec![("HOME", "")])), None);
        assert_eq!(well_known_file(&Env(vec![])), None);
    }
}
