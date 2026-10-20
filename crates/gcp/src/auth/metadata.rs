//! The GCE / Cloud Run metadata server: the runtime service account's token
//! is one GET away, so production needs no key at all.

use std::sync::atomic::AtomicU16;

use super::error::GcpAuthError;
use super::{exchange, Fetched, TokenOptions};
use crate::util::Failed;

/// The metadata server's base URL. Plain HTTP by design: it is link-local and
/// the `Metadata-Flavor` header is its CSRF guard.
pub const DEFAULT_METADATA_BASE_URL: &str = "http://metadata.google.internal";

const TOKEN_PATH: &str = "/computeMetadata/v1/instance/service-accounts/default/token";

/// The request that both proves the caller is on the instance and names the
/// scopes. Without the header the server answers 403.
pub(crate) async fn fetch(
    http: &reqwest::Client,
    scopes: &[String],
    options: &TokenOptions,
    status_line: &AtomicU16,
) -> Result<Fetched, Failed<GcpAuthError>> {
    let mut url = format!(
        "{}{TOKEN_PATH}",
        options.metadata_base_url.trim_end_matches('/')
    );
    if !scopes.is_empty() {
        let scopes: Vec<String> = scopes
            .iter()
            .map(|scope| crate::util::encode_component(scope))
            .collect();
        url.push_str("?scopes=");
        url.push_str(&scopes.join(","));
    }
    let request = http.get(&url).header("Metadata-Flavor", "Google");
    exchange(request, &url, options.metadata_timeout, status_line).await
}
