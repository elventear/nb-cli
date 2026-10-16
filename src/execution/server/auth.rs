//! Authentication helpers shared by the REST and WebSocket clients.
//!
//! The token is always sent as an `Authorization: token <t>` header, never as
//! a `?token=` URL parameter. JupyterHub >= 5 single-user servers reject URL
//! tokens (`HubAuth.allow_token_in_url = False`), and URL tokens leak into
//! proxy and access logs. Plain Jupyter Server accepts the header too.
//!
//! An empty token sends no header at all.

use anyhow::{Context, Result};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, handshake::client::Request};

/// Value for the `Authorization` header, or `None` for an empty token.
pub fn header_value(token: &str) -> Result<Option<HeaderValue>> {
    if token.is_empty() {
        return Ok(None);
    }
    let mut value = HeaderValue::from_str(&format!("token {}", token))
        .context("Token contains characters that are not valid in an HTTP header")?;
    value.set_sensitive(true);
    Ok(Some(value))
}

/// Default headers for a `reqwest::Client` talking to the server.
pub fn default_headers(token: &str) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    if let Some(value) = header_value(token)? {
        headers.insert(AUTHORIZATION, value);
    }
    Ok(headers)
}

/// Add the `Authorization` header to a single request.
pub fn authorize(request: reqwest::RequestBuilder, token: &str) -> Result<reqwest::RequestBuilder> {
    Ok(match header_value(token)? {
        Some(value) => request.header(AUTHORIZATION, value),
        None => request,
    })
}

/// Build a WebSocket upgrade request carrying the `Authorization` header.
pub fn ws_request(ws_url: &str, token: &str) -> Result<Request> {
    let mut request = ws_url
        .into_client_request()
        .context("Invalid WebSocket URL")?;
    if let Some(value) = header_value(token)? {
        request.headers_mut().insert(AUTHORIZATION, value);
    }
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_token_sends_no_header() {
        assert!(header_value("").unwrap().is_none());
        assert!(default_headers("").unwrap().is_empty());
        let req = ws_request("ws://host/api/x", "").unwrap();
        assert!(req.headers().get(AUTHORIZATION).is_none());
    }

    #[test]
    fn token_uses_token_scheme() {
        let value = header_value("abc").unwrap().unwrap();
        assert_eq!(value.to_str().unwrap(), "token abc");
        assert!(value.is_sensitive());
        let headers = default_headers("abc").unwrap();
        assert_eq!(headers.get(AUTHORIZATION).unwrap(), "token abc");
        let req = ws_request("ws://host/api/x", "abc").unwrap();
        assert_eq!(req.headers().get(AUTHORIZATION).unwrap(), "token abc");
        // No token in the URL.
        assert_eq!(req.uri().to_string(), "ws://host/api/x");
    }

    #[test]
    fn invalid_token_is_an_error() {
        assert!(header_value("bad\ntoken").is_err());
    }
}
