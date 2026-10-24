//! WebAssembly HTTP transport for edge runtimes (#553).
//!
//! Cloudflare Workers, Deno and browsers all expose the WHATWG `fetch` API on
//! the global object. `web-sys` provides typed bindings for `Request`,
//! `Response` and `Headers`, and `wasm-bindgen-futures` turns the returned
//! `Promise` into a Rust future, so a Soroban RPC call can be awaited
//! directly inside a Worker without blocking the event loop.
//!
//! The native transport (`ureq`) is synchronous, so it cannot be used from
//! `wasm32-unknown-unknown`. This module is the wasm-only replacement and is
//! compiled only when the `wasm` feature is enabled for the
//! `wasm32-unknown-unknown` target.

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Headers, Request, RequestInit, RequestMode, Response};

use crate::errors::SdkError;

/// POSTs `body` as `application/json` to `url` and returns the response text.
///
/// The response body is refused when it exceeds `max_bytes`, mirroring the
/// native transport's bound so a hostile or misconfigured node cannot exhaust
/// a Worker's memory. A `429` response is surfaced as
/// [`SdkError::RateLimited`]; edge runtimes are expected to apply their own
/// retry/backoff policy at the call site.
pub(crate) async fn post(url: &str, body: &str, max_bytes: usize) -> Result<String, SdkError> {
    let headers = Headers::new()
        .map_err(|err| SdkError::TransportError(format!("failed to build headers: {err:?}")))?;
    headers
        .append("content-type", "application/json")
        .map_err(|err| SdkError::TransportError(format!("failed to set headers: {err:?}")))?;

    let init = RequestInit::new();
    init.set_method("POST");
    init.set_mode(RequestMode::Cors);
    init.set_headers(&headers);
    init.set_body(&JsValue::from_str(body));

    let request = Request::new_with_str_and_init(url, &init)
        .map_err(|err| SdkError::TransportError(format!("failed to build request: {err:?}")))?;

    let promise = fetch(&request)?;

    let response_value = JsFuture::from(promise)
        .await
        .map_err(|err| SdkError::TransportError(format!("fetch failed: {err:?}")))?;
    let response: Response = response_value
        .dyn_into()
        .map_err(|_| SdkError::TransportError("fetch did not resolve to a Response".into()))?;

    let status = response.status();

    // Refuse an over-large body from the announced length before buffering it.
    if let Some(announced) = response
        .headers()
        .get("content-length")
        .ok()
        .flatten()
        .and_then(|value| value.parse::<usize>().ok())
    {
        if announced > max_bytes {
            return Err(SdkError::ResponseTooLarge {
                limit: max_bytes,
                observed: Some(announced),
            });
        }
    }

    let text_promise = response
        .text()
        .map_err(|err| SdkError::TransportError(format!("failed to read body: {err:?}")))?;
    let text = JsFuture::from(text_promise)
        .await
        .map_err(|err| SdkError::TransportError(format!("failed to read body: {err:?}")))?
        .as_string()
        .ok_or_else(|| SdkError::TransportError("response body was not a string".into()))?;

    if status == 429 {
        return Err(SdkError::RateLimited { retries: 0 });
    }
    if !(200..300).contains(&status) {
        return Err(SdkError::TransportError(format!(
            "HTTP {status} from Soroban RPC"
        )));
    }
    if text.len() > max_bytes {
        return Err(SdkError::ResponseTooLarge {
            limit: max_bytes,
            observed: Some(text.len()),
        });
    }

    Ok(text)
}

/// Resolves the runtime's global `fetch` function.
///
/// `window` is absent in Workers and Deno, so the function is read from the
/// global object instead, which every supported runtime provides.
fn fetch(request: &Request) -> Result<js_sys::Promise, SdkError> {
    let global = js_sys::global();
    let fetch_value = js_sys::Reflect::get(&global, &JsValue::from_str("fetch"))
        .map_err(|err| SdkError::TransportError(format!("fetch is unavailable: {err:?}")))?;
    if !fetch_value.is_function() {
        return Err(SdkError::TransportError(
            "this runtime does not provide a global fetch function".into(),
        ));
    }
    let function: js_sys::Function = fetch_value
        .dyn_into()
        .map_err(|_| SdkError::TransportError("global fetch is not callable".into()))?;
    let result = function
        .call1(&JsValue::NULL, request)
        .map_err(|err| SdkError::TransportError(format!("fetch failed: {err:?}")))?;
    Ok(js_sys::Promise::from(result))
}
