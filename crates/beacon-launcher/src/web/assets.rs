//! The embedded page: plain HTML/CSS/JS from `crates/beacon-launcher/ui/`
//! (`include_str!`, no build step, no CDN).

use axum::http::header;
use axum::response::{IntoResponse, Response};

/// One embedded file.
#[derive(Debug)]
pub struct Asset {
    /// URL path.
    pub path: &'static str,
    /// `Content-Type`.
    pub content_type: &'static str,
    /// Content.
    pub body: &'static str,
}

/// Everything the page loads.
pub static ASSETS: &[Asset] = &[
    Asset {
        path: "/",
        content_type: "text/html; charset=utf-8",
        body: include_str!("../../ui/index.html"),
    },
    Asset {
        path: "/app.js",
        content_type: "text/javascript; charset=utf-8",
        body: include_str!("../../ui/app.js"),
    },
    Asset {
        path: "/style.css",
        content_type: "text/css; charset=utf-8",
        body: include_str!("../../ui/style.css"),
    },
    Asset {
        path: "/favicon.svg",
        content_type: "image/svg+xml",
        body: include_str!("../../ui/favicon.svg"),
    },
];

pub(super) async fn serve(asset: &'static Asset) -> Response {
    ([(header::CONTENT_TYPE, asset.content_type)], asset.body).into_response()
}
