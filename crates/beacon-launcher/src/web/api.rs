//! JSON handlers of `/api/…`. Success: `{"ok": true, …}`; failure: an HTTP error
//! status with `{"ok": false, "error": {"kind", "field"?, "reason"?, "message"}}`.
//! `kind` is a [`CommandErrorKind`] in snake_case or one of `forbidden`,
//! `bad_request`, `not_found`, `too_many_streams`, `internal`; `reason` names the
//! failed input rule (the page shows a German text for it).

use std::path::Path;

use axum::extract::rejection::JsonRejection;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::warn;

use super::Shared;
use crate::app::{CommandError, CommandErrorKind, ConnectRequest, SettingsPatch};
use crate::config::{validate_player_name, NameError, ServerAddr, RES_RANGE};
use crate::util;

/// An error answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApiError {
    #[serde(skip)]
    status: StatusCode,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    field: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            kind,
            field: None,
            reason: None,
            message: message.into(),
        }
    }

    /// `400 invalid_input` for one field.
    fn invalid(field: &'static str, reason: &'static str, message: impl Into<String>) -> Self {
        Self {
            field: Some(field),
            reason: Some(reason),
            ..Self::new(StatusCode::BAD_REQUEST, "invalid_input", message)
        }
    }

    /// `403 forbidden` (request guard).
    pub(super) fn forbidden(reason: &'static str) -> Self {
        Self {
            reason: Some(reason),
            ..Self::new(StatusCode::FORBIDDEN, "forbidden", "access denied")
        }
    }

    /// `429`: all event-stream slots are taken.
    pub(super) fn too_many_streams() -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, "too_many_streams", "too many open event streams")
    }

    fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "ok": false, "error": self }))).into_response()
    }
}

/// The wire name of a command error kind (same as its serde name).
pub fn kind_name(kind: CommandErrorKind) -> &'static str {
    match kind {
        CommandErrorKind::InvalidInput => "invalid_input",
        CommandErrorKind::NotConnected => "not_connected",
        CommandErrorKind::NotHost => "not_host",
        CommandErrorKind::GameNotFound => "game_not_found",
        CommandErrorKind::GameRunning => "game_running",
        CommandErrorKind::HookForeign => "hook_foreign",
        CommandErrorKind::HookInUse => "hook_in_use",
        CommandErrorKind::HookMissing => "hook_missing",
        CommandErrorKind::SmartAppControlBlocked => "smart_app_control_blocked",
        CommandErrorKind::LaunchFailed => "launch_failed",
        CommandErrorKind::Busy => "busy",
        CommandErrorKind::Io => "io",
        CommandErrorKind::NotReady => "not_ready",
        CommandErrorKind::Unsupported => "unsupported",
    }
}

impl From<CommandError> for ApiError {
    fn from(e: CommandError) -> Self {
        let status = match e.kind {
            CommandErrorKind::InvalidInput => StatusCode::BAD_REQUEST,
            CommandErrorKind::Io | CommandErrorKind::LaunchFailed => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::CONFLICT,
        };
        Self::new(status, kind_name(e.kind), e.message)
    }
}

type Body<T> = Result<Json<T>, JsonRejection>;
type ApiResult = Result<Json<Value>, ApiError>;

fn body<T>(b: Body<T>) -> Result<T, ApiError> {
    b.map(|Json(v)| v)
        .map_err(|r| ApiError::new(r.status(), "bad_request", r.body_text()))
}

fn ok() -> Json<Value> {
    Json(json!({ "ok": true }))
}

fn check_name(field: &'static str, name: &str) -> Result<(), ApiError> {
    validate_player_name(name).map_err(|e| {
        let reason = match e {
            NameError::Empty => "name_empty",
            NameError::TooLong => "name_too_long",
            NameError::Spaces => "name_spaces",
            NameError::InvalidChar(_) => "name_invalid_char",
        };
        ApiError::invalid(field, reason, e.to_string())
    })
}

fn check_server(field: &'static str, server: &str) -> Result<(), ApiError> {
    ServerAddr::parse(server)
        .map(|_| ())
        .map_err(|e| ApiError::invalid(field, "invalid_address", format!("invalid server address: {e}")))
}

fn check_settings(p: &SettingsPatch) -> Result<(), ApiError> {
    if let Some(n) = &p.player_name {
        check_name("player_name", n)?;
    }
    if let Some(d) = p.game_dir.as_deref().map(str::trim) {
        if !d.is_empty() && !Path::new(d).is_absolute() {
            return Err(ApiError::invalid(
                "game_dir",
                "path_not_absolute",
                "the game folder must be an absolute path",
            ));
        }
    }
    if let Some(l) = &p.launch {
        if [l.xres, l.yres].into_iter().flatten().any(|v| !RES_RANGE.contains(&v)) {
            return Err(ApiError::invalid(
                "launch",
                "resolution_range",
                format!("resolution outside {}..={}", RES_RANGE.start(), RES_RANGE.end()),
            ));
        }
    }
    if let Some(d) = p.mods_dir.as_deref().map(str::trim) {
        if !d.is_empty() && !Path::new(d).is_absolute() {
            return Err(ApiError::invalid(
                "mods_dir",
                "path_not_absolute",
                "the mods folder must be an absolute path",
            ));
        }
    }
    if let Some(dirs) = &p.import_dirs {
        if dirs.iter().map(|d| d.trim()).any(|d| !d.is_empty() && !Path::new(d).is_absolute()) {
            return Err(ApiError::invalid(
                "import_dirs",
                "path_not_absolute",
                "import folders must be absolute paths",
            ));
        }
    }
    if let Some(r) = &p.redundancy {
        let range = 1..=beacon_proto::relay::MAX_REDUNDANCY;
        if [r.lobby, r.game, r.other].into_iter().flatten().any(|v| !range.contains(&v)) {
            return Err(ApiError::invalid(
                "redundancy",
                "redundancy_range",
                format!("redundancy must be {}..={}", range.start(), range.end()),
            ));
        }
    }
    Ok(())
}

/// `GET /api/state`: the full [`AppState`](crate::state::AppState).
pub(super) async fn state(State(s): State<Shared>) -> Response {
    Json(s.app.snapshot()).into_response()
}

/// `POST /api/connect`. The password is wiped when the body is dropped.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ConnectBody {
    server: String,
    name: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    remember: bool,
    /// Default: `true` without a password.
    #[serde(default)]
    use_remembered: Option<bool>,
}

impl Drop for ConnectBody {
    fn drop(&mut self) {
        if let Some(p) = &mut self.password {
            util::wipe_string(p);
        }
    }
}

pub(super) async fn connect(State(s): State<Shared>, b: Body<ConnectBody>) -> ApiResult {
    let mut b = body(b)?;
    let server = b.server.trim().to_owned();
    check_server("server", &server)?;
    check_name("name", &b.name)?;
    let password = b.password.take().filter(|p| !p.is_empty());
    let use_remembered = b.use_remembered.unwrap_or(password.is_none());
    if password.is_none() && !use_remembered {
        return Err(ApiError::invalid("password", "password_missing", "a password is required"));
    }
    s.app
        .connect(ConnectRequest {
            server,
            name: std::mem::take(&mut b.name),
            password,
            use_remembered,
            remember: b.remember,
        })
        .await?;
    Ok(ok())
}

pub(super) async fn disconnect(State(s): State<Shared>) -> Json<Value> {
    s.app.disconnect().await;
    ok()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ChatBody {
    text: String,
}

pub(super) async fn chat(State(s): State<Shared>, b: Body<ChatBody>) -> ApiResult {
    let b = body(b)?;
    if b.text.trim().is_empty() {
        return Err(ApiError::invalid("text", "chat_empty", "empty message"));
    }
    s.app.send_chat(&b.text).await?;
    Ok(ok())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReadyBody {
    ready: bool,
}

pub(super) async fn ready(State(s): State<Shared>, b: Body<ReadyBody>) -> ApiResult {
    let b = body(b)?;
    s.app.set_ready(b.ready).await?;
    Ok(ok())
}

pub(super) async fn launch(State(s): State<Shared>) -> ApiResult {
    s.app.launch_game().await?;
    Ok(ok())
}

pub(super) async fn launch_all(State(s): State<Shared>) -> ApiResult {
    s.app.launch_all().await?;
    Ok(ok())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NameBody {
    name: String,
}

fn player(b: Body<NameBody>) -> Result<String, ApiError> {
    let name = body(b)?.name;
    if name.is_empty() {
        return Err(ApiError::invalid("name", "name_missing", "no player given"));
    }
    Ok(name)
}

pub(super) async fn kick(State(s): State<Shared>, b: Body<NameBody>) -> ApiResult {
    let name = player(b)?;
    s.app.kick(&name).await?;
    Ok(ok())
}

/// `POST /api/fingerprint {name}`: asks the server for that player's file list
/// (appears in `peer_files`).
pub(super) async fn fingerprint(State(s): State<Shared>, b: Body<NameBody>) -> ApiResult {
    let name = player(b)?;
    s.app.request_fingerprint(&name).await?;
    Ok(ok())
}

pub(super) async fn settings(State(s): State<Shared>, b: Body<SettingsPatch>) -> ApiResult {
    let patch = body(b)?;
    check_settings(&patch)?;
    s.app.update_settings(patch).await?;
    Ok(ok())
}

pub(super) async fn maps_sync(State(s): State<Shared>) -> ApiResult {
    s.app.sync_maps().await?;
    Ok(ok())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ServerBody {
    server: String,
}

fn server(b: Body<ServerBody>) -> Result<String, ApiError> {
    let server = body(b)?.server.trim().to_owned();
    check_server("server", &server)?;
    Ok(server)
}

pub(super) async fn pin_reset(State(s): State<Shared>, b: Body<ServerBody>) -> ApiResult {
    let server = server(b)?;
    let removed = s.app.reset_server_pin(&server).await?;
    Ok(Json(json!({ "ok": true, "removed": removed })))
}

pub(super) async fn password_forget(State(s): State<Shared>, b: Body<ServerBody>) -> ApiResult {
    let server = server(b)?;
    let removed = s.app.forget_password(&server).await?;
    Ok(Json(json!({ "ok": true, "removed": removed })))
}

/// `POST /api/mods/select {key, language?}`: host only; `key` = a catalog key
/// (`guid@version`) or `null` for vanilla.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SelectBody {
    key: Option<String>,
    #[serde(default)]
    language: Option<String>,
}

pub(super) async fn mods_select(State(s): State<Shared>, b: Body<SelectBody>) -> ApiResult {
    let b = body(b)?;
    if let Some(k) = &b.key {
        if k.is_empty() || k.len() > 200 || !k.contains('@') {
            return Err(ApiError::invalid("key", "config_key", "invalid configuration key"));
        }
    }
    if let Some(l) = &b.language {
        if !beacon_proto::control::is_valid_language(l) {
            return Err(ApiError::invalid("language", "language_code", "invalid language code"));
        }
    }
    s.app.set_game_config(b.key, b.language).await?;
    Ok(ok())
}

/// `POST /api/mods/retry`: prepare the lobby's configuration again.
pub(super) async fn mods_retry(State(s): State<Shared>) -> Json<Value> {
    s.app.mods_retry();
    ok()
}

/// `POST /api/mods/cancel`: cancel the preparation.
pub(super) async fn mods_cancel(State(s): State<Shared>) -> Json<Value> {
    s.app.mods_cancel();
    ok()
}

/// `POST /api/mods/reload`: read the BFME Workshop library again.
pub(super) async fn mods_reload(State(s): State<Shared>) -> Json<Value> {
    s.app.mods_reload();
    ok()
}

/// `POST /api/mods/import {path}`: search a folder for package files.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PathBody {
    path: String,
}

pub(super) async fn mods_import(State(s): State<Shared>, b: Body<PathBody>) -> ApiResult {
    let path = body(b)?.path;
    let trimmed = path.trim();
    if trimmed.is_empty() || !Path::new(trimmed).is_absolute() {
        return Err(ApiError::invalid("path", "path_not_absolute", "the folder must be an absolute path"));
    }
    s.app.mods_import_folder(trimmed).await?;
    Ok(ok())
}

/// `POST /api/mods/cleanup`: remove unused instances and store files.
pub(super) async fn mods_cleanup(State(s): State<Shared>) -> ApiResult {
    let report = s.app.mods_cleanup().await?;
    Ok(Json(json!({ "ok": true, "removed": report })))
}

/// `POST /api/name/restore`: BFME's original LAN name back into Network.ini.
pub(super) async fn name_restore(State(s): State<Shared>) -> ApiResult {
    let restored = s.app.restore_user_name().await?;
    Ok(Json(json!({ "ok": true, "restored": restored })))
}

/// `POST /api/logs/open`: shows Beacon's log folder in Explorer.
pub(super) async fn logs_open(State(s): State<Shared>) -> ApiResult {
    let dir = s.app.data_dirs().logs_dir();
    let open = s.open_folder.clone();
    let result = tokio::task::spawn_blocking(move || {
        std::fs::create_dir_all(&dir)?;
        open(&dir)
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    result.map_err(|e| {
        warn!("cannot open the log folder: {e}");
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "io", e.to_string())
    })?;
    Ok(ok())
}

/// `POST /api/quit`: Beacon shuts down (the answer is sent first).
pub(super) async fn quit(State(s): State<Shared>) -> Json<Value> {
    s.app.request_quit();
    ok()
}

/// Unknown paths (`404` with a JSON body).
pub(super) async fn not_found() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "not_found", "not found")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{LaunchOptions, RedundancyOverrides};

    #[test]
    fn kind_names_match_serde() {
        use CommandErrorKind::*;
        for kind in [
            InvalidInput,
            NotConnected,
            NotHost,
            GameNotFound,
            GameRunning,
            HookForeign,
            HookInUse,
            HookMissing,
            SmartAppControlBlocked,
            LaunchFailed,
            Busy,
            Io,
            NotReady,
            Unsupported,
        ] {
            assert_eq!(serde_json::to_value(kind).unwrap(), kind_name(kind), "{kind:?}");
        }
    }

    #[test]
    fn error_body_shape() {
        let e = ApiError::invalid("name", "name_too_long", "x");
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v, json!({"kind": "invalid_input", "field": "name", "reason": "name_too_long", "message": "x"}));
        let e: ApiError = CommandError {
            kind: CommandErrorKind::NotHost,
            message: "host only".into(),
        }
        .into();
        assert_eq!(e.status, StatusCode::CONFLICT);
        assert_eq!(serde_json::to_value(&e).unwrap(), json!({"kind": "not_host", "message": "host only"}));
        let e: ApiError = CommandError {
            kind: CommandErrorKind::SmartAppControlBlocked,
            message: String::new(),
        }
        .into();
        assert_eq!(e.kind, "smart_app_control_blocked");
        assert_eq!(ApiError::forbidden("token").status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn name_reasons() {
        let reason = |n: &str| check_name("name", n).err().and_then(|e| e.reason);
        assert_eq!(reason("Bob"), None);
        assert_eq!(reason(""), Some("name_empty"));
        assert_eq!(reason("abcdefghijklm"), Some("name_too_long"));
        assert_eq!(reason(" Bob"), Some("name_spaces"));
        assert_eq!(reason("Bo<b"), Some("name_invalid_char"));
        assert_eq!(check_server("server", "home.example.org:28086"), Ok(()));
        assert_eq!(
            check_server("server", "bad host:1").err().and_then(|e| e.reason),
            Some("invalid_address")
        );
    }

    #[test]
    fn settings_rules() {
        let reason = |p: SettingsPatch| check_settings(&p).err().and_then(|e| e.reason);
        assert_eq!(reason(SettingsPatch::default()), None);
        assert_eq!(
            reason(SettingsPatch {
                game_dir: Some("relative\\dir".into()),
                ..SettingsPatch::default()
            }),
            Some("path_not_absolute")
        );
        assert_eq!(
            reason(SettingsPatch {
                game_dir: Some(String::new()),
                ..SettingsPatch::default()
            }),
            None
        );
        let launch = |x| LaunchOptions {
            xres: Some(x),
            ..LaunchOptions::default()
        };
        assert_eq!(
            reason(SettingsPatch {
                launch: Some(launch(100)),
                ..SettingsPatch::default()
            }),
            Some("resolution_range")
        );
        assert_eq!(
            reason(SettingsPatch {
                launch: Some(launch(1920)),
                ..SettingsPatch::default()
            }),
            None
        );
        assert_eq!(
            reason(SettingsPatch {
                redundancy: Some(RedundancyOverrides {
                    game: Some(4),
                    ..RedundancyOverrides::default()
                }),
                ..SettingsPatch::default()
            }),
            Some("redundancy_range")
        );
        assert_eq!(
            reason(SettingsPatch {
                player_name: Some("  ".into()),
                ..SettingsPatch::default()
            }),
            Some("name_spaces")
        );
    }
}
