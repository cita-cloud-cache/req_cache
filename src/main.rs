// Copyright Rivtower Technologies LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![forbid(unsafe_code)]
#![warn(
    missing_copy_implementations,
    missing_debug_implementations,
    unused_crate_dependencies,
    clippy::missing_const_for_fn,
    unused_extern_crates
)]

#[macro_use]
extern crate tracing;

mod config;

use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    middleware,
    response::IntoResponse,
    routing::any,
    Json, Router,
};
use clap::Parser;
use parking_lot::RwLock;
use serde_json::json;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use config::Config;

use common_rs::{
    consul::{register_to_consul, ConsulClient},
    restful::{handle_http_error, ok, RESTfulError},
};

fn clap_about() -> String {
    let name = env!("CARGO_PKG_NAME").to_string();
    let version = env!("CARGO_PKG_VERSION");
    let authors = env!("CARGO_PKG_AUTHORS");
    name + " " + version + "\n" + authors
}

#[derive(Parser)]
#[clap(version, about = clap_about())]
struct Opts {
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Parser)]
enum SubCommand {
    /// run this service
    #[clap(name = "run")]
    Run(RunOpts),
}

/// A subcommand for run
#[derive(Parser)]
struct RunOpts {
    /// config path
    #[clap(short = 'c', long = "config", default_value = "config.toml")]
    config_path: String,
}

fn main() {
    ::std::env::set_var("RUST_BACKTRACE", "full");

    let opts: Opts = Opts::parse();

    match opts.subcmd {
        SubCommand::Run(opts) => {
            if let Err(e) = run(opts) {
                warn!("err: {:?}", e);
            }
        }
    }
}

#[derive(OpenApi)]
#[openapi(paths(req_filter,), components(schemas()))]
struct ApiDoc;

#[derive(Clone)]
struct AppState {
    _config: Config,
    _consul: Option<Arc<RwLock<ConsulClient>>>,
}

#[tokio::main]
async fn run(opts: RunOpts) -> Result<()> {
    ::std::env::set_var("RUST_BACKTRACE", "full");

    let config = Config::new(&opts.config_path);

    // init tracer
    cloud_util::tracer::init_tracer("req_cache".to_string(), &config.log_config)
        .map_err(|e| println!("tracer init err: {e}"))
        .unwrap();

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));

    let app_state = if let Some(consul_config) = &config.consul_config {
        let consul = register_to_consul(consul_config.clone()).await?;
        AppState {
            _config: config,
            _consul: Some(Arc::new(RwLock::new(consul))),
        }
    } else {
        AppState {
            _config: config,
            _consul: None,
        }
    };

    async fn req_logger<B>(
        req: axum::http::Request<B>,
        next: middleware::Next<B>,
    ) -> impl IntoResponse
    where
        B: std::fmt::Debug,
    {
        debug!("req: {:?}", req);
        next.run(req).await
    }

    let app = Router::new()
        .route("/req_cache/api/", any(req_filter))
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .route_layer(middleware::from_fn(req_logger))
        .route_layer(middleware::from_fn(handle_http_error))
        .fallback(|| async {
            debug!("Not Found");
            (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "code": 404,
                    "message": "Not Found",
                })),
            )
        })
        .with_state(app_state);

    info!("req_cache listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .map_err(|e| anyhow::anyhow!("axum serve failed: {e}"))?;
    anyhow::bail!("http server exited!")
}

#[utoipa::path(post, path = "/req_cache/api/")]
async fn req_filter(
    headers: HeaderMap,
    State(_state): State<AppState>,
) -> Result<impl IntoResponse, RESTfulError> {
    debug!("headers: {:?}", headers);

    if headers.get("user_code").is_none() {
        return Err(anyhow::anyhow!("user_code missing").into());
    }
    if headers.get("req_id").is_none() {
        return Err(anyhow::anyhow!("user_code missing").into());
    }

    // TODO: check user_code and req_id

    ok(true)
}
