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
    extract::State, http::StatusCode, middleware, response::IntoResponse, routing::any, Json,
    Router,
};
use clap::Parser;
use hyper::{client::HttpConnector, Body, Request, Uri};
use parking_lot::RwLock;
use serde_json::json;
use storage_dal::Storage;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use config::Config;

use common_rs::{
    configure::file_config,
    consul,
    restful::{err, ok_no_data, RESTfulError},
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

type HttpClient = hyper::Client<HttpConnector, Body>;

#[derive(Clone)]
struct AppState {
    config: Config,
    http_client: HttpClient,
    _cache: Arc<RwLock<Storage>>,
    storage: Arc<RwLock<Storage>>,
}

#[tokio::main]
async fn run(opts: RunOpts) -> Result<()> {
    ::std::env::set_var("RUST_BACKTRACE", "full");

    let config: Config = file_config(&opts.config_path)?;

    // init tracer
    cloud_util::tracer::init_tracer("req_cache".to_string(), &config.log_config)
        .map_err(|e| println!("tracer init err: {e}"))
        .unwrap();

    let http_client: HttpClient = hyper::Client::builder().build(HttpConnector::new());

    let cache = Arc::new(RwLock::new(Storage::init_moka()));
    let storage = Arc::new(RwLock::new(Storage::init_sled(&config.storage_path)));

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));

    if let Some(consul_config) = &config.consul_config {
        consul::service_register(consul_config).await?;
    }

    let app_state = AppState {
        config,
        http_client,
        _cache: cache,
        storage,
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
        .route("/*path", any(req_filter))
        .route("/health", any(|| async { ok_no_data() }))
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .route_layer(middleware::from_fn(req_logger))
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

#[utoipa::path(post, path = "/*path")]
async fn req_filter(
    State(state): State<AppState>,
    mut req: Request<Body>,
) -> Result<impl IntoResponse, RESTfulError> {
    let headers = req.headers();
    debug!("headers: {:?}", headers);

    let user_code = headers
        .get("user_code")
        .ok_or_else(|| anyhow::anyhow!("user_code missing"))?
        .to_str()?
        .to_string();
    let req_id_str = headers
        .get("req_id")
        .ok_or_else(|| anyhow::anyhow!("req_id missing"))?
        .to_str()?;
    let req_id = req_id_str
        .parse::<u64>()
        .map_err(|e| anyhow::anyhow!("decode req_id failed: {e}"))?;

    // check req_id
    let cas = match state
        .storage
        .read()
        .op
        .blocking()
        .read(&format!("req_id/{}", user_code))
    {
        Ok(prev_req_id_bytes) => {
            let prev_req_id = u64::from_be_bytes(prev_req_id_bytes.as_slice().try_into()?);
            prev_req_id < req_id
        }
        Err(_) => true,
    };
    if cas {
        let path = req.uri().path();
        let path_query = req
            .uri()
            .path_and_query()
            .map(|v| v.as_str())
            .unwrap_or(path);
        debug!("path_query: {}", path_query);

        let uri = format!("{}{}", state.config.gateway_endpoint, path_query);

        *req.uri_mut() = Uri::try_from(uri)?;

        let rsp = state.http_client.request(req).await?;
        if rsp.status().is_success() {
            state
                .storage
                .read()
                .op
                .blocking()
                .write(
                    &format!("req_id/{}", user_code),
                    req_id.to_be_bytes().to_vec(),
                )
                .map_err(|e| anyhow::anyhow!("storage req_id failed: {e}"))?;
        }
        Ok(rsp)
    } else {
        Err(err(
            StatusCode::BAD_REQUEST.as_u16(),
            "Expired req_id".to_string(),
        ))
    }
}
