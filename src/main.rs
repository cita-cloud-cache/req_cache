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

#[macro_use]
extern crate tracing;

mod config;

use std::sync::Arc;

use clap::Parser;
use color_eyre::eyre::{eyre, Result};
use parking_lot::RwLock;
use regex::Regex;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use storage_hal::{Storage, StorageData};

use config::Config;

use common_rs::{
    configure::{config_hot_reload, file_config},
    consul,
    restful::{err, http_serve, ok_no_data, RESTfulError},
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
    #[clap(short = 'c', long = "config", default_value = "config/config.toml")]
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

#[derive(Clone)]
struct AppState {
    config: Arc<RwLock<Config>>,
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

    let storage = Storage::new(&config.storage_config);
    storage.recover::<ReqId>();
    let storage = Arc::new(RwLock::new(storage));
    let storage_clone = storage.clone();
    tokio::spawn(async move {
        let mut t = tokio::time::interval(tokio::time::Duration::from_millis(100));
        loop {
            storage_clone.write().run_pending_tasks();
            t.tick().await;
        }
    });

    if let Some(consul_config) = &config.consul_config {
        consul::keep_service_register_in_k8s(consul_config)
            .await
            .ok();
    }

    let port = config.port;

    let config = Arc::new(RwLock::new(config));

    let cloned_config_path = opts.config_path.clone();
    let cloned_config = Arc::clone(&config);

    // reload config
    config_hot_reload(cloned_config, cloned_config_path)?;

    let app_state = AppState { config, storage };

    let router = Router::new()
        .hoop(affix::inject(app_state))
        .push(Router::with_path("auth").get(auth));

    http_serve("req_cache", port, router).await;

    Ok(())
}

#[derive(StorageData, Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
struct ReqId;

#[handler]
async fn auth(depot: &Depot, req: &Request) -> Result<impl Writer, RESTfulError> {
    let headers = req.headers();
    debug!("headers: {:?}", headers);

    let forwarded_uri = headers
        .get("x-forwarded-uri")
        .ok_or_else(|| eyre!("x-forwarded-uri missing"))?
        .to_str()?;

    debug!("forwarded_uri: {forwarded_uri}");

    let state = depot
        .obtain::<AppState>()
        .map_err(|e| eyre!("get app_state failed: {e:?}"))?;

    if state
        .config
        .read()
        .limit_uri_regex_vec
        .iter()
        .any(|path_regex| {
            let re = Regex::new(path_regex)
                .map_err(|e| eyre!("regex err: {:?}", e))
                .unwrap();
            re.is_match(forwarded_uri)
        })
    {
        let request_key = headers
            .get("request_key")
            .ok_or_else(|| eyre!("request_key missing"))?
            .to_str()?;
        let user_code = headers
            .get("user_code")
            .ok_or_else(|| eyre!("user_code missing"))?
            .to_str()?
            .to_string();
        let key = user_code + "/" + request_key;
        debug!("user_code/request_key: {}", key);

        let prev_contain = state.storage.read().contains_key::<ReqId>(&key);
        if prev_contain {
            return Err(err(
                StatusCode::TOO_MANY_REQUESTS.as_u16(),
                "Too Many Requests".to_string(),
            ));
        } else {
            state.storage.write().insert(&key, ReqId);
            return ok_no_data();
        }
    }

    ok_no_data()
}
