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
use etcd_client::{Client, PutOptions};
use parking_lot::RwLock;
use regex::Regex;
use salvo::prelude::*;

use config::Config;

use common_rs::{
    configure::{config_hot_reload, file_config},
    error::CALError,
    etcd, log,
    restful::{err, err_code, http_serve, ok_no_data, RESTfulError},
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
                println!("err: {:?}", e);
            }
        }
    }
}

#[derive(Clone)]
struct AppState {
    config: Arc<RwLock<Config>>,
    storage: Client,
}

#[tokio::main]
async fn run(opts: RunOpts) -> Result<()> {
    ::std::env::set_var("RUST_BACKTRACE", "full");

    let config: Config = file_config(&opts.config_path)?;

    // init tracer
    log::init_tracing(&config.name, &config.log_config)?;

    let storage = Client::connect(&config.etcd_endpoints, None).await?;

    if let Some(service_register_config) = &config.service_register_config {
        let etcd = etcd::Etcd {
            client: storage.clone(),
        };
        etcd.keep_service_register_in_k8s(
            &config.name,
            config.port,
            service_register_config.clone(),
        )
        .await
        .ok();
    }

    let service_name = config.name.clone();
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

    http_serve(&service_name, port, router).await;

    Ok(())
}

#[handler]
async fn auth(depot: &Depot, req: &Request) -> Result<impl Writer, RESTfulError> {
    let headers = req.headers();
    debug!("headers: {:?}", headers);

    let forwarded_uri = headers
        .get("x-forwarded-uri")
        .ok_or_else(|| eyre!("x-forwarded-uri missing"))?
        .to_str()?;

    debug!("forwarded_uri: {forwarded_uri}");

    let request_key = if let Some(request_key) = headers.get("request_key") {
        request_key.to_str()?
    } else {
        return err(CALError::BadRequest, "request_key missing");
    };
    let user_code = if let Some(user_code) = headers.get("user_code") {
        user_code.to_str()?
    } else {
        return err(CALError::BadRequest, "user_code missing");
    };

    let state = depot
        .obtain::<AppState>()
        .map_err(|e| eyre!("get app_state failed: {e:?}"))?;

    let ttl = state.config.read().request_key_time_to_live;

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
        let key = format!(
            "{}/RequestFilter/{user_code}/{request_key}",
            state.config.read().name
        );
        debug!("user_code/request_key: {}", key);

        {
            let mut storage = state.storage.clone();
            let prev_contain = storage.get(key.clone(), None).await?;
            if prev_contain.count() > 0 {
                return err_code(CALError::TooManyRequests);
            }
            let lease = storage.lease_grant(ttl, None).await?;
            let option = PutOptions::new().with_lease(lease.id());
            storage.put(key, "", Some(option)).await?;
        }
    }

    ok_no_data()
}
