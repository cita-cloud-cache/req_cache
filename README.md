# req_cache

## 编译docker镜像
```
docker build -t citacloudcache/req_cache .
```
## 使用方法

```
$ req_cache -h
req_cache 0.1.0
Rivtower Technologies <contact@rivtower.com>

Usage: req_cache <COMMAND>

Commands:
  run   run this service
  help  Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### req_cache-run

运行`req_cache`服务。

```
$ req_cache run -h
run this service

Usage: req_cache run [OPTIONS]

Options:
  -c, --config <CONFIG_PATH>  config path [default: config.toml]
  -h, --help                  Print help
```

参数：
1. 微服务配置文件。

    参见示例`config/config.toml`。

    其中`[req_cache]`段为微服务的配置：
    * `port` http port

    其中`[req_cache.log_config]`段为微服务日志的配置：
    * `max_level` 日志等级
    * `filter` 日志过滤配置
    * `service_name` 服务名称，用作日志文件名与日志采集的服务名称
    * `rolling_file_path` 日志文件路径
    * `agent_endpoint` jaeger 采集端地址

    其中`[req_cache.consul_config]`段为微服务consul的配置：
    * `consul_addr` consul 服务地址
    * `node` consul 服务节点名称
    * `service_name` 服务注册名称
    * `service_address` 微服务地址
    * `service_port` 微服务监听端口
    * `service_tags` 微服务标签
    * `check_interval` 微服务健康检查间隔
    * `check_timeout` 微服务健康检查超时
    * `check_http_path` 微服务健康检查地址
    * `check_deregister_critical_service_after` 微服务健康检查失败后注销时间

```
$ req_cache run -c config/config.toml
2023-09-01T16:45:46.499179+08:00  INFO req_cache: req_cache listening on 127.0.0.1:3001
```

## 服务接口

/*path
