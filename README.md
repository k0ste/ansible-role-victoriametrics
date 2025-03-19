# ansible-victoriametrics

Deploy [VictoriaMetrics](//victoriametrics.com/) - is a fast, cost-effective and
scalable monitoring solution and time series database

## Requirements

* Ansible 3.0.0+;

## Extra

The deployments expectes binaries from
[cluster](//github.com/VictoriaMetrics/VictoriaMetrics/tree/cluster) branch of VM


### Supported daemons:
* `vmauth`
* `vminsert`
* `vmselect`
* `vmstorage`

## Example configuration

```yaml
---
victoriametrics:
  - package_state: 'present'
    install_package: 'true'
    enable:
      - vminsert: 'true'
        vmstorage: 'true'
        vmselect: 'true'
        vmauth: 'true'
    restart:
      - vminsert: 'true'
        vmstorage: 'true'
        vmselect: 'true'
        vmauth: 'true'
    started:
      - vminsert: 'true'
        vmstorage: 'true'
        vmselect: 'true'
        vmauth: 'true'
    settings:
      - vmauth:
          - config:
# VMAuth users configuration, see: https://docs.victoriametrics.com/vmauth/
              users:
                - bearer_token: 'd4c762d5-dcd9-4635-b2a6-1245994fdcf0'
                  url_map:
                    - src_paths:
                        - '/insert/.*'
                      url_prefix:
                        - 'http://vminsert-1:8480/'
                        - 'http://vminsert-2:8480/'
                        - 'http://vminsert-3:8480/'
                    - src_paths:
                        - '/select/.*'
                      url_prefix:
                        - 'http://vmselect-1:8481/'
                        - 'http://vmselect-2:8481/'
            backend:
# Optional path to TLS root CA file, which is used for TLS verification when
# connecting to backends over HTTPS
              - tls_ca_file: '/path/to/tls/root/ca'
# Optional path to TLS client certificate file, which must be sent to HTTPS
# backend
                tls_cert_file: '/path/to/tls/cert'
# Optional path to TLS client key file, which must be sent to HTTPS backend
                tls_key_file: '/path/to/tls/key'
# Optional TLS ServerName, which must be sent to HTTPS backend
                tls_server_name: 'foo.bar.com'
# Whether to skip TLS verification when connecting to backends over HTTPS
                tls_insecure_skip_verify: 'true'
# Interval for YAML config file re-read. Zero value disables config re-reading.
# By default, refreshing is disabled, send SIGHUP for config refresh
            config_check_interval: '10m'
# Whether to discover backend IPs via periodic DNS queries to hostnames
# specified in `url_prefix`. This may be useful when `url_prefix` points to a
# hostname with dynamically scaled instances behind it
            discover_backend_ips: 'true'
# The interval for re-discovering backend IPs if 'discover_backend_ips' is set.
# Too low value may lead to DNS errors (default is '10s')
            discover_backend_ips_interval: '10s'
# Whether to enable IPv6 for listening and dialing. By default, only IPv4 TCP
# and UDP are used
            enable_tcp6: 'false'
# Whether to disable fadvise() syscall when reading large data files. The
# fadvise() syscall prevents from eviction of recently accessed data from OS
# page cache during background merges and backups. In some rare cases it is
# better to disable the syscall if it uses too much CPU
            filestream_disable_fadvise: 'true'
# Auth key for /flags endpoint. It must be passed via authKey query arg. It
# overrides `-httpAuth.*` Flag value can be read from the given file when
# using 'file:///abs/path/to/file' or 'file://./relative/path/to/file'. Flag
# value can be read from the given http/https url when using 'http://host/path'
# or 'https://host/path'
            flags_auth_key: ''
# Whether to use pread() instead of mmap() for reading data files. By default,
# mmap() is used for 64-bit arches and pread() is used for 32-bit arches, since
# they cannot read data files bigger than 2^32 bytes in memory. mmap() is
# usually faster for reading small data chunks than pread()
            fs_disable_mmap: 'true'
            http:
# Incoming connections to listen address are closed after the configured timeout.
# This may help evenly spreading load among a cluster of services behind
# TCP-level load balancer. Zero value disables closing of incoming
# connections (default is '2m')
              - conn_timeout: '2m'
# Disable compression of HTTP responses to save CPU resources. By default,
# compression is enabled to save network bandwidth
                disable_response_compression: 'true'
# Value for 'Content-Security-Policy' header, recommended: "default-src 'self'"
                header_csp: "default-src 'self'"
# Value for 'X-Frame-Options' header
                header_frame_options: ''
# Value for 'Strict-Transport-Security' header, recommended:
# `'max-age=31536000; includeSubDomains'`
                header_hsts: 'max-age=31536000; includeSubDomains'
# Timeout for incoming idle http connections (default 1m)
                idle_conn_timeout: '1m'
# The maximum duration for a graceful shutdown of the HTTP server. A highly
# loaded server may require increased value for a graceful shutdown (default is
# '7s')
                max_graceful_shutdown_duration: '7s'
# An optional prefix to add to all the paths handled by http server. For
# example, if prefix '/foo/bar' is set, then all the http requests will be
# handled on '/foo/bar/*' paths
                path_prefix: ''
# Optional delay before http server shutdown. During this delay, the server
# returns non-OK responses from /health page, so load balancers can route new
# requests to other servers
                shutdown_delay: ''
# Password for HTTP server's Basic Auth. The authentication is disabled if
# empty. Flag value can be read from the given file when using
# 'file:///abs/path/to/file' or 'file://./relative/path/to/file'. Flag value can
# be read from the given http/https url when using 'http://host/path' or
# 'https://host/path'
                auth_password: ''
# Username for HTTP server's Basic Auth. The authentication is disabled if
# empty
                auth_username: ''
                listen_addr: ':8427'
# The timeout for HTTP keep-alive connections to backend services. It is
# recommended setting this value to values smaller than `http`
# 'idle_conn_timeout' set at backend services (default is '50s')
            idle_conn_timeout: '50s'



# The expiry duration for caches for interned strings (default is '6m')
            intern_string_cache_expire_duration: '6m'
# Whether to disable caches for interned strings. This may reduce memory usage
# at the cost of higher CPU usage
            intern_string_disable_cache: 'true'
# The maximum length for strings to intern. A lower limit may save memory at
# the cost of higher CPU usage (default is '500')
            intern_string_max_len: '500'
# The default load balancing policy to use for backend urls specified inside
# `url_prefix` section. Supported policies: 'least_loaded' (the default),
# 'first_available'
            load_balancing_policy: 'least_loaded'
# Whether to log requests with invalid auth tokens. Such requests are always
# counted at `vmauth_http_request_errors_total{reason="invalid_auth_token"}`
# metric, which is exposed at `/metrics` page
            log_invalid_auth_tokens: 'true'
            logger:
# Whether to disable writing timestamps in logs
              - disable_timestamps: 'true'
# Per-second limit on the number of ERROR messages. If more than the given
# number of errors are emitted per second, the remaining errors are suppressed.
# Zero values disable the rate limit
                errors_per_second_limit: '4'
# Format for logs. Possible values: 'default' (the default), 'json'
                format: 'default'
# Allows renaming fields in JSON formatted logs. Example:
# * ts:timestamp,msg:message - renames "ts" to "timestamp" and "msg" to
# "message". Supported fields: ts, level, caller, msg
                json_fields: ''
# Minimum level of errors to log. Possible values: 'INFO' (the default), 'WARN',
# 'ERROR', 'FATAL', 'PANIC'
                level: 'INFO'
# The maximum length of a single logged argument. Longer arguments are replaced
# with 'arg_start..arg_end', where `arg_start` and `arg_end` is prefix and
# suffix of the arg with the length not exceeding 'max_arg_len' / 2 (default is
# '5000')
                max_arg_len: '5000'
# Output for the logs. Supported values: 'stderr' (the default), 'stdout'
                output: 'stderr'
# Timezone to use for timestamps in logs. Timezone must be a valid IANA Time
# Zone (default is 'UTC')
                timezone: 'UTC'
# Per-second limit on the number of WARN messages. If more than the given
# number of warns are emitted per second, then the remaining warns are
# suppressed. Zero values disable the rate limit
                warns_per_second_limit: ''
# The maximum number of concurrent requests `vmauth` can process per each
# configured user. Other requests are rejected with '429 Too Many Requests'
# http status code (default is '300')
            max_concurrent_per_user_requests: '300'
# The maximum number of concurrent requests `vmauth` can process. Other requests
# are rejected with '429 Too Many Requests' http status code (default is '1000')
            max_concurrent_requests: '100'
# The maximum number of idle connections `vmauth` can open per each backend
# host (default is '100')
            max_idle_conns_per_backend: '100'
# The maximum request body size, which can be cached and re-tried at other
# backends. Bigger values may require more memory. Zero or negative value
# disables caching of request body. This may be useful when proxying data
# ingestion requests. Supports the following optional suffixes for size values:
# 'KB', 'MB', 'GB', 'TB', 'KiB', 'MiB', 'GiB', 'TiB' (default is '16384')
            max_request_body_size_to_retry: '16384'
# Allowed size of system memory VictoriaMetrics caches may occupy. This option
# overrides 'memory_allowed_percent' if set to a non-zero value. Too low a
# value may increase the cache miss rate usually resulting in higher CPU and
# disk IO usage. Too high a value may evict too much data from the OS page
# cache resulting in higher disk IO usage. Supports the following optional
# suffixes for size values: 'KB', 'MB', 'GB', 'TB', 'KiB', 'MiB', 'GiB', 'TiB'
# (default is '0')
            memory_allowed_bytes: '0'
# Allowed percent of system memory VictoriaMetrics caches may occupy. Too low a
# value may increase cache miss rate usually resulting in higher CPU and disk
# IO usage. Too high a value may evict too much data from the OS page cache
# which will result in higher disk IO usage (default is '60')
            memory_allowed_percent: '60'
            metrics:
# Whether to expose TYPE and HELP metadata at the '/metrics' page. The metadata
# may be needed when the '/metrics' page is consumed by systems, which require
# this information
              - expose_metadata: 'true'
# Auth key for '/metrics' endpoint. It must be passed via authKey query arg.
# It overrides "http auth *" flag value can be read from the given file when
# using 'file:///abs/path/to/file' or 'file://./relative/path/to/file'. Flag
# value can be read from the given http/https url when using 'http://host/path'
# or 'https://host/path'
                auth_key: ''
# The maximum size in bytes of a single NewRelic request to
# '/newrelic/infra/v2/metrics/events/bulk'. Supports the following optional
# suffixes for size values: 'KB', 'MB', 'GB', 'TB', 'KiB', 'MiB', 'GiB', 'TiB'
# (default is '67108864')
# Auth key for '/debug/pprof' endpoints. It must be passed via 'pprof_auth_key'.
# Value can be read from the given file when using 'file:///abs/path/to/file' or
# 'file://./relative/path/to/file'. Value can be read from the given http/https
# url when using 'http://host/path' or 'https://host/path'
            pprof_auth_key: ''
            pushmetrics:
# Whether to disable request body compression when pushing metrics to every
# Pushmetrics URL
              - disable_compression: 'true'
# Optional labels to add to metrics pushed to every Pushmetrics URL. For
# example, 'instance="foo"' adds `instance="foo"` label to all the metrics
# pushed to every Pushmetrics URL
                extra_label:
                  - 'instance="foo"'
                  - 'job="bar"'
# Optional HTTP request header to send to every Pushmetrics URL. For example,
# 'Authorization: Basic foobar' adds `Authorization: Basic foobar` header to
# every request to every Pushmetrics URL
                header: 'Authorization: Basic foobar'
# Interval for pushing metrics to every Pushmetrics URL (default is '10s')
                interval: '10s'
# Optional URL to push metrics exposed at '/metrics' page. By default, metrics
# exposed at '/metrics' page aren't pushed to any remote storage
                url:
                  - 'https://victoria-metrics:8428/api/v1/import/prometheus'
                  - 'https://user:pass@maas.victoriametrics.com/api/v1/import/prometheus'
# Auth key for '/-/reload' http endpoint. Value can be read from the given file
# when using 'file:///abs/path/to/file' or 'file://./relative/path/to/file'.
# Value can be read from the given http/https url when using 'http://host/path'
# or 'https://host/path'
            reload_auth_key: ''
# Whether to remove the X-Forwarded-For HTTP header value from client requests
# before forwarding them to the backend. Recommended when `vmauth` is exposed
# to the internet
            remove_xff_http_header_value: 'true'
# The timeout for receiving a response from backend (default is '5m')
            response_timeout: '5m'
# List of default HTTP response status codes when `vmauth` re-tries the request
# on other backends. Default is '0'
            retry_status_codes:
              - '500'
              - '502'
# Whether to enable TLS for incoming HTTP requests at the 'http_listen_addr'
            tls:
# Path to file with TLS certificate for the corresponding 'http_listen_addr'.
# Prefer ECDSA certs instead of RSA certs as RSA certs are slower. The provided
# certificate file is automatically re-read every second, so it can be
# dynamically updated
              - cert_file: '/etc/pki/tls/private/le/fullchain.pem'
#  Path to file with TLS key for the corresponding 'http_listen_addr'. The
# provided key file is automatically re-read every second, so it can be
# dynamically updated
                key_file: '/etc/pki/tls/private/le/privkey.pem'
# Optional list of TLS cipher suites for incoming requests over HTTPS. See the
# list of supported cipher suites at https://pkg.go.dev/crypto/tls#pkg-constants
                cipher_suites: ''
# Optional minimum TLS version to use for the corresponding http_listen_addr'.
# Supported values: 'TLS10', 'TLS11', 'TLS12', 'TLS13'
                min_version: 'TLS13'
        vminsert:
# The number of cache misses before putting the block into cache. Higher values
# may reduce indexdb/dataBlocks cache size at the cost of higher CPU and disk
# read usage (default '2')
          - blockcache_misses_before_caching: '2'
# Items are removed from in-memory caches after they aren't accessed for this
# duration. Lower values may reduce memory usage at the cost of higher CPU
# usage (default is '30m')
            cache_expire_duration: '30m'
            cluster_native:
# The time needed for gradual closing of upstream `vminsert` connections during
# graceful shutdown. Bigger duration reduces spikes in CPU, RAM and disk IO
# load on the remaining lower-level clusters during rolling restart. Smaller
# duration reduces the time needed to close all the upstream `vminsert`
# connections, thus reducing the time for graceful shutdown (default 25s)
              - vminsert_conns_shutdown_duration: '25s'
# TCP address to listen for data from other `vminsert` nodes in multi-level
# cluster setup. Usually ':8400' should be set to match default `vmstorage` port
# for `vminsert`. Disabled work if empty
                listen_addr: ':8400'
# Trim timestamps when importing csv data to this duration. Minimum practical
# duration is 1ms. Higher duration (i.e. 1s) may be used for reducing disk space
# usage for timestamp data (default is '1ms')
            csv_trim_timestamp: '1ms'
            datadog:
# The maximum size in bytes of a single DataDog POST request to
# '/datadog/api/v2/series'. Supports the following optional suffixes for size
# values: KB, MB, GB, TB, KiB, MiB, GiB, TiB (default 67108864)
              - max_insert_request_size: '64MB'
# Sanitize metric names for the ingested DataDog data to comply with DataDog
# (default is 'true')
                sanitize_metric_name: 'true'
# Whether to disable re-routing when some of `vmstorage` nodes accept incoming
# data at slower speed compared to other storage nodes. Disabled re-routing
# limits the ingestion rate by the slowest `vmstorage` node. On the other side,
# disabled re-routing minimizes the number of active time series in the cluster
# during rolling restarts and during spikes in series churn rate (default is
# true)
            disable_rerouting: 'true'
# Whether to disable re-routing when some of `vmstorage` nodes are unavailable.
# Disabled re-routing stops ingestion when some storage nodes are unavailable.
# On the other side, disabled re-routing minimizes the number of active time
# series in the cluster during rolling restarts and during spikes in series
# churn rate
            disable_rerouting_on_unavailable: 'true'
# Whether to drop incoming samples if the destination `vmstorage` node is
# overloaded and/or unavailable. This prioritizes cluster availability over
# consistency, e.g. the cluster continues accepting all the ingested samples,
# but some of them may be dropped if `vmstorage` nodes are temporarily
# unavailable and/or overloaded. The drop of samples happens before the
# replication, so it's not recommended to use this flag with
# 'replication_factor' enabled
            drop_samples_on_overload: 'true'
# Whether to enable IPv6 for listening and dialing. By default, only IPv4 TCP
# and UDP are used
            enable_tcp6: 'false'
# Whether to disable fadvise() syscall when reading large data files. The
# fadvise() syscall prevents from eviction of recently accessed data from OS
# page cache during background merges and backups. In some rare cases it is
# better to disable the syscall if it uses too much CPU
            filestream_disable_fadvise: 'true'
# Auth key for /flags endpoint. It must be passed via authKey query arg. It
# overrides `-httpAuth.*` Flag value can be read from the given file when
# using 'file:///abs/path/to/file' or 'file://./relative/path/to/file'. Flag
# value can be read from the given http/https url when using 'http://host/path'
# or 'https://host/path'
            flags_auth_key: ''
# Whether to use pread() instead of mmap() for reading data files. By default,
# mmap() is used for 64-bit arches and pread() is used for 32-bit arches, since
# they cannot read data files bigger than 2^32 bytes in memory. mmap() is
# usually faster for reading small data chunks than pread()
            fs_disable_mmap: 'true'
            graphite:
# Sanitize metric names for the ingested Graphite data
              - sanitize_metric_name: 'true'
# TCP and UDP address to listen for Graphite plaintext data. Usually ':2003'
# must be set. Doesn't work if empty
                listen_addr: ':2003'
# Whether to use proxy protocol for connections
                listen_addr_use_proxy_protocol: ''
# Trim timestamps for Graphite data to this duration. Minimum practical
# duration is '1s'. Higher duration (i.e. '1m') may be used for reducing disk
# space usage for timestamp data (default '1s')
                trim_timestamp: '1s'
            http:
# Incoming connections to listen address are closed after the configured timeout.
# This may help evenly spreading load among a cluster of services behind
# TCP-level load balancer. Zero value disables closing of incoming
# connections (default is '2m')
              - conn_timeout: '2m'
# Disable compression of HTTP responses to save CPU resources. By default,
# compression is enabled to save network bandwidth
                disable_response_compression: 'true'
# Value for 'Content-Security-Policy' header, recommended: "default-src 'self'"
                header_csp: "default-src 'self'"
# Value for 'X-Frame-Options' header
                header_frame_options: ''
# Value for 'Strict-Transport-Security' header, recommended:
# `'max-age=31536000; includeSubDomains'`
                header_hsts: 'max-age=31536000; includeSubDomains'
# Timeout for incoming idle http connections (default 1m)
                idle_conn_timeout: '1m'
# The maximum duration for a graceful shutdown of the HTTP server. A highly
# loaded server may require increased value for a graceful shutdown (default is
# '7s')
                max_graceful_shutdown_duration: '7s'
# An optional prefix to add to all the paths handled by http server. For
# example, if prefix '/foo/bar' is set, then all the http requests will be
# handled on '/foo/bar/*' paths
                path_prefix: ''
# Optional delay before http server shutdown. During this delay, the server
# returns non-OK responses from /health page, so load balancers can route new
# requests to other servers
                shutdown_delay: ''
# Password for HTTP server's Basic Auth. The authentication is disabled if
# empty. Flag value can be read from the given file when using
# 'file:///abs/path/to/file' or 'file://./relative/path/to/file'. Flag value can
# be read from the given http/https url when using 'http://host/path' or
# 'https://host/path'
                auth_password: ''
# Username for HTTP server's Basic Auth. The authentication is disabled if
# empty
                auth_username: ''
                listen_addr: ':8480'
# The maximum length in bytes of a single line accepted by `/api/v1/import`, the
# line length can be limited with 'max_rows_per_line' query arg passed to
# `/api/v1/export`. Supports the following optional suffixes for size
# values: 'KB', 'MB', 'GB', 'TB', 'KiB', 'MiB', 'GiB', 'TiB' (default is
# '10485760')
            import_max_line_len: '10485760'
            influxdb:
# List of database names to return from '/query' and '/influx/query' API
              - database_names:
                  - 'db1'
                  - 'db2'
# The maximum size in bytes for a single InfluxDB line during parsing.
# Applicable for stream mode only. See Supports the following optional suffixes
# for size values: 'KB', 'MB', 'GB', 'TB', 'KiB', 'MiB', 'GiB', 'TiB' (default
# is '262144')
                max_line_size: '262144'
# The maximum size in bytes of a single InfluxDB request. Applicable for batch
# mode only. Supports the following optional suffixes for size values: 'KB',
# 'MB', 'GB', 'TB', 'KiB', 'MiB', 'GiB', 'TiB' (default is '67108864')
                max_request_size: '67108864'
# Default label for the DB name sent over '?db={db_name}' query parameter
# (default is 'db')
                db_label: 'db'
# TCP and UDP address to listen for InfluxDB line protocol data. Usually
# ':8089' must be set. Doesn't work if empty. This flag isn't needed when
# ingesting data over HTTP - just send it to
# 'http://<victoriametrics>:8428/write'
                listen_addr: ':8089'
# Whether to use proxy protocol for connections accepted at listen address
                listen_addr_use_proxy_protocol: 'false'
# Separator for '{measurement}{separator}{field_name}' metric name when
# inserted via InfluxDB line protocol (default is '_')
                measurement_field_separator: '_'
# Uses '{field_name}' as a metric name while ignoring '{measurement}' and
# `measurement_field_separator`
                skip_measurement: 'true'
# Uses '{measurement}' instead of '{measurement}{separator}{field_name}' for
# metric name if InfluxDB line contains only a single field
                skip_single_field: 'true'
# Trim timestamps for InfluxDB line protocol data to this duration. Minimum
# practical duration is '1ms'. Higher duration (i.e. '1s') may be used for
# reducing disk space usage for timestamp data (default is '1ms')
                trim_timestamp: '1ms'
# The maximum duration to wait in the queue when concurrent insert requests are
# executed (default 1m)
            insert_max_queue_duration: '1m'
# The expiry duration for caches for interned strings (default is '6m')
            intern_string_cache_expire_duration: '6m'
# Whether to disable caches for interned strings. This may reduce memory usage
# at the cost of higher CPU usage
            intern_string_disable_cache: 'true'
# The maximum length for strings to intern. A lower limit may save memory at
# the cost of higher CPU usage (default is '500')
            intern_string_max_len: '500'
            logger:
# Whether to disable writing timestamps in logs
              - disable_timestamps: 'true'
# Per-second limit on the number of ERROR messages. If more than the given
# number of errors are emitted per second, the remaining errors are suppressed.
# Zero values disable the rate limit
                errors_per_second_limit: '4'
# Format for logs. Possible values: 'default' (the default), 'json'
                format: 'default'
# Allows renaming fields in JSON formatted logs. Example:
# * ts:timestamp,msg:message - renames "ts" to "timestamp" and "msg" to
# "message". Supported fields: ts, level, caller, msg
                json_fields: ''
# Minimum level of errors to log. Possible values: 'INFO' (the default), 'WARN',
# 'ERROR', 'FATAL', 'PANIC'
                level: 'INFO'
# The maximum length of a single logged argument. Longer arguments are replaced
# with 'arg_start..arg_end', where `arg_start` and `arg_end` is prefix and
# suffix of the arg with the length not exceeding 'max_arg_len' / 2 (default is
# '5000')
                max_arg_len: '5000'
# Output for the logs. Supported values: 'stderr' (the default), 'stdout'
                output: 'stderr'
# Timezone to use for timestamps in logs. Timezone must be a valid IANA Time
# Zone (default is 'UTC')
                timezone: 'UTC'
# Per-second limit on the number of WARN messages. If more than the given
# number of warns are emitted per second, then the remaining warns are
# suppressed. Zero values disable the rate limit
                warns_per_second_limit: ''
# The maximum number of concurrent insert requests. Set higher value when
# clients send data over slow networks. Default value depends on the number of
# available CPU cores. It should work fine in most cases since it minimizes
# resource usage (default is '8')
            max_concurrent_inserts: '8'
# The maximum size in bytes of a single Prometheus remote_write API request
# Supports the following optional suffixes for size values: 'KB', 'MB', 'GB',
# 'TB', 'KiB', 'MiB', 'GiB', 'TiB' (default is '33554432')
            max_insert_request_size: '33554432'
# The maximum length of label name in the accepted time series. Series with
# longer label name are ignored. In this case the
# vm_rows_ignored_total{reason="too_long_label_name"} metric at '/metrics' page
# is incremented (default is '256')
            max_label_name_len: '256'
# The maximum length of label values in the accepted time series. Series with
# longer label value are ignored. In this case the
# vm_rows_ignored_total{reason="too_long_label_value"} metric at '/metrics' page
# is incremented (default is '4096')
            max_label_value_len: '4096'
# The maximum number of labels per time series to be accepted. Series with
# superfluous labels are ignored. In this case the
# vm_rows_ignored_total{reason="too_many_labels"} metric at '/metrics' page is
# incremented (default is '40')
            max_labels_per_timeseries: '40'
# Allowed size of system memory VictoriaMetrics caches may occupy. This option
# overrides 'memory_allowed_percent' if set to a non-zero value. Too low a
# value may increase the cache miss rate usually resulting in higher CPU and
# disk IO usage. Too high a value may evict too much data from the OS page
# cache resulting in higher disk IO usage. Supports the following optional
# suffixes for size values: 'KB', 'MB', 'GB', 'TB', 'KiB', 'MiB', 'GiB', 'TiB'
# (default is '0')
            memory_allowed_bytes: '0'
# Allowed percent of system memory VictoriaMetrics caches may occupy. Too low a
# value may increase cache miss rate usually resulting in higher CPU and disk
# IO usage. Too high a value may evict too much data from the OS page cache
# which will result in higher disk IO usage (default is '60')
            memory_allowed_percent: '60'
            metrics:
# Whether to expose TYPE and HELP metadata at the '/metrics' page. The metadata
# may be needed when the '/metrics' page is consumed by systems, which require
# this information
              - expose_metadata: 'true'
# Auth key for '/metrics' endpoint. It must be passed via authKey query arg.
# It overrides "http auth *" flag value can be read from the given file when
# using 'file:///abs/path/to/file' or 'file://./relative/path/to/file'. Flag
# value can be read from the given http/https url when using 'http://host/path'
# or 'https://host/path'
                auth_key: ''
# The maximum size in bytes of a single NewRelic request to
# '/newrelic/infra/v2/metrics/events/bulk'. Supports the following optional
# suffixes for size values: 'KB', 'MB', 'GB', 'TB', 'KiB', 'MiB', 'GiB', 'TiB'
# (default is '67108864')
            newrelic_max_insert_request_size: '67108864'
# Whether to convert metric names and labels into Prometheus-compatible format
# for the metrics ingested via OpenTelemetry protocol
            opentelemetry_use_prometheus_naming: 'true'
            opentsdb:
# TCP address to listen for OpenTSDB HTTP put requests. Usually ':4242' must be
# set. Doesn't work if empty
              - http_listen_addr: ':4242'
# Whether to use proxy protocol for connections accepted at 'http_listen_addr'
                http_listen_addr_use_proxy_protocol: 'true'
# TCP and UDP address to listen for OpenTSDB metrics. Telnet put messages and
# HTTP '/api/put' messages are simultaneously served on TCP port. Usually
# ':4242' must be set. Doesn't work if empty
                listen_addr: ':4242'
# Whether to use proxy protocol for connections accepted at 'listen_addr'
                listen_addr_use_proxy_protocol: 'true'
# Trim timestamps for OpenTSDB 'telnet put' data to this duration. Minimum
# practical duration is '1s'. Higher duration (i.e. '1m') may be used for
# reducing disk space usage for timestamp data (default '1s')
                trim_timestamp: '1s'
# The maximum size of OpenTSDB HTTP put request
# Supports the following optional suffixes for size values: 'KB', 'MB', 'GB',
# 'TB', 'KiB', 'MiB', 'GiB', 'TiB' (default is 33554432)
                http_max_insert_request_size: '33554432'
# Trim timestamps for OpenTSDB HTTP data to this duration. Minimum practical
# duration is '1ms'. Higher duration (i.e. '1s') may be used for reducing disk
# space usage for timestamp data (default is '1ms')
                http_trim_timestamp: '1ms'
# Auth key for '/debug/pprof' endpoints. It must be passed via 'pprof_auth_key'.
# Value can be read from the given file when using 'file:///abs/path/to/file' or
# 'file://./relative/path/to/file'. Value can be read from the given http/https
# url when using 'http://host/path' or 'https://host/path'
            pprof_auth_key: ''
# Items in the previous caches are removed when the percent of requests it
# serves becomes lower than this value. Higher values reduce memory usage at
# the cost of higher CPU usage (default is '0.1')
            prev_cache_removal_percent: '0.1'
            pushmetrics:
# Whether to disable request body compression when pushing metrics to every
# Pushmetrics URL
              - disable_compression: 'true'
# Optional labels to add to metrics pushed to every Pushmetrics URL. For
# example, 'instance="foo"' adds `instance="foo"` label to all the metrics
# pushed to every Pushmetrics URL
                extra_label:
                  - 'instance="foo"'
                  - 'job="bar"'
# Optional HTTP request header to send to every Pushmetrics URL. For example,
# 'Authorization: Basic foobar' adds `Authorization: Basic foobar` header to
# every request to every Pushmetrics URL
                header: 'Authorization: Basic foobar'
# Interval for pushing metrics to every Pushmetrics URL (default is '10s')
                interval: '10s'
# Optional URL to push metrics exposed at '/metrics' page. By default, metrics
# exposed at '/metrics' page aren't pushed to any remote storage
                url:
                  - 'https://victoria-metrics:8428/api/v1/import/prometheus'
                  - 'https://user:pass@maas.victoriametrics.com/api/v1/import/prometheus'
# Interval for checking for changes in relabel config file. By default the
# checking is disabled
            relabel_config_check_interval: '10m'
# Replication factor for the ingested data, i.e. how many copies to make among
# distinct 'storage_node' instances. Note that `vmselect` must run with
# 'dedup_min_scrape_interval': '1ms' for data de-duplication when
# replication_factor is greater than '1'. Higher values for
# 'dedup_min_scrape_interval' at `vmselect` is OK (default is '1')
            replication_factor: '1'
# Whether to disable compression for the data sent from `vminsert` to
# `vmstorage`. This reduces CPU usage at the cost of higher network bandwidth
# usage
            rpc_disable_compression: 'true'
# Whether to sort labels for incoming samples before writing them to storage.
# This may be needed for reducing memory usage at storage when the order of
# labels in incoming samples is random. For example, if
# 'm{k1="v1",k2="v2"}'' may be sent as 'm{k2="v2",k1="v1"}'. Enabled sorting
# or labels can slow down ingestion performance a bit
            sort_labels: 'true'
# List of addresses of `vmstorage` nodes. Enterprise version of VictoriaMetrics
# supports automatic discovery of `vmstorage` addresses via DNS SRV records
            storage_node:
              - 'vm1.example.com:8400'
              - 'vm2.example.com:8400'
              - 'srv+vmstorage.addrs'
# Whether to enable TLS for incoming HTTP requests at the 'http_listen_addr'
            tls:
# Path to file with TLS certificate for the corresponding 'http_listen_addr'.
# Prefer ECDSA certs instead of RSA certs as RSA certs are slower. The provided
# certificate file is automatically re-read every second, so it can be
# dynamically updated
              - cert_file: '/etc/pki/tls/private/le/fullchain.pem'
#  Path to file with TLS key for the corresponding 'http_listen_addr'. The
# provided key file is automatically re-read every second, so it can be
# dynamically updated
                key_file: '/etc/pki/tls/private/le/privkey.pem'
# Optional list of TLS cipher suites for incoming requests over HTTPS. See the
# list of supported cipher suites at https://pkg.go.dev/crypto/tls#pkg-constants
                cipher_suites: ''
# Optional minimum TLS version to use for the corresponding http_listen_addr'.
# Supported values: 'TLS10', 'TLS11', 'TLS12', 'TLS13'
                min_version: 'TLS13'
        vmstorage:
# The number of cache misses before putting the block into cache. Higher values
# may reduce indexdb/dataBlocks cache size at the cost of higher CPU and disk
# read usage (default '2')
          - blockcache_misses_before_caching: '2'
# Items are removed from in-memory caches after they aren't accessed for this
# duration. Lower values may reduce memory usage at the cost of higher CPU
# usage (default is '30m')
            cache_expire_duration: '30m'
# Leave only the last sample in every time series per each discrete interval
# equal to dedup_min_scrape_interval > 0
            dedup_min_scrape_interval: ''
# Whether to deny queries outside of the configured 'retention_period'. When
# set, then `/api/v1/query_range` would return "503 Service Unavailable" error
# for queries with 'from' value outside 'retention_period'. This may be useful
# when multiple data sources with distinct retentions are hidden behind
# query-tee
            deny_queries_outside_retention: 'true'
# Whether to disable the ability to trace queries
            deny_query_tracing: 'true'
# Whether to enable IPv6 for listening and dialing. By default, only IPv4 TCP
# and UDP are used
            enable_tcp6: 'false'
# Whether to disable fadvise() syscall when reading large data files. The
# fadvise() syscall prevents from eviction of recently accessed data from OS
# page cache during background merges and backups. In some rare cases it is
# better to disable the syscall if it uses too much CPU
            filestream_disable_fadvise: 'true'
# Auth key for /flags endpoint. It must be passed via authKey query arg. It
# overrides `-httpAuth.*` Flag value can be read from the given file when
# using 'file:///abs/path/to/file' or 'file://./relative/path/to/file'. Flag
# value can be read from the given http/https url when using 'http://host/path'
# or 'https://host/path'
            flags_auth_key: ''
# Whether to use pread() instead of mmap() for reading data files. By default,
# mmap() is used for 64-bit arches and pread() is used for 32-bit arches, since
# they cannot read data files bigger than 2^32 bytes in memory. mmap() is
# usually faster for reading small data chunks than pread()
            fs_disable_mmap: 'true'
# authKey, which must be passed in query string to '/internal/force_flush'
# pages. Flag value can be read from the given file when using
# 'file:///abs/path/to/file' or 'file://./relative/path/to/file'. Flag value
# can be read from the given http/https url when using 'http://host/path' or
# 'https://host/path'
            force_flush_auth_key: ''
# authKey, which must be passed in query string to '/internal/force_merge'.
# pages Flag value can be read from the given file when using
# 'file:///abs/path/to/file' or 'file://./relative/path/to/file'. Flag value can
# be read from the given http/https url when using 'http://host/path' or
# 'https://host/path'
            force_merge_auth_key: ''
            http:
# Incoming connections to listen address are closed after the configured timeout.
# This may help evenly spreading load among a cluster of services behind
# TCP-level load balancer. Zero value disables closing of incoming
# connections (default is '2m')
              - conn_timeout: '2m'
# Disable compression of HTTP responses to save CPU resources. By default,
# compression is enabled to save network bandwidth
                disable_response_compression: 'true'
# Value for 'Content-Security-Policy' header, recommended: "default-src 'self'"
                header_csp: "default-src 'self'"
# Value for 'X-Frame-Options' header
                header_frame_options: ''
# Value for 'Strict-Transport-Security' header, recommended:
# `'max-age=31536000; includeSubDomains'`
                header_hsts: 'max-age=31536000; includeSubDomains'
# Timeout for incoming idle http connections (default 1m)
                idle_conn_timeout: '1m'
# The maximum duration for a graceful shutdown of the HTTP server. A highly
# loaded server may require increased value for a graceful shutdown (default is
# '7s')
                max_graceful_shutdown_duration: '7s'
# An optional prefix to add to all the paths handled by http server. For
# example, if prefix '/foo/bar' is set, then all the http requests will be
# handled on '/foo/bar/*' paths
                path_prefix: ''
# Optional delay before http server shutdown. During this delay, the server
# returns non-OK responses from /health page, so load balancers can route new
# requests to other servers
                shutdown_delay: ''
# Password for HTTP server's Basic Auth. The authentication is disabled if
# empty. Flag value can be read from the given file when using
# 'file:///abs/path/to/file' or 'file://./relative/path/to/file'. Flag value can
# be read from the given http/https url when using 'http://host/path' or
# 'https://host/path'
                auth_password: ''
# Username for HTTP server's Basic Auth. The authentication is disabled if
# empty
                auth_username: ''
                listen_addr: ':8482'
# The interval for guaranteed saving of in-memory data to disk. The saved data
# survives unclean shutdowns such as OOM crash, hardware reset, SIGKILL, etc.
# Bigger intervals may help increase the lifetime of flash storage with limited
# write cycles. Smaller intervals increase disk IO load. Minimum supported
# value is 1s (default 5s)
            inmemory_data_flush_interval: '5s'
# The maximum duration to wait in the queue when concurrent insert requests are
# executed (default 1m)
            insert_max_queue_duration: '1m'
# The expiry duration for caches for interned strings (default is '6m')
            intern_string_cache_expire_duration: '6m'
# Whether to disable caches for interned strings. This may reduce memory usage
# at the cost of higher CPU usage
            intern_string_disable_cache: 'true'
# The maximum length for strings to intern. A lower limit may save memory at
# the cost of higher CPU usage (default is '500')
            intern_string_max_len: '500'
# Whether to log new series. This option is for debug purposes only. It can
# lead to performance issues when big number of new series are ingested into
# VictoriaMetrics
            log_new_series: 'true'
            logger:
# Whether to disable writing timestamps in logs
              - disable_timestamps: 'true'
# Per-second limit on the number of ERROR messages. If more than the given
# number of errors are emitted per second, the remaining errors are suppressed.
# Zero values disable the rate limit
                errors_per_second_limit: '4'
# Format for logs. Possible values: 'default' (the default), 'json'
                format: 'default'
# Allows renaming fields in JSON formatted logs. Example:
# * ts:timestamp,msg:message - renames "ts" to "timestamp" and "msg" to
# "message". Supported fields: ts, level, caller, msg
                json_fields: ''
# Minimum level of errors to log. Possible values: 'INFO' (the default), 'WARN',
# 'ERROR', 'FATAL', 'PANIC'
                level: 'INFO'
# The maximum length of a single logged argument. Longer arguments are replaced
# with 'arg_start..arg_end', where `arg_start` and `arg_end` is prefix and
# suffix of the arg with the length not exceeding 'max_arg_len' / 2 (default is
# '5000')
                max_arg_len: '5000'
# Output for the logs. Supported values: 'stderr' (the default), 'stdout'
                output: 'stderr'
# Timezone to use for timestamps in logs. Timezone must be a valid IANA Time
# Zone (default is 'UTC')
                timezone: 'UTC'
# Per-second limit on the number of WARN messages. If more than the given
# number of warns are emitted per second, then the remaining warns are
# suppressed. Zero values disable the rate limit
                warns_per_second_limit: ''
# The maximum number of concurrent insert requests. Set higher value when
# clients send data over slow networks. Default value depends on the number of
# available CPU cores. It should work fine in most cases since it minimizes
# resource usage (default is '8')
            max_concurrent_inserts: '8'
# Allowed size of system memory VictoriaMetrics caches may occupy. This option
# overrides 'memory_allowed_percent' if set to a non-zero value. Too low a
# value may increase the cache miss rate usually resulting in higher CPU and
# disk IO usage. Too high a value may evict too much data from the OS page
# cache resulting in higher disk IO usage. Supports the following optional
# suffixes for size values: 'KB', 'MB', 'GB', 'TB', 'KiB', 'MiB', 'GiB', 'TiB'
# (default is '0')
            memory_allowed_bytes: '0'
# Allowed percent of system memory VictoriaMetrics caches may occupy. Too low a
# value may increase cache miss rate usually resulting in higher CPU and disk
# IO usage. Too high a value may evict too much data from the OS page cache
# which will result in higher disk IO usage (default is '60')
            memory_allowed_percent: '60'
            metrics:
# Whether to expose TYPE and HELP metadata at the '/metrics' page. The metadata
# may be needed when the '/metrics' page is consumed by systems, which require
# this information
              - expose_metadata: 'true'
# Auth key for '/metrics' endpoint. It must be passed via authKey query arg.
# It overrides "http auth *" flag value can be read from the given file when
# using 'file:///abs/path/to/file' or 'file://./relative/path/to/file'. Flag
# value can be read from the given http/https url when using 'http://host/path'
# or 'https://host/path'
                auth_key: ''
# Auth key for '/debug/pprof' endpoints. It must be passed via 'pprof_auth_key'.
# Value can be read from the given file when using 'file:///abs/path/to/file' or
# 'file://./relative/path/to/file'. Value can be read from the given http/https
# url when using 'http://host/path' or 'https://host/path'
            pprof_auth_key: ''
# The number of precision bits to store per each value. Lower precision bits
# improves data compression at the cost of precision loss (default is '64')
            precision_bits: '64'
# Items in the previous caches are removed when the percent of requests it
# serves becomes lower than this value. Higher values reduce memory usage at
# the cost of higher CPU usage (default is '0.1')
            prev_cache_removal_percent: '0.1'
            pushmetrics:
# Whether to disable request body compression when pushing metrics to every
# Pushmetrics URL
              - disable_compression: 'true'
# Optional labels to add to metrics pushed to every Pushmetrics URL. For
# example, 'instance="foo"' adds `instance="foo"` label to all the metrics
# pushed to every Pushmetrics URL
                extra_label:
                  - 'instance="foo"'
                  - 'job="bar"'
# Optional HTTP request header to send to every Pushmetrics URL. For example,
# 'Authorization: Basic foobar' adds `Authorization: Basic foobar` header to
# every request to every Pushmetrics URL
                header: 'Authorization: Basic foobar'
# Interval for pushing metrics to every Pushmetrics URL (default is '10s')
                interval: '10s'
# Optional URL to push metrics exposed at '/metrics' page. By default, metrics
# exposed at '/metrics' page aren't pushed to any remote storage
                url:
                  - 'https://victoria-metrics:8428/api/v1/import/prometheus'
                  - 'https://user:pass@maas.victoriametrics.com/api/v1/import/prometheus'
# Data with timestamps outside the 'retention_period' is automatically deleted.
# The minimum 'retention_period' is '24h' or '1d'. The default is '4w'
            retention_period: '4w'
# The offset for performing indexdb rotation. If set to '0', then the indexdb
# rotation is performed at 4am UTC time per each 'retention_period'. If set to
# '2h', then the indexdb rotation is performed at 4am EET time (the timezone
# with +2h offset)
            retention_timezone_offset: '0'
# Whether to disable compression for the data sent from `vminsert` to
# `vmstorage`. This reduces CPU usage at the cost of higher network bandwidth
# usage
            rpc_disable_compression: 'true'
            search:
# The maximum number of concurrent `vmselect` requests the `vmstorage` can
# process at 'vmselect_addr'. It shouldn't be high, since a single request
# usually saturates a CPU core, and many concurrently executed requests may
# require high amounts of memory (default is 8)
              - max_concurrent_requests: '8'
# The maximum time the incoming vmselect request waits for execution when
# 'max_concurrent_requests' limit is reached (default is '10s')
                max_queue_duration: '10s'
# The maximum number of tag keys returned per search (default is '100000')
                max_tag_keys: '100000'
# The maximum number of tag value suffixes returned from '/metrics/find'
# (default is '100000')
                max_tag_value_suffixes_per_search: '100000'
# The maximum number of tag values returned per search (default is '100000')
                max_tag_values: '100000'
# The maximum number of unique time series, which can be scanned during every
# query. This allows protecting against heavy queries, which select unexpectedly
# high number of series. When set to zero, the limit is automatically calculated
# based on 'max_concurrent_requests' (inversely proportional) and memory
# available to the process (proportional)
                max_unique_timeseries: '0'
# authKey, which must be passed in query string to '/snapshot*'' pages. Flag
# value can be read from the given file when using 'file:///abs/path/to/file' or
# 'file://./relative/path/to/file'. Flag value can be read from the given
# http/https url when using 'http://host/path' or 'https://host/path'
            snapshot_auth_key: ''
# Automatically delete snapshots older than 'snapshots_max_age' if it is set to
# non-zero duration. Make sure that backup process has enough time to finish
# the backup before the corresponding snapshot is automatically deleted
            snapshots_max_age: '0'
            storage:
# Overrides max size for indexdb/dataBlocks cache. Supports the following
# optional suffixes for size values: 'KB', 'MB', 'GB', 'TB', 'KiB', 'MiB',
# 'GiB', 'TiB' (default is '0')
              - cache_size_index_db_data_blocks: '0'
# Overrides max size for indexdb/dataBlocksSparse cache. Supports the following
# optional suffixes for size values: 'KB', 'MB', 'GB', 'TB', 'KiB', 'MiB',
# 'GiB', 'TiB' (default is '0')
                cache_size_index_db_data_blocks_sparse: '0'
# Overrides max size for indexdb/indexBlocks cache. Supports the following
# optional suffixes for size values: 'KB', 'MB', 'GB', 'TB', 'KiB', 'MiB',
# 'GiB', 'TiB' (default is '0')
                cache_size_index_db_index_blocks: '0'
# Overrides max size for indexdb/tagFiltersToMetricIDs cache. Supports the
# following optional suffixes for size values: 'KB', 'MB', 'GB', 'TB', 'KiB',
# 'MiB', 'GiB', 'TiB' (default is '0')
                cache_size_index_db_tag_filters: '0'
# Overrides max size for storage/tsid cache. Supports the following optional
# suffixes for size values: 'KB', 'MB', 'GB', 'TB', 'KiB', 'MiB', 'GiB', 'TiB'
# (default is '0')
                cache_size_storage_tsid: '0'
# The interval for checking when final deduplication process should be started.
# Storage unconditionally adds 25% jitter to the interval value on each check
# evaluation. Changing the interval to the bigger values may delay downsampling,
# deduplication for historical data (default is '1h')
                final_dedup_schedule_check_interval: '1h'
# The maximum number of unique series can be added to the storage during the
# last 24 hours. Excess series are logged and dropped. This can be useful for
# limiting series churn rate
                max_daily_series: ''
# The maximum number of unique series can be added to the storage during the
# last hour. Excess series are logged and dropped. This can be useful for
# limiting series cardinality
                max_hourly_series: ''
# The minimum free disk space at after which the storage stops accepting new
# data. Supports the following optional suffixes for size values: 'KB', 'MB',
# 'GB', 'TB', 'KiB', 'MiB', 'GiB', 'TiB' (default is 9.537MiB)
                min_free_disk_space_bytes: '10000000'
# The time needed for gradual closing of `vminsert` connections during graceful
# shutdown. Bigger duration reduces spikes in CPU, RAM and disk IO load on the
# remaining `vmstorage` nodes during rolling restart. Smaller duration reduces
# the time needed to close all the `vminsert` connections, thus reducing the
# time for graceful shutdown (default is '25s')
                vminsert_conns_shutdown_duration: '25s'
# Whether to enable TLS for incoming HTTP requests at the 'http_listen_addr'
            tls:
# Path to file with TLS certificate for the corresponding 'http_listen_addr'.
# Prefer ECDSA certs instead of RSA certs as RSA certs are slower. The provided
# certificate file is automatically re-read every second, so it can be
# dynamically updated
              - cert_file: '/etc/pki/tls/private/le/fullchain.pem'
#  Path to file with TLS key for the corresponding 'http_listen_addr'. The
# provided key file is automatically re-read every second, so it can be
# dynamically updated
                key_file: '/etc/pki/tls/private/le/privkey.pem'
# Optional list of TLS cipher suites for incoming requests over HTTPS. See the
# list of supported cipher suites at https://pkg.go.dev/crypto/tls#pkg-constants
                cipher_suites: ''
# Optional minimum TLS version to use for the corresponding http_listen_addr'.
# Supported values: 'TLS10', 'TLS11', 'TLS12', 'TLS13'
                min_version: 'TLS13'
# TCP address to accept connections from vminsert services (default is ':8400')
            vminsert_addr: ':8400'
# TCP address to accept connections from vmselect services (default is ':8401')
            vmselect_addr: ':8401'
        vmselect:
# The number of cache misses before putting the block into cache. Higher values
# may reduce indexdb/dataBlocks cache size at the cost of higher CPU and disk
# read usage (default '2')
          - blockcache_misses_before_caching: '2'
# Items are removed from in-memory caches after they aren't accessed for this
# duration. Lower values may reduce memory usage at the cost of higher CPU
# usage (default is '30m')
            cache_expire_duration: '30m'
# Path to directory for cache files and temporary query results. By default, the
# cache won't be persisted, and temporary query results will be placed under
# "/tmp/searchResults". If set, the cache will be persisted under
# "cacheDataPath/rollupResult", and temporary query results will be placed
# under "cacheDataPath/tmp/searchResults"
            cache_data_path: ''
            cluster_native:
# Whether to disable compression of the data sent to vmselect via
# clusternative 'listen_addr'. This reduces CPU usage at the cost of higher
# network bandwidth usage:
              - disable_compression: 'true'
# The maximum number of concurrent `vmselect` requests the server can process
# at clusternative 'listen_addr'. It shouldn't be high, since a single request
# usually saturates a CPU core at the underlying `vmstorage` nodes, and many
# concurrently executed requests may require high amounts of memory (default is
# '8')
                max_concurrent_requests: '8'
# The maximum time the incoming query to clusternative 'listen_addr' waits for
# execution when clusternative 'max_concurrent_requests limit is reached
# (default is '10s')
                max_queue_duration: '10s'
# The maximum number of tag keys returned per search at
# clusternative 'listen_addr' (default is '100000')
                max_tag_keys: '100000'
# The maximum number of tag value suffixes returned from '/metrics/find' at
# clusternative 'listen_addr' (default is '100000')
                max_tag_value_suffixes_per_search: '100000'
# The maximum number of tag values returned per search at
# clusternative 'listen_addr' (default is '100000')
                max_tag_values: '100000'
# TCP address to listen for data from other `vminsert` nodes in multi-level
# cluster setup. Usually ':8401' should be set to match default `vmstorage` port
# for `vminsert`. Disabled work if empty
                listen_addr: ':8401'
# Leave only the last sample in every time series per each discrete interval
# equal to dedup_min_scrape_interval > 0
            dedup_min_scrape_interval: ''
# Auth key for metrics deletion via
# '/prometheus/api/v1/admin/tsdb/delete_series' and '/graphite/tags/delSeries'.
# It could be passed via 'auth_key' query arg. Value can be read from the given
# file when using 'file:///abs/path/to/file' or
# 'file://./relative/path/to/file'. Value can be read from the given
# http/https url when using 'http://host/path' or 'https://host/path'
            delete_auth_key: ''
# Whether to disable the ability to trace queries
            deny_query_tracing: 'true'
# Whether to enable IPv6 for listening and dialing. By default, only IPv4 TCP
# and UDP are used
            enable_tcp6: 'false'
# Whether to disable fadvise() syscall when reading large data files. The
# fadvise() syscall prevents from eviction of recently accessed data from OS
# page cache during background merges and backups. In some rare cases it is
# better to disable the syscall if it uses too much CPU
            filestream_disable_fadvise: 'true'
# Auth key for /flags endpoint. It must be passed via authKey query arg. It
# overrides `-httpAuth.*` Flag value can be read from the given file when
# using 'file:///abs/path/to/file' or 'file://./relative/path/to/file'. Flag
# value can be read from the given http/https url when using 'http://host/path'
# or 'https://host/path'
            flags_auth_key: ''
# Whether to use pread() instead of mmap() for reading data files. By default,
# mmap() is used for 64-bit arches and pread() is used for 32-bit arches, since
# they cannot read data files bigger than 2^32 bytes in memory. mmap() is
# usually faster for reading small data chunks than pread()
            fs_disable_mmap: 'true'
# How many copies of every ingested sample is available across `vmstorage`
# groups. `vmselect` continues returning full responses when up to
# 'global_replication_factor' -1 `vmstorage` groups are temporarily
# unavailable (default is '1')
            global_replication_factor: '1'
            graphite:
# Sanitize metric names for the ingested Graphite data
              - sanitize_metric_name: 'true'
            http:
# Incoming connections to listen address are closed after the configured timeout.
# This may help evenly spreading load among a cluster of services behind
# TCP-level load balancer. Zero value disables closing of incoming
# connections (default is '2m')
              - conn_timeout: '2m'
# Disable compression of HTTP responses to save CPU resources. By default,
# compression is enabled to save network bandwidth
                disable_response_compression: 'true'
# Value for 'Content-Security-Policy' header, recommended: "default-src 'self'"
                header_csp: "default-src 'self'"
# Value for 'X-Frame-Options' header
                header_frame_options: ''
# Value for 'Strict-Transport-Security' header, recommended:
# `'max-age=31536000; includeSubDomains'`
                header_hsts: 'max-age=31536000; includeSubDomains'
# Timeout for incoming idle http connections (default 1m)
                idle_conn_timeout: '1m'
# The maximum duration for a graceful shutdown of the HTTP server. A highly
# loaded server may require increased value for a graceful shutdown (default is
# '7s')
                max_graceful_shutdown_duration: '7s'
# An optional prefix to add to all the paths handled by http server. For
# example, if prefix '/foo/bar' is set, then all the http requests will be
# handled on '/foo/bar/*' paths
                path_prefix: ''
# Optional delay before http server shutdown. During this delay, the server
# returns non-OK responses from /health page, so load balancers can route new
# requests to other servers
                shutdown_delay: ''
# Password for HTTP server's Basic Auth. The authentication is disabled if
# empty. Flag value can be read from the given file when using
# 'file:///abs/path/to/file' or 'file://./relative/path/to/file'. Flag value can
# be read from the given http/https url when using 'http://host/path' or
# 'https://host/path'
                auth_password: ''
# Username for HTTP server's Basic Auth. The authentication is disabled if
# empty
                auth_username: ''
                listen_addr: ':8481'
# The expiry duration for caches for interned strings (default is '6m')
            intern_string_cache_expire_duration: '6m'
# Whether to disable caches for interned strings. This may reduce memory usage
# at the cost of higher CPU usage
            intern_string_disable_cache: 'true'
# The maximum length for strings to intern. A lower limit may save memory at
# the cost of higher CPU usage (default is '500')
            intern_string_max_len: '500'
            logger:
# Whether to disable writing timestamps in logs
              - disable_timestamps: 'true'
# Per-second limit on the number of ERROR messages. If more than the given
# number of errors are emitted per second, the remaining errors are suppressed.
# Zero values disable the rate limit
                errors_per_second_limit: '4'
# Format for logs. Possible values: 'default' (the default), 'json'
                format: 'default'
# Allows renaming fields in JSON formatted logs. Example:
# * ts:timestamp,msg:message - renames "ts" to "timestamp" and "msg" to
# "message". Supported fields: ts, level, caller, msg
                json_fields: ''
# Minimum level of errors to log. Possible values: 'INFO' (the default), 'WARN',
# 'ERROR', 'FATAL', 'PANIC'
                level: 'INFO'
# The maximum length of a single logged argument. Longer arguments are replaced
# with 'arg_start..arg_end', where `arg_start` and `arg_end` is prefix and
# suffix of the arg with the length not exceeding 'max_arg_len' / 2 (default is
# '5000')
                max_arg_len: '5000'
# Output for the logs. Supported values: 'stderr' (the default), 'stdout'
                output: 'stderr'
# Timezone to use for timestamps in logs. Timezone must be a valid IANA Time
# Zone (default is 'UTC')
                timezone: 'UTC'
# Per-second limit on the number of WARN messages. If more than the given
# number of warns are emitted per second, then the remaining warns are
# suppressed. Zero values disable the rate limit
                warns_per_second_limit: ''
# Allowed size of system memory VictoriaMetrics caches may occupy. This option
# overrides 'memory_allowed_percent' if set to a non-zero value. Too low a
# value may increase the cache miss rate usually resulting in higher CPU and
# disk IO usage. Too high a value may evict too much data from the OS page
# cache resulting in higher disk IO usage. Supports the following optional
# suffixes for size values: 'KB', 'MB', 'GB', 'TB', 'KiB', 'MiB', 'GiB', 'TiB'
# (default is '0')
            memory_allowed_bytes: '0'
# Allowed percent of system memory VictoriaMetrics caches may occupy. Too low a
# value may increase cache miss rate usually resulting in higher CPU and disk
# IO usage. Too high a value may evict too much data from the OS page cache
# which will result in higher disk IO usage (default is '60')
            memory_allowed_percent: '60'
            metrics:
# Whether to expose TYPE and HELP metadata at the '/metrics' page. The metadata
# may be needed when the '/metrics' page is consumed by systems, which require
# this information
              - expose_metadata: 'true'
# Auth key for '/metrics' endpoint. It must be passed via authKey query arg.
# It overrides "http auth *" flag value can be read from the given file when
# using 'file:///abs/path/to/file' or 'file://./relative/path/to/file'. Flag
# value can be read from the given http/https url when using 'http://host/path'
# or 'https://host/path'
                auth_key: ''
# Auth key for '/debug/pprof' endpoints. It must be passed via 'pprof_auth_key'.
# Value can be read from the given file when using 'file:///abs/path/to/file' or
# 'file://./relative/path/to/file'. Value can be read from the given http/https
# url when using 'http://host/path' or 'https://host/path'
            pprof_auth_key: ''
# Items in the previous caches are removed when the percent of requests it
# serves becomes lower than this value. Higher values reduce memory usage at
# the cost of higher CPU usage (default is '0.1')
            prev_cache_removal_percent: '0.1'
            pushmetrics:
# Whether to disable request body compression when pushing metrics to every
# Pushmetrics URL
              - disable_compression: 'true'
# Optional labels to add to metrics pushed to every Pushmetrics URL. For
# example, 'instance="foo"' adds `instance="foo"` label to all the metrics
# pushed to every Pushmetrics URL
                extra_label:
                  - 'instance="foo"'
                  - 'job="bar"'
# Optional HTTP request header to send to every Pushmetrics URL. For example,
# 'Authorization: Basic foobar' adds `Authorization: Basic foobar` header to
# every request to every Pushmetrics URL
                header: 'Authorization: Basic foobar'
# Interval for pushing metrics to every Pushmetrics URL (default is '10s')
                interval: '10s'
# Optional URL to push metrics exposed at '/metrics' page. By default, metrics
# exposed at '/metrics' page aren't pushed to any remote storage
                url:
                  - 'https://victoria-metrics:8428/api/v1/import/prometheus'
                  - 'https://user:pass@maas.victoriametrics.com/api/v1/import/prometheus'
# How many copies of every ingested sample is available across 'storage_node'
# nodes. `vmselect` continues returning full responses when up to
# 'replication_factor' - 1 `vmstorage` nodes are temporarily unavailable (
# default is '1')
            replication_factor: '1'
            search:
# The maximum duration since the current time for response data, which is always
# queried from the original raw data, without using the response cache. Increase
# this value if you see gaps in responses due to time synchronization issues
# between VictoriaMetrics and data sources (default is '5m')
              - cache_timestamp_offset: '5m'
# Whether to deny partial responses if a part of 'storage_node' instances fail
# to perform queries, this trades availability over consistency
                deny_partial_response: 'true'
# Whether to disable response caching. This may be useful when ingesting
# historical data
                disable_cache: 'true'
# Whether to return an error for queries that rely on implicit subquery
# conversions
                disable_implicit_conversion: 'true'
# The maximum number of points per series Graphite render API can return (
# default is '1000000')
                graphite_max_points_per_series: '1000000'
# The interval between datapoints stored in the database. It is used at Graphite
# Render API handler for normalizing the interval between datapoints in case it
# isn't normalized. It can be overridden by sending 'storage_step' query arg to
# '/render' API or by sending the desired interval via 'Storage-Step' http
# header during querying '/render' API (default is '10s')
                graphite_storage_step: '10s'
# Whether to ignore "match[]", "extra_filters[]" and "extra_label" query args at
# '/api/v1/labels' and '/api/v1/label/.../values' . This may be useful for
# decreasing load on VictoriaMetrics when extra filters match too many time
# series. The downside is that superfluous labels or series could be returned,
# which do not match the extra filters
                ignore_extra_filters_at_labels_api: 'true'
# Size for in-memory data blocks used during processing search requests. By
# default, the size is automatically calculated based on available memory.
# Adjust this flag value if you observe that
# `vm_tmp_blocks_max_inmemory_file_size_bytes` metric constantly shows much
# higher values than `vm_tmp_blocks_inmemory_file_size_bytes`. Supports the
# following optional suffixes for size values: 'KB', 'MB', 'GB', 'TB', 'KiB',
# 'MiB', 'GiB', 'TiB' (default is '0')
                inmemory_buf_size_bytes: '0'
# The time when data points become visible in query results after the
# collection. It can be overridden on per-query basis via latency_offset arg.
# Too small value can result in incomplete last points for query results (
# default is '30s')
                latency_offset: '30s'
# Whether to log queries with implicit subquery conversions, see
# https://docs.victoriametrics.com/metricsql/#subqueries for details. Such
# conversion can be disabled using 'disable_implicit_conversion'
                log_implicit_conversion: 'true'
# Log query and increment vm_memory_intensive_queries_total metric each time
# he query requires more memory than specified by this flag. This may help
# detecting and optimizing heavy queries. Query logging is disabled by default.
# Supports the following optional suffixes for size values: 'KB', 'MB', 'GB',
# 'TB', 'KiB', 'MiB', 'GiB', 'TiB' (default is '0')
                log_query_memory_usage: '0'
# Log queries with execution time exceeding this value. Zero disables slow
# query logging (default is '5s')
                log_slow_query_duration: '5s'
# The maximum number of values for a label in the first expression that can be
# extracted as a common label filter and pushed down to the second expression
# in a binary operation. A larger value makes the pushed-down filter more
# complex but fewer time series will be returned. This flag is useful when
# selective label contains numerous values, for example instance, and storage
# resources are abundant (default is '100')
                max_binary_op_pushdown_label_values: '100'
# The maximum number of concurrent search requests. It shouldn't be high, since
# a single request can saturate all the CPU cores, while many concurrently
# executed requests may require high amounts of memory (default is '8')
                max_concurrent_requests: '8'
# The maximum duration for '/api/v1/admin/tsdb/delete_series' call (default is
# '5m')
                max_delete_duration: '5m'
# The maximum number of time series, which can be deleted using
# '/api/v1/admin/tsdb/delete_series'. This option allows limiting memory usage
# (default is '1000000')
                max_delete_series: '1000000'
# The maximum duration for '/api/v1/export' call (default is '720h')
                max_export_duration: '720h'
# The maximum number of time series, which can be returned from
# '/api/v1/export*' APIs. This option allows limiting memory usage
# (default is '10000000')
                max_export_series: '10000000'
# The maximum number of time series, which can be returned from '/federate'.
# This option allows limiting memory usage (default '1000000')
                max_federate_series: '1000000'
# The maximum number of time series, which can be scanned during queries to
# Graphite Render API (default is '300000')
                max_graphite_series: '300000'
# The maximum number of tag keys returned from Graphite API, which returns tags
# (default is '100000')
                max_graphite_tag_keys: '100000'
# The maximum number of tag values returned from Graphite API, which returns
# tag values (default is '100000')
                max_graphite_tag_values: '100000'
# The maximum duration for '/api/v1/labels', '/api/v1/label/.../values' and
# '/api/v1/series' requests (default is '5s')
                max_labels_api_duration: '5s'
# The maximum number of time series, which could be scanned when searching for
# the matching time series at '/api/v1/labels' and '/api/v1/label/.../values'.
# This option allows limiting memory usage and CPU usage (default is '1000000')
                max_labels_api_series: '1000000'
# Synonym to "-search.lookback-delta" from Prometheus. The value is
# dynamically detected from interval between time series datapoints if not set.
# It can be overridden on per-query basis via 'max_lookback' arg. See also
# 'max_staleness_interval' flag, which has the same meaning due to historical
# reasons
                max_lookback: ''
# The maximum amounts of memory a single query may consume. Queries requiring
# more memory are rejected. The total memory limit for concurrently executed
# queries can be estimated as 'max_memory_per_query' multiplied by
# 'max_concurrent_requests'. Supports the following optional suffixes for size
# values: 'KB', 'MB', 'GB', 'TB', 'KiB', 'MiB', 'GiB', 'TiB' (default is '0')
                max_memory_per_query: '0'
# The maximum points per a single timeseries returned from
# '/api/v1/query_range'. This option doesn't limit the number of scanned raw
# samples in the database. The main purpose of this option is to limit the
# number of per-series points returned to graphing UI such as VMUI or Grafana.
# There is no sense in setting this limit to values bigger than the horizontal
# resolution of the graph (default is '30000')
                max_points_per_timeseries: '30000'
# The maximum number of points per series, which can be generated by subquery
# (default is '100000')
                max_points_subquery_per_timeseries: '100000'
# The maximum duration for query execution. It can be overridden to a smaller
# value on a per-query basis via 'timeout' query arg (default is '30s')
                max_query_duration: '30s'
# The maximum search query length in bytes. Supports the following optional
# suffixes for size values: 'KB', 'MB', 'GB', 'TB', 'KiB', 'MiB', 'GiB', 'TiB'
# (default is '16384')
                max_query_len: '16384'
# The maximum time the request waits for execution when
# 'max_concurrent_requests' limit is reached (default is '10s')
                max_queue_duration: '10s'
# The maximum number of time series which can be returned from
# '/api/v1/query' and '/api/v1/query_range'. The limit is disabled if it equals
# to '0'
                max_response_series: '0'
# The maximum number of raw samples a single query can process across all time
# series. This protects from heavy queries, which select unexpectedly high
# number of raw samples. See also -search.maxSamplesPerSeries (default is
# '1000000000')
                max_samples_per_query: '1000000000'
# The maximum number of raw samples a single query can scan per each time
# series (default is '30000000')
                max_samples_per_series:
# The maximum number of time series, which can be returned from
# '/api/v1/series'. This option allows limiting memory usage (default is
# '30000')
                max_series: '30000'
# The maximum number of time series an aggregate MetricsQL function can generate
# (default is '1000000')
                max_series_per_aggr_func: '1000000'
# The maximum interval for staleness calculations. By default, it is
# automatically calculated from the median interval between samples. This flag
# could be useful for tuning Prometheus data model closer to Influx-style data
# model
                max_staleness_interval: ''
# The maximum duration for '/api/v1/status/*'' requests (default is '5m')
                max_status_request_duration: '5m'
# The maximum step when /api/v1/query_range handler adjusts points with
# timestamps closer than 'latency_offset' to the current time. The adjustment is
# needed because such points may contain incomplete data (default is '1m')
                max_step_for_points_adjustment: '1m'
# The maximum number of time series, which can be processed during the call to
# '/api/v1/status/tsdb'. This option allows limiting memory usage (default is
# '10000000')
                max_tsdb_status_series: '10000000'
# The maximum number of tag value suffixes returned from '/metrics/find'
# (default is '100000')
                max_tag_value_suffixes_per_search: '100000'
# The maximum number of unique time series, which can be selected during
# '/api/v1/query' and '/api/v1/query_range' queries. This option allows limiting
# memory usage. The limit can't exceed the explicitly set corresponding value
# 'max_unique_timeseries' on `vmstorage` side
                max_unique_timeseries: ''
# The maximum number of CPU cores a single query can use. The default value
# should work good for most cases. The flag can be set to lower values for
# improving performance of big number of concurrently executed queries. The
# flag can be set to bigger values for improving performance of heavy queries,
# which scan big number of time series (>10K) and/or big number of samples
# (>100M). There is no sense in setting this flag to values bigger than the
# number of CPU cores available on the system (default is '4')
                max_workers_per_query: '4'
# The minimum interval for staleness calculations. This flag could be useful
# for removing gaps on graphs generated from time series with irregular
# intervals between samples
                min_staleness_interval: ''
# Enable cache-based optimization for repeated queries to '/api/v1/query' (aka
# instant queries), which contain rollup functions with lookbehind window
# exceeding the given value (default '3h')
                min_window_for_instant_rollup_optimization: '3h'
# Set this flag to 'true' if the database doesn't contain Prometheus stale
# markers, so there is no need in spending additional CPU time on its handling.
# Staleness markers may exist only in data obtained from Prometheus scrape
# targets
                no_stale_markers: 'true'
# Query stats for '/api/v1/status/top_queries' is tracked on this number of
# last queries. Zero value disables query stats tracking (default is '20000')
                query_stats_last_queries_count: '20000'
# The minimum duration for queries to track in query stats at
# '/api/v1/status/top_queries'. Queries with lower duration are ignored in
# query stats (default is '1ms')
                query_stats_min_query_duration: '1ms'
# Optional authKey for resetting rollup cache via
# '/internal/resetRollupResultCache' call. It could be passed via 'auth_key'
# query arg. Value can be read from the given file when using
# 'file:///abs/path/to/file' or 'file://./relative/path/to/file'. Flag value
# can be read from the given http/https url when using 'http://host/path' or
# 'https://host/path'
                reset_cache_auth_key: ''
# Whether to reset rollup result cache on startup
                reset_rollup_result_cache_on_startup: 'true'
# Whether to fix lookback interval to 'step' query arg value. If set to 'true',
# the query model becomes closer to InfluxDB data model. If set to 'true', then
# 'max_lookback' and 'max_staleness_interval' are ignored
                set_lookback_to_step: 'true'
# Whether to skip 'replication_factor' - 1 slowest `vmstorage` nodes during
# querying. Enabling this setting may improve query speed, but it could also
# lead to incomplete results if some queried data has less than
# 'replication_factor' copies at `vmstorage` nodes. Consider enabling this
# setting only if all the queried data contains 'replication_factor' copies in
# the cluster
                skip_slow_replicas: 'true'
# The expiry duration for list of tenants for multi-tenant queries. (default
# is '5m')
                tenant_cache_expire_duration: '5m'
# Addresses of `vmselect` nodes
            select_node:
              - 'vmselect-host1'
              - 'vmselect-host2'
# List of addresses of `vmstorage` nodes. Enterprise version of VictoriaMetrics
# supports automatic discovery of `vmstorage` addresses via DNS SRV records
            storage_node:
              - 'vm1.example.com:8400'
              - 'vm2.example.com:8400'
              - 'srv+vmstorage.addrs'
# Whether to enable TLS for incoming HTTP requests at the 'http_listen_addr'
            tls:
# Path to file with TLS certificate for the corresponding 'http_listen_addr'.
# Prefer ECDSA certs instead of RSA certs as RSA certs are slower. The provided
# certificate file is automatically re-read every second, so it can be
# dynamically updated
              - cert_file: '/etc/pki/tls/private/le/fullchain.pem'
#  Path to file with TLS key for the corresponding 'http_listen_addr'. The
# provided key file is automatically re-read every second, so it can be
# dynamically updated
                key_file: '/etc/pki/tls/private/le/privkey.pem'
# Optional list of TLS cipher suites for incoming requests over HTTPS. See the
# list of supported cipher suites at https://pkg.go.dev/crypto/tls#pkg-constants
                cipher_suites: ''
# Optional minimum TLS version to use for the corresponding http_listen_addr'.
# Supported values: 'TLS10', 'TLS11', 'TLS12', 'TLS13'
                min_version: 'TLS13'
# Optional URL for proxying requests to `vmalert`. For example, if value is
# 'http://vmalert:8880', then alerting API requests such as '/api/v1/rules' from
# Grafana will be proxied to 'http://vmalert:8880/api/v1/rules'
                vmalert_proxy_url: 'http://vmalert:8880'
# Timeout for establishing RPC connections from `vmselect` to `vmstorage`
# (default is '3s')
                vmstorage_dial_timeout: '3s'
# Network timeout for RPC connections from `vmselect` to `vmstorage` (Linux
# only). Lower values reduce the maximum query durations when some `vmstorage`
# nodes become unavailable because of networking issues (default is '3s')
                vmstorage_user_timeout: '3s'
# Optional path to `vmui` dashboards
                vmui_custom_dashboards_path: ''
# The default timezone to be used in `vmui`. Timezone must be a valid IANA Time
# Zone. For example: `America/New_York`, `Etc/GMT+3` or `Local`
                vmui_default_timezone: 'Asia/Novosibirsk'
```
