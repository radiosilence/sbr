/* sbr C ABI. All strings are UTF-8, NUL-terminated. Strings returned by sbr
 * (other than sbr_version) must be released with sbr_string_free. Every
 * function is safe to call from any thread, and none lets a Rust panic
 * escape. Do not call sbr_stop or sbr_reload from inside the log callback. */
#ifndef SBR_H
#define SBR_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SbrInstance SbrInstance;

/* Options for sbr_start_ex. Always start from sbr_start_options_default()
 * so new fields get sane values. */
typedef struct SbrStartOptions {
    /* Nullable. Resolves relative paths such as local rule-sets. */
    const char *base_dir;
    /* Pre-opened TUN fd (see sbr_find_tun_fd), or -1. The tun inbound adopts
     * it instead of creating an interface; routes and DNS are the host's job
     * (NEPacketTunnelNetworkSettings). sbr dup()s it on every start, so the
     * caller keeps ownership of this fd and it survives sbr_reload. */
    int32_t tun_fd;
    /* 0: platform default (1 on iOS/tvOS, CPU count capped at 8 elsewhere).
     * 1: a single-threaded runtime (fewest wakeups). N > 1: N worker threads. */
    int32_t threads;
    /* Per-direction relay buffer in bytes; 0: default (16 KiB on iOS/tvOS,
     * 64 KiB elsewhere). Each TCP connection holds two. */
    uint32_t relay_buffer;
    /* Cap on concurrent TCP connections, and separately on UDP sessions;
     * over it new ones are refused. 0: unlimited. Default: 512 on iOS/tvOS
     * (16 MB of relay buffers at 16 KiB), unlimited elsewhere. */
    uint32_t max_connections;
} SbrStartOptions;

typedef struct SbrRuntimeStats {
    /* Bytes charged to the process: phys_footprint on Apple (what jetsam
     * counts), RSS on Linux. */
    uint64_t memory_footprint;
    /* Bytes left before jetsam (os_proc_available_memory, iOS/tvOS); 0 when
     * unknown or unlimited (macOS). */
    uint64_t memory_available;
    /* TCP connections being routed, connected or relayed. */
    uint64_t active_connections;
    uint64_t udp_sessions;
    /* Bytes relayed since start, including connections still open. */
    uint64_t uplink_bytes;
    uint64_t downlink_bytes;
} SbrRuntimeStats;

/* Log levels passed to the callback. */
#define SBR_LOG_TRACE 0
#define SBR_LOG_DEBUG 1
#define SBR_LOG_INFO 2
#define SBR_LOG_WARN 3
#define SBR_LOG_ERROR 4

/* Called from sbr's threads, possibly concurrently; `message` is only valid
 * during the call. */
typedef void (*SbrLogCallback)(int32_t level, const char *message, void *context);

/* Static string; do not free. */
const char *sbr_version(void);

/* Validate a sing-box JSON config. Returns NULL if it is valid, otherwise an
 * error message naming the offending JSON path. */
char *sbr_check(const char *config_json);

SbrStartOptions sbr_start_options_default(void);

/* Start an instance. On failure returns NULL and, if `error_out` is non-NULL,
 * stores an error message there. `options` may be NULL for defaults. */
SbrInstance *sbr_start_ex(const char *config_json, const SbrStartOptions *options, char **error_out);

/* sbr_start_ex with default options, base_dir set and no TUN fd. */
SbrInstance *sbr_start(const char *config_json, const char *base_dir, char **error_out);

/* Replace the running config: validate, stop, start again with the same
 * options (and the same TUN fd). Returns NULL on success, else an error. A
 * config that fails validation leaves the old one running; a failure while
 * starting (e.g. a port in use) leaves the instance stopped until the next
 * successful sbr_reload. */
char *sbr_reload(SbrInstance *instance, const char *config_json);

/* Called once per sbr_fetch_profile, from an sbr thread: `profile` is the
 * downloaded text and `error` NULL, or `profile` NULL and `error` why. Both
 * are only valid during the call. Do not call sbr_stop, sbr_reload or
 * sbr_apply_profile from inside it. */
typedef void (*SbrFetchCallback)(void *context, const char *profile, const char *error);

/* Download a remote profile from `url` (https only) through the running
 * config's route rules, as a connection arriving on its tun inbound would
 * go, so it leaves through the tunnel's outbounds rather than around them.
 * No User-Agent or other identifying header is sent. Returns 1 if started,
 * and `callback` then runs exactly once (with an error if the instance stops
 * or reloads first); 0 if `url` is not https or nothing is running, and
 * `callback` is never called. The download is not validated: pass the text
 * to sbr_apply_profile. */
int32_t sbr_fetch_profile(SbrInstance *instance, const char *url, SbrFetchCallback callback, void *context);

/* sbr_apply_profile results. */
#define SBR_PROFILE_UNCHANGED 0
#define SBR_PROFILE_RELOADED 1
/* Valid, but its tun inbound wants different interface settings: apply
 * sbr_tun_network_settings for it, then sbr_reload. */
#define SBR_PROFILE_NEEDS_NETWORK_SETTINGS 2

/* Run `config_json` unless it is exactly the running config: validate, then
 * reload as sbr_reload does. Returns an SBR_PROFILE_* value, or -1 with
 * `error_out` set. After -1 or SBR_PROFILE_NEEDS_NETWORK_SETTINGS the running
 * config is untouched (barring a failure while starting, as for sbr_reload). */
int32_t sbr_apply_profile(SbrInstance *instance, const char *config_json, char **error_out);

/* Stop and free. In-flight connections are torn down. Blocks until done. */
void sbr_stop(SbrInstance *instance);

/* Switch a selector group. Returns 1 on success, 0 if group/member unknown. */
int32_t sbr_select(SbrInstance *instance, const char *group, const char *member);

/* JSON: [{"tag":"proxy","type":"selector","selected":"auto","now":"hy2-a-443",
 *         "delay":38,"members":[{"tag":"auto","type":"urltest","delay":38,
 *         "degraded":false,"reason":null,"retry_in":null}, ...]}]
 * `now` is the leaf the group currently resolves to; `delay` is the last
 * measured latency in ms, or null when untested.
 *
 * Per member, for the leaf it resolves to:
 * - `degraded`: the path completed handshakes but stopped carrying data,
 *   so urltest groups skip it (unless no healthy member is left).
 * - `reason`: why, or null when healthy:
 *     "frozen"      a data probe stopped receiving mid-transfer (the TSPU
 *                   16-20 KB freeze);
 *     "reset"       connections or a data probe were reset right after the
 *                   handshake;
 *     "closed"      connections were closed before any data came back;
 *     "no_response" requests went unanswered with nothing received;
 *     "connect"     connections failed to open.
 *   The last four degrade only when several destinations fail at once.
 * - `retry_in`: seconds until the path is probed again (0: waiting for its
 *   group's next probe), or null when healthy. The exclusion starts at
 *   120 s and doubles on each relapse, up to 30 min. */
char *sbr_groups(SbrInstance *instance);

/* Start a latency test of a urltest group (or of a selector's urltest
 * members) and return at once; results appear in sbr_groups. 1 = started. */
int32_t sbr_url_test(SbrInstance *instance, const char *group);

/* Open connections (TCP streams and UDP sessions), newest first, as JSON:
 * {"total":312,"upload_total":1024,"download_total":4096,
 *  "connections":[{"id":"3f2a...-8b1c-000000000123","network":"tcp",
 *    "inbound":"tun/tun-in","source":"172.19.0.1:50123",
 *    "destination":"1.2.3.4:443","domain":"example.com","ip":"1.2.3.4",
 *    "protocol":"tls","chain":["hy2-a","auto","proxy"],
 *    "rule":"domain_suffix=[example.com] => route(proxy)",
 *    "upload":512,"download":2048,"start":1761397200123}, ...]}
 * `total` counts every open connection; at most `limit` are listed (0 or
 * anything above 200 means 200). `destination` is the address as requested;
 * `domain` is the requested or sniffed domain and `ip` the resolved address,
 * each null when unknown; `protocol` is the sniffed protocol or null.
 * `chain` runs from the leaf outbound to the one the rule chose; `rule` is
 * "final" for route.final. Byte counts are live; `start` is Unix ms.
 * `*_total` include closed connections. NULL when the instance is stopped. */
char *sbr_connections(SbrInstance *instance, uint32_t limit);

/* Close the connection with this `id` from sbr_connections. 1 if it was
 * open, 0 otherwise. */
int32_t sbr_close_connection(SbrInstance *instance, const char *id);

/* Bytes relayed so far (live) and currently open TCP connections. Any
 * out-pointer may be NULL. */
void sbr_stats(SbrInstance *instance, uint64_t *up, uint64_t *down, uint64_t *active);

/* Memory and traffic. `instance` may be NULL (memory figures only). */
void sbr_runtime_stats(SbrInstance *instance, SbrRuntimeStats *out);

/* The default network path changed (NWPathMonitor). Drops state bound to the
 * old path (UDP sessions; later pooled upstream connections and the DNS
 * cache). Open TCP connections are left to survive or fail on their own. */
void sbr_network_changed(SbrInstance *instance);

/* NEPacketTunnelNetworkSettings for the config's tun inbound, as JSON
 * (sing-box libbox semantics; rules in src/tun_settings.rs):
 * {"mtu":9000,
 *  "ipv4":{"addresses":["172.19.0.1"],"prefixes":[30],"subnet_masks":["255.255.255.252"],
 *          "included_routes":[{"address":"0.0.0.0","prefix":0,"subnet_mask":"0.0.0.0"}],
 *          "excluded_routes":[]},
 *  "ipv6":null or the same shape,
 *  "dns_servers":["172.19.0.2"], "auto_route":true, "strict_route":false}
 * On error (bad config, no tun inbound) returns NULL and sets `error_out`. */
char *sbr_tun_network_settings(const char *config_json, char **error_out);

/* Inside an NEPacketTunnelProvider: the utun fd NetworkExtension opened for
 * this process, or -1. Call after setTunnelNetworkSettings completes. Always
 * -1 on non-Apple platforms. */
int32_t sbr_find_tun_fd(void);

/* Route sbr's logs to `callback` (NULL: back to stderr). Takes effect
 * process-wide; the level comes from the config's `log` section. After this
 * returns, the previous callback and context are no longer used. */
void sbr_set_log_callback(SbrLogCallback callback, void *context);

void sbr_string_free(char *s);

#ifdef __cplusplus
}
#endif

#endif
