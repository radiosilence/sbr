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

/* Stop and free. In-flight connections are torn down. Blocks until done. */
void sbr_stop(SbrInstance *instance);

/* Switch a selector group. Returns 1 on success, 0 if group/member unknown. */
int32_t sbr_select(SbrInstance *instance, const char *group, const char *member);

/* JSON: [{"tag":"proxy","type":"selector","selected":"a","members":["a","b"]}] */
char *sbr_groups(SbrInstance *instance);

/* Bytes relayed so far (live) and currently open TCP connections. Any
 * out-pointer may be NULL. */
void sbr_stats(SbrInstance *instance, uint64_t *up, uint64_t *down, uint64_t *active);

/* Memory and traffic. `instance` may be NULL (memory figures only). */
void sbr_runtime_stats(SbrInstance *instance, SbrRuntimeStats *out);

/* The default network path changed (NWPathMonitor). Drops state bound to the
 * old path (UDP sessions; later pooled upstream connections and the DNS
 * cache). Open TCP connections are left to survive or fail on their own. */
void sbr_network_changed(SbrInstance *instance);

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
