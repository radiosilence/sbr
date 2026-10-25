/* Links libsbr_apple.a through include/sbr.h and calls every entry point.
 * Built and run by tests/c_abi.rs; exits non-zero on the first failure. */
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sbr.h"

#define CHECK(cond)                                                         \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); \
            exit(1);                                                        \
        }                                                                   \
    } while (0)

static const char *CONFIG =
    "{\"log\":{\"level\":\"debug\"},"
    "\"inbounds\":[{\"type\":\"mixed\",\"tag\":\"in\",\"listen\":\"127.0.0.1\",\"listen_port\":0}],"
    "\"outbounds\":[{\"type\":\"selector\",\"tag\":\"proxy\",\"outbounds\":[\"a\",\"b\"]},"
    "{\"type\":\"direct\",\"tag\":\"a\"},{\"type\":\"direct\",\"tag\":\"b\"}]}";

static atomic_int log_lines;

static void on_log(int32_t level, const char *message, void *context) {
    CHECK(context == (void *)&log_lines);
    CHECK(level >= SBR_LOG_TRACE && level <= SBR_LOG_ERROR);
    CHECK(message != NULL);
    atomic_fetch_add(&log_lines, 1);
}

int main(void) {
    printf("sbr %s\n", sbr_version());

    CHECK(sbr_check(CONFIG) == NULL);
    char *err = sbr_check("{\"outbounds\":[{\"type\":\"warp-drive\"}]}");
    CHECK(err != NULL && strstr(err, "outbounds[0].type") != NULL);
    sbr_string_free(err);
    sbr_string_free(NULL);

    sbr_set_log_callback(on_log, &log_lines);

    SbrStartOptions opts = sbr_start_options_default();
    CHECK(opts.tun_fd == -1 && opts.base_dir == NULL);
    opts.threads = 1;
    opts.max_connections = 64;
    err = NULL;
    SbrInstance *sbr = sbr_start_ex(CONFIG, &opts, &err);
    CHECK(sbr != NULL && err == NULL);

    CHECK(sbr_select(sbr, "proxy", "b") == 1);
    CHECK(sbr_select(sbr, "proxy", "nope") == 0);
    char *groups = sbr_groups(sbr);
    CHECK(groups != NULL && strstr(groups, "\"selected\":\"b\"") != NULL);
    sbr_string_free(groups);

    char *conns = sbr_connections(sbr, 0);
    CHECK(conns != NULL && strstr(conns, "\"connections\":[]") != NULL);
    sbr_string_free(conns);
    CHECK(sbr_close_connection(sbr, "00000000-0000-4000-8000-000000000001") == 0);
    CHECK(sbr_close_connection(sbr, NULL) == 0);

    uint64_t up = 1, down = 1, active = 1;
    sbr_stats(sbr, &up, &down, &active);
    CHECK(up == 0 && down == 0 && active == 0);
    sbr_stats(sbr, NULL, NULL, NULL);

    SbrRuntimeStats st;
    memset(&st, 0xff, sizeof st);
    sbr_runtime_stats(sbr, &st);
    CHECK(st.active_connections == 0 && st.udp_sessions == 0);
    CHECK(st.memory_footprint > 0);
    printf("footprint %llu bytes\n", (unsigned long long)st.memory_footprint);

    sbr_network_changed(sbr);
    CHECK(sbr_find_tun_fd() == -1); /* not inside a Network Extension */

    err = sbr_reload(sbr, "{not json");
    CHECK(err != NULL);
    sbr_string_free(err);
    CHECK(sbr_reload(sbr, CONFIG) == NULL);
    groups = sbr_groups(sbr);
    CHECK(groups != NULL && strstr(groups, "\"selected\":\"a\"") != NULL); /* fresh start */
    sbr_string_free(groups);

    sbr_stop(sbr);
    sbr_set_log_callback(NULL, NULL);
    CHECK(atomic_load(&log_lines) > 0);

    err = NULL;
    CHECK(sbr_start("{bad", NULL, &err) == NULL && err != NULL);
    sbr_string_free(err);
    CHECK(sbr_start_ex("{bad", NULL, NULL) == NULL);

    char *net = sbr_tun_network_settings(
        "{\"inbounds\":[{\"type\":\"tun\",\"address\":[\"172.19.0.1/30\"],\"auto_route\":true}],"
        "\"outbounds\":[{\"type\":\"direct\"}]}",
        &err);
    CHECK(net != NULL && strstr(net, "\"dns_servers\":[\"172.19.0.2\"]") != NULL);
    sbr_string_free(net);
    err = NULL;
    CHECK(sbr_tun_network_settings(CONFIG, &err) == NULL && err != NULL); /* no tun inbound */
    sbr_string_free(err);

    printf("ok (%d log lines)\n", atomic_load(&log_lines));
    return 0;
}
