/* sbr C ABI. All strings are UTF-8, NUL-terminated. Strings returned by sbr
 * must be released with sbr_string_free. Every function is safe to call from
 * any thread. */
#ifndef SBR_H
#define SBR_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SbrInstance SbrInstance;

/* Validate a sing-box JSON config. Returns NULL if it is valid, otherwise an
 * error message naming the offending JSON path. */
char *sbr_check(const char *config_json);

/* Start an instance. `base_dir` (nullable) resolves relative paths such as
 * local rule-sets. On failure returns NULL and, if `error_out` is non-NULL,
 * stores an error message there. */
SbrInstance *sbr_start(const char *config_json, const char *base_dir, char **error_out);

/* Stop and free. In-flight connections are torn down. */
void sbr_stop(SbrInstance *instance);

/* Switch a selector group. Returns 1 on success, 0 if group/member unknown. */
int32_t sbr_select(SbrInstance *instance, const char *group, const char *member);

/* JSON: [{"tag":"proxy","type":"selector","selected":"a","members":["a","b"]}] */
char *sbr_groups(SbrInstance *instance);

/* Cumulative bytes for closed connections, and currently open connections. */
void sbr_stats(SbrInstance *instance, uint64_t *up, uint64_t *down, uint64_t *active);

void sbr_string_free(char *s);

#ifdef __cplusplus
}
#endif

#endif
