// os_log is a macro that builds its format buffer at the call site, so Rust
// reaches it through this function. The first argument is logged public,
// the second private (redacted in Console unless a profile allows it); an
// empty private part is left out rather than shown as "<private>".
#include <os/log.h>
#include <stdint.h>

void sbr_tunnel_os_log(os_log_t log, uint8_t type, const char *public_part, const char *private_part) {
    if (private_part[0] == '\0') {
        os_log_with_type(log, (os_log_type_t)type, "%{public}s", public_part);
    } else {
        os_log_with_type(log, (os_log_type_t)type, "%{public}s%{private}s", public_part, private_part);
    }
}
