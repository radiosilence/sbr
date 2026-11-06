// os_log is a macro that builds its format buffer at the call site, so Rust
// reaches it through this function. The first argument is logged public,
// the second private (redacted in Console unless a profile allows it).
#include <os/log.h>
#include <stdint.h>

void sbr_tunnel_os_log(os_log_t log, uint8_t type, const char *public_part, const char *private_part) {
    os_log_with_type(log, (os_log_type_t)type, "%{public}s%{private}s", public_part, private_part);
}
