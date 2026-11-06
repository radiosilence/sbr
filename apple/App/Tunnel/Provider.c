// The packet tunnel provider is SbrTunnelProvider, an NEPacketTunnelProvider
// subclass defined in Rust (crates/sbr-tunnel-ext) and linked from
// SbrTunnel.xcframework. The library registers the class with the
// Objective-C runtime as the extension loads; this reference is what makes
// the linker take it from the archive at all.
extern void sbr_tunnel_provider_register(void);

__attribute__((used)) static void (*const sbr_tunnel_provider)(void) = sbr_tunnel_provider_register;
