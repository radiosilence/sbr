// The iOS and macOS app is the sbr-gui Rust library (SbrGui.xcframework);
// this target exists so Xcode builds, signs and packages it with its
// extensions.
extern void sbr_gui_main(void);

int main(void) {
    sbr_gui_main();
    return 0;
}
