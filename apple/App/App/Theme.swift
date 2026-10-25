import CoreText
import SwiftUI

// kōan's design language (see koan/docs/design/koan-theme.md): one mono face,
// lowercase UI text, square corners, hairlines instead of shadows or glass, a
// neutral ground and a single mint accent.

extension Color {
    static func sbr(dark: UInt32, light: UInt32) -> Color {
        #if os(macOS)
        Color(nsColor: NSColor(name: nil) { appearance in
            NSColor(hex: appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? dark : light)
        })
        #else
        Color(uiColor: UIColor { $0.userInterfaceStyle == .dark ? UIColor(hex: dark) : UIColor(hex: light) })
        #endif
    }

    static let sbrBg = sbr(dark: 0x1E1E1E, light: 0xFFFFFF)
    static let sbrSurface = sbr(dark: 0x2A2A2A, light: 0xF2F2F2)
    static let sbrRule = sbr(dark: 0x383838, light: 0xE0E0E0)
    static let sbrHover = sbr(dark: 0x4D4D4D, light: 0xC4C4C4)
    static let sbrInk = sbr(dark: 0xCCCCCC, light: 0x333333)
    static let sbrStrong = sbr(dark: 0xFFFFFF, light: 0x111111)
    static let sbrMuted = sbr(dark: 0x919191, light: 0x666666)
    static let sbrBad = sbr(dark: 0xEF6B73, light: 0xC43F3F)
    static let sbrAccent = sbr(dark: 0x7DD3A7, light: 0x1F7A50)
}

#if os(macOS)
extension NSColor {
    convenience init(hex: UInt32) {
        self.init(srgbRed: CGFloat((hex >> 16) & 0xFF) / 255, green: CGFloat((hex >> 8) & 0xFF) / 255,
                  blue: CGFloat(hex & 0xFF) / 255, alpha: 1)
    }
}
#else
extension UIColor {
    convenience init(hex: UInt32) {
        self.init(red: CGFloat((hex >> 16) & 0xFF) / 255, green: CGFloat((hex >> 8) & 0xFF) / 255,
                  blue: CGFloat(hex & 0xFF) / 255, alpha: 1)
    }
}
#endif

enum SbrType {
    case display, title, body, control, meta, fine

    var size: CGFloat {
        let base: CGFloat = switch self {
        case .display: 34
        case .title: 22
        case .body: 15
        case .control: 14
        case .meta: 13
        case .fine: 12
        }
        #if os(tvOS)
        return base * 1.8
        #elseif os(macOS)
        return base * 0.86
        #else
        return base
        #endif
    }

    var weight: Font.Weight {
        switch self {
        case .display: .ultraLight
        case .title: .light
        default: .regular
        }
    }

    var relative: Font.TextStyle {
        switch self {
        case .display: .largeTitle
        case .title: .title2
        case .body: .body
        case .control: .callout
        case .meta: .subheadline
        case .fine: .footnote
        }
    }
}

extension Font {
    static func sbr(_ type: SbrType) -> Font {
        .custom("Geist Mono", size: type.size, relativeTo: type.relative).weight(type.weight)
    }
}

enum Theme {
    enum Space {
        static let xs: CGFloat = 4
        static let s: CGFloat = 8
        static let m: CGFloat = 12
        static let l: CGFloat = 16
        static let xl: CGFloat = 22
        static let xxl: CGFloat = 32
    }

    static let hairline: CGFloat = 1

    /// The one curve: quick out, no overshoot.
    static func motion(_ seconds: Double) -> Animation { .timingCurve(0.2, 0.9, 0.3, 1, duration: seconds) }
    static let fast = motion(0.08)
    static let normal = motion(0.12)
    static let settle = motion(0.25)

    /// Geist Mono ships as a resource and is registered for this process only.
    static func registerFont() {
        guard let url = Bundle.main.url(forResource: "geist-mono", withExtension: "woff2") else { return }
        CTFontManagerRegisterFontsForURL(url as CFURL, .process, nil)
    }
}

struct SbrButtonStyle: ButtonStyle {
    enum Kind { case prominent, standard, bordered, text }
    var kind: Kind = .standard
    @Environment(\.isEnabled) private var enabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.sbr(kind == .prominent ? .body : .control))
            .textCase(.lowercase)
            .lineLimit(1)
            .foregroundStyle(foreground)
            .padding(.vertical, kind == .prominent ? 12 : 6)
            .padding(.horizontal, kind == .prominent ? 20 : (kind == .text ? 0 : 12))
            .frame(minHeight: 44)
            .background(configuration.isPressed ? Color.sbrHover : .clear)
            .overlay {
                if let outline { Rectangle().strokeBorder(outline, lineWidth: Theme.hairline) }
            }
            .contentShape(Rectangle())
            .opacity(enabled ? 1 : 0.4)
            .animation(Theme.fast, value: configuration.isPressed)
    }

    private var foreground: Color {
        switch kind {
        case .prominent: .sbrAccent
        case .text: .sbrMuted
        default: .sbrInk
        }
    }

    private var outline: Color? {
        switch kind {
        case .prominent: .sbrAccent
        case .bordered: .sbrMuted
        default: nil
        }
    }
}

extension View {
    func sbrButton(_ kind: SbrButtonStyle.Kind = .standard) -> some View { buttonStyle(SbrButtonStyle(kind: kind)) }
}

/// A lowercase section label with breathing room above, no rule.
struct SectionHeader: View {
    let title: String
    var trailing: AnyView?

    init(_ title: String) { self.title = title }
    init(_ title: String, @ViewBuilder trailing: () -> some View) {
        self.title = title
        self.trailing = AnyView(trailing())
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(title).font(.sbr(.fine)).textCase(.lowercase).foregroundStyle(Color.sbrMuted)
            Spacer()
            trailing
        }
        .padding(.top, Theme.Space.xl)
        .padding(.bottom, Theme.Space.s)
    }
}

/// A faint rule between rows: ink at 12%.
struct RowRule: View {
    var body: some View {
        Rectangle().fill(Color.sbrInk.opacity(0.12)).frame(height: Theme.hairline)
    }
}
