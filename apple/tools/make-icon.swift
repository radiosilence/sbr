// Renders the sbr app icon: a brush-drawn archway on near-black with a mint
// light at its threshold, in kōan's palette. Every artwork derived from it is
// drawn here from the same arch, so none can drift from the icon:
//
//   swift apple/tools/make-icon.swift <out.png> [size]
//       the full-bleed square icon; iOS masks it itself
//   swift apple/tools/make-icon.swift --mac <AppIcon.appiconset>
//       the macOS sizes: the artwork on the standard rounded tile, with the
//       grid's transparent margin and drop shadow, since macOS draws icons
//       unmasked. Rewrites the set's Contents.json, keeping the iOS entry.
//   swift apple/tools/make-icon.swift --glyph <Assets.xcassets>
//       the macOS menu bar glyphs: the arch as black-on-clear template PDFs,
//       with the light (MenuBarOn) and without it (MenuBarOff)
//   swift apple/tools/make-icon.swift --dmg-background <font.woff2> <out-dir>
//       the disk image window's background, background.png and
//       background@2x.png; the layout must match apple/dmg/settings.py
import CoreGraphics
import CoreText
import Foundation
import ImageIO
import UniformTypeIdentifiers

func rgb(_ hex: UInt32, _ a: CGFloat = 1) -> CGColor {
    CGColor(
        srgbRed: CGFloat((hex >> 16) & 0xFF) / 255,
        green: CGFloat((hex >> 8) & 0xFF) / 255,
        blue: CGFloat(hex & 0xFF) / 255,
        alpha: a
    )
}

let ground = 0x15151A as UInt32
let paper = 0xEDEAE2 as UInt32
let mint = 0x7DD3A7 as UInt32
let srgb = CGColorSpace(name: CGColorSpace.sRGB)!

// The arch: two legs and a round head, traced as one stroke with a slow,
// deterministic wobble so it reads as brushed rather than drawn. Unit
// coordinates, origin top-left.
func archPoints() -> [CGPoint] {
    let cx = 0.5, top = 0.215, foot = 0.775, r = 0.225
    let springY = top + r
    var pts: [CGPoint] = []
    let steps = 360
    let legLen = foot - springY
    let arcLen = Double.pi * r
    let total = 2 * legLen + arcLen
    for i in 0...steps {
        let d = Double(i) / Double(steps) * total
        var p: CGPoint
        var normal: CGPoint
        if d < legLen {
            p = CGPoint(x: cx - r, y: foot - d)
            normal = CGPoint(x: -1, y: 0)
        } else if d < legLen + arcLen {
            let a = Double.pi + (d - legLen) / r // π → 2π, over the top
            p = CGPoint(x: cx + r * cos(a), y: springY + r * sin(a))
            normal = CGPoint(x: cos(a), y: sin(a))
        } else {
            p = CGPoint(x: cx + r, y: springY + (d - legLen - arcLen))
            normal = CGPoint(x: 1, y: 0)
        }
        let t = d / total
        let wobble = 0.0045 * sin(t * 7.0 + 0.7) + 0.0025 * sin(t * 13.0 + 2.1)
        p.x += normal.x * wobble
        p.y += normal.y * wobble
        pts.append(p)
    }
    return pts
}

let light = CGPoint(x: 0.5, y: 0.705)

/// The icon's artwork over the unit square of the current transform.
func drawArtwork(_ ctx: CGContext) {
    ctx.setFillColor(rgb(ground))
    ctx.fill(CGRect(x: 0, y: 0, width: 1, height: 1))

    // The threshold light: a soft mint glow, then the light itself.
    let glow = CGGradient(
        colorsSpace: srgb,
        colors: [rgb(mint, 0.30), rgb(mint, 0.10), rgb(mint, 0)] as CFArray,
        locations: [0, 0.35, 1]
    )!
    ctx.drawRadialGradient(glow, startCenter: light, startRadius: 0, endCenter: light, endRadius: 0.30, options: [])

    let path = CGMutablePath()
    path.addLines(between: archPoints())
    ctx.setLineCap(.round)
    ctx.setLineJoin(.round)

    ctx.addPath(path)
    ctx.setStrokeColor(rgb(paper, 0.22))
    ctx.setLineWidth(46.0 / 512)
    ctx.strokePath()

    ctx.addPath(path)
    ctx.setStrokeColor(rgb(paper))
    ctx.setLineWidth(30.0 / 512)
    ctx.strokePath()

    ctx.setFillColor(rgb(mint))
    let dot = 0.03
    ctx.fillEllipse(in: CGRect(x: light.x - dot, y: light.y - dot, width: dot * 2, height: dot * 2))
}

func bitmap(_ width: Int, _ height: Int, opaque: Bool) -> CGContext {
    CGContext(
        data: nil, width: width, height: height, bitsPerComponent: 8, bytesPerRow: 0, space: srgb,
        bitmapInfo: (opaque ? CGImageAlphaInfo.noneSkipLast : .premultipliedLast).rawValue
    )!
}

func writePNG(_ image: CGImage, to url: URL, dpi: CGFloat? = nil) {
    let dest = CGImageDestinationCreateWithURL(url as CFURL, UTType.png.identifier as CFString, 1, nil)!
    let props = dpi.map { [kCGImagePropertyDPIWidth: $0, kCGImagePropertyDPIHeight: $0] as CFDictionary }
    CGImageDestinationAddImage(dest, image, props)
    guard CGImageDestinationFinalize(dest) else { exit(1) }
}

/// The macOS icon tile, a continuous-corner rounded square, as a superellipse
/// around `centre`.
func tile(centre: CGPoint, half: CGFloat) -> CGPath {
    let n = 5.0
    let path = CGMutablePath()
    let steps = 720
    for i in 0..<steps {
        let a = Double(i) / Double(steps) * 2 * .pi
        let c = cos(a), s = sin(a)
        let p = CGPoint(
            x: centre.x + half * CGFloat(copysign(pow(abs(c), 2 / n), c)),
            y: centre.y + half * CGFloat(copysign(pow(abs(s), 2 / n), s))
        )
        i == 0 ? path.move(to: p) : path.addLine(to: p)
    }
    path.closeSubpath()
    return path
}

/// The macOS icon at `size` pixels: on Apple's 1024 grid the tile is 824
/// square, centred, with a drop shadow below it in the margin.
func macIcon(size: Int) -> CGImage {
    let s = CGFloat(size)
    let ctx = bitmap(size, size, opaque: false)
    ctx.translateBy(x: 0, y: s)
    ctx.scaleBy(x: s, y: -s)
    let inset = 100.0 / 1024
    let shape = tile(centre: CGPoint(x: 0.5, y: 0.5), half: 0.5 - inset)

    // The shadow's offset and blur are in device space, so in pixels, and the
    // flipped transform puts a positive y offset upwards: hence the minus.
    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -10 / 1024 * s), blur: 20 / 1024 * s, color: CGColor(gray: 0, alpha: 0.4))
    ctx.addPath(shape)
    ctx.setFillColor(rgb(ground))
    ctx.fillPath()
    ctx.restoreGState()

    ctx.saveGState()
    ctx.addPath(shape)
    ctx.clip()
    ctx.translateBy(x: inset, y: inset)
    ctx.scaleBy(x: 1 - 2 * inset, y: 1 - 2 * inset)
    drawArtwork(ctx)
    ctx.restoreGState()

    // A faint rim, so the dark tile holds its edge on a dark Dock or desktop.
    ctx.addPath(shape)
    ctx.clip()
    ctx.addPath(shape)
    ctx.setStrokeColor(rgb(paper, 0.10))
    ctx.setLineWidth(max(2 / 1024, 1 / s) * 2)
    ctx.strokePath()
    return ctx.makeImage()!
}

let args = CommandLine.arguments
let usage = "usage: make-icon.swift <out.png> [size] | --mac <AppIcon.appiconset> | --glyph <Assets.xcassets> | --dmg-background <font.woff2> <out-dir>\n"
func fail() -> Never {
    FileHandle.standardError.write(Data(usage.utf8))
    exit(2)
}
guard args.count >= 2 else { fail() }

switch args[1] {
case "--mac":
    guard args.count == 3 else { fail() }
    let dir = URL(fileURLWithPath: args[2])
    // Named as iconutil names an .iconset's files, so apple/macos-release.sh
    // can build the disk image's volume icon from them.
    var images = [#"    { "filename" : "icon-1024.png", "idiom" : "universal", "platform" : "ios", "size" : "1024x1024" }"#]
    for pt in [16, 32, 128, 256, 512] {
        for scale in [1, 2] {
            let name = "icon_\(pt)x\(pt)\(scale == 2 ? "@2x" : "").png"
            writePNG(macIcon(size: pt * scale), to: dir.appendingPathComponent(name))
            images.append(#"    { "filename" : "\#(name)", "idiom" : "mac", "scale" : "\#(scale)x", "size" : "\#(pt)x\#(pt)" }"#)
        }
    }
    let contents = """
    {
      "images" : [
    \(images.joined(separator: ",\n"))
      ],
      "info" : { "author" : "xcode", "version" : 1 }
    }

    """
    try! contents.write(to: dir.appendingPathComponent("Contents.json"), atomically: true, encoding: .utf8)

case "--glyph":
    guard args.count == 3 else { fail() }
    // 18pt square, the menu bar's usual glyph size. The arch spans 0.215–0.775
    // of the icon, so it is drawn from a crop of that box with a thicker
    // stroke, which keeps it legible at this size.
    let pt: CGFloat = 18
    let crop = CGRect(x: 0.19, y: 0.19, width: 0.62, height: 0.62)
    for (name, lit) in [("MenuBarOn", true), ("MenuBarOff", false)] {
        let dir = URL(fileURLWithPath: args[2]).appendingPathComponent("\(name).imageset")
        try! FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        var box = CGRect(x: 0, y: 0, width: pt, height: pt)
        let g = CGContext(dir.appendingPathComponent("\(name).pdf") as CFURL, mediaBox: &box, nil)!
        g.beginPDFPage(nil)
        g.translateBy(x: 0, y: pt)
        g.scaleBy(x: pt / crop.width, y: -pt / crop.height)
        g.translateBy(x: -crop.minX, y: -crop.minY)
        let arch = CGMutablePath()
        arch.addLines(between: archPoints())
        g.addPath(arch)
        g.setLineCap(.round)
        g.setLineJoin(.round)
        g.setStrokeColor(CGColor(gray: 0, alpha: 1))
        g.setLineWidth(0.075)
        g.strokePath()
        if lit {
            g.setFillColor(CGColor(gray: 0, alpha: 1))
            let r = 0.065
            g.fillEllipse(in: CGRect(x: 0.5 - r, y: 0.64 - r, width: r * 2, height: r * 2))
        }
        g.endPDFPage()
        g.closePDF()
        let contents = """
        {
          "images" : [ { "filename" : "\(name).pdf", "idiom" : "universal" } ],
          "info" : { "author" : "xcode", "version" : 1 },
          "properties" : { "preserves-vector-representation" : true, "template-rendering-intent" : "template" }
        }

        """
        try! contents.write(to: dir.appendingPathComponent("Contents.json"), atomically: true, encoding: .utf8)
    }

case "--dmg-background":
    guard args.count == 4 else { fail() }
    let fontData = try! Data(contentsOf: URL(fileURLWithPath: args[2])) as CFData
    let outDir = URL(fileURLWithPath: args[3])
    dmgBackground(fontData: fontData, outDir: outDir)

default:
    let size = args.count > 2 ? Int(args[2]) ?? 1024 : 1024
    let s = CGFloat(size)
    let ctx = bitmap(size, size, opaque: true)
    ctx.translateBy(x: 0, y: s)
    ctx.scaleBy(x: s, y: -s)
    drawArtwork(ctx)
    writePNG(ctx.makeImage()!, to: URL(fileURLWithPath: args[1]))
}

// The disk image window, in points. apple/dmg/settings.py places the icons at
// these centres and sizes the window to match.
func dmgBackground(fontData: CFData, outDir: URL) {
    let size = CGSize(width: 660, height: 400)
    let app = CGPoint(x: 170, y: 190)
    let applications = CGPoint(x: 490, y: 190)
    let muted = 0x8A8A93 as UInt32

    // Finder draws icon labels in black over a background image, whatever the
    // appearance. Each label gets a light plate to sit on; its centre is where
    // Finder puts the label for a 128pt icon at 13pt text.
    let labelOffset: CGFloat = 84
    let plate = CGSize(width: 112, height: 22)

    func font(size: CGFloat, weight: CGFloat) -> CTFont {
        let descriptors = CTFontManagerCreateFontDescriptorsFromData(fontData) as! [CTFontDescriptor]
        let base = CTFontCreateWithFontDescriptor(descriptors[0], size, nil)
        let wght = 0x7767_6874 // 'wght'
        return CTFontCreateCopyWithAttributes(
            base, size, nil,
            CTFontDescriptorCreateWithAttributes([kCTFontVariationAttribute: [wght: weight]] as CFDictionary))
    }

    func draw(_ text: String, font: CTFont, color: CGColor, tracking: CGFloat = 0, at point: CGPoint, centred: Bool = false, in ctx: CGContext) {
        let attributed = NSAttributedString(string: text, attributes: [
            NSAttributedString.Key(kCTFontAttributeName as String): font,
            NSAttributedString.Key(kCTForegroundColorAttributeName as String): color,
            NSAttributedString.Key(kCTKernAttributeName as String): tracking,
        ])
        let line = CTLineCreateWithAttributedString(attributed)
        let width = CTLineGetTypographicBounds(line, nil, nil, nil)
        ctx.saveGState()
        // Text is laid out bottom-up; the canvas is flipped to read top-down.
        ctx.textMatrix = CGAffineTransform(scaleX: 1, y: -1)
        ctx.textPosition = CGPoint(x: centred ? point.x - width / 2 : point.x, y: point.y)
        CTLineDraw(line, ctx)
        ctx.restoreGState()
    }

    func render(scale: CGFloat) -> CGImage {
        let ctx = bitmap(Int(size.width * scale), Int(size.height * scale), opaque: false)
        ctx.translateBy(x: 0, y: size.height * scale)
        ctx.scaleBy(x: scale, y: -scale)

        ctx.setFillColor(rgb(ground))
        ctx.fill(CGRect(origin: .zero, size: size))

        // The threshold light falls on the app waiting to go through.
        let glow = CGGradient(colorsSpace: srgb, colors: [rgb(mint, 0.16), rgb(mint, 0.05), rgb(mint, 0)] as CFArray,
                              locations: [0, 0.4, 1])!
        ctx.drawRadialGradient(glow, startCenter: app, startRadius: 0, endCenter: app, endRadius: 200, options: [])

        // The icon's arch, large and faint, as the doorway around Applications.
        let archScale: CGFloat = 300
        let archOrigin = CGPoint(x: applications.x - 0.5 * archScale, y: applications.y + 6 - 0.5 * archScale)
        let arch = CGMutablePath()
        arch.addLines(between: archPoints().map {
            CGPoint(x: archOrigin.x + $0.x * archScale, y: archOrigin.y + $0.y * archScale)
        })
        // In a layer, so the stroke's overlapping segments do not stack their alpha.
        ctx.setAlpha(0.07)
        ctx.beginTransparencyLayer(auxiliaryInfo: nil)
        ctx.setLineCap(.round)
        ctx.setLineJoin(.round)
        ctx.addPath(arch)
        ctx.setStrokeColor(rgb(paper))
        ctx.setLineWidth(30.0 / 512 * archScale)
        ctx.strokePath()
        ctx.endTransparencyLayer()
        ctx.setAlpha(1)

        // The way through: a dotted line from the app to the doorway, ending
        // in the icon's light.
        let from = CGPoint(x: app.x + 92, y: app.y)
        let to = CGPoint(x: applications.x - 96, y: applications.y)
        let dots = 9
        for i in 0..<dots {
            let t = CGFloat(i) / CGFloat(dots - 1)
            let p = CGPoint(x: from.x + (to.x - from.x) * t, y: from.y)
            let last = i == dots - 1
            let r: CGFloat = last ? 5 : 1.6 + 0.6 * t
            ctx.setFillColor(last ? rgb(mint) : rgb(paper, 0.25 + 0.45 * t))
            ctx.fillEllipse(in: CGRect(x: p.x - r, y: p.y - r, width: r * 2, height: r * 2))
        }

        ctx.setFillColor(rgb(paper))
        for icon in [app, applications] {
            let rect = CGRect(x: icon.x - plate.width / 2, y: icon.y + labelOffset - plate.height / 2,
                              width: plate.width, height: plate.height)
            ctx.addPath(CGPath(roundedRect: rect, cornerWidth: plate.height / 2, cornerHeight: plate.height / 2, transform: nil))
            ctx.fillPath()
        }

        draw("sbr", font: font(size: 26, weight: 300), color: rgb(paper), tracking: 0.5, at: CGPoint(x: 30, y: 48), in: ctx)
        draw("drag into Applications to install", font: font(size: 11, weight: 400), color: rgb(muted), tracking: 0.3,
             at: CGPoint(x: size.width / 2, y: 356), centred: true, in: ctx)

        // Grain, so the glow does not band. Seeded: the same every build.
        var seed: UInt64 = 0x7362_72
        let data = ctx.data!.assumingMemoryBound(to: UInt8.self)
        for i in stride(from: 0, to: ctx.bytesPerRow * ctx.height, by: 4) {
            seed = seed &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
            let n = Int((seed >> 33) % 7) - 3
            for c in 0..<3 { data[i + c] = UInt8(clamping: Int(data[i + c]) + n) }
        }
        return ctx.makeImage()!
    }

    // 144 dpi marks the 2x image as the same size in points; tiffutil pairs them by it.
    for (scale, name) in [(1.0, "background.png"), (2.0, "background@2x.png")] {
        writePNG(render(scale: scale), to: outDir.appendingPathComponent(name), dpi: 72 * scale)
    }
}
