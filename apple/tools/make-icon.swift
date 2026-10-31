// Renders the sbr app icon: a brush-drawn archway on near-black with a mint
// light at its threshold, in kōan's palette. With --glyph, it instead writes
// the macOS menu bar glyphs into an asset catalog: the same arch as
// black-on-clear template PDFs, with the light (MenuBarOn) and without it
// (MenuBarOff).
//
// Usage: swift apple/tools/make-icon.swift <out.png> [size]
//        swift apple/tools/make-icon.swift --glyph <Assets.xcassets>
import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

let args = CommandLine.arguments
guard args.count >= 2, args[1] != "--glyph" || args.count == 3 else {
    FileHandle.standardError.write(Data("usage: make-icon.swift <out.png> [size] | --glyph <Assets.xcassets>\n".utf8))
    exit(2)
}

if args[1] == "--glyph" {
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
    exit(0)
}
let size = args.count > 2 ? Int(args[2]) ?? 1024 : 1024
let s = CGFloat(size)

func rgb(_ hex: UInt32, _ a: CGFloat = 1) -> CGColor {
    CGColor(
        srgbRed: CGFloat((hex >> 16) & 0xFF) / 255,
        green: CGFloat((hex >> 8) & 0xFF) / 255,
        blue: CGFloat(hex & 0xFF) / 255,
        alpha: a
    )
}

let ground = rgb(0x15151A)
let paper = 0xEDEAE2 as UInt32
let mint = 0x7DD3A7 as UInt32

let ctx = CGContext(
    data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: 0,
    space: CGColorSpace(name: CGColorSpace.sRGB)!,
    bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue
)!
// Unit coordinates, origin top-left like the SVG sources.
ctx.translateBy(x: 0, y: s)
ctx.scaleBy(x: s, y: -s)

ctx.setFillColor(ground)
ctx.fill(CGRect(x: 0, y: 0, width: 1, height: 1))

// The threshold light: a soft mint glow, then the light itself.
let light = CGPoint(x: 0.5, y: 0.705)
let glow = CGGradient(
    colorsSpace: CGColorSpace(name: CGColorSpace.sRGB),
    colors: [rgb(mint, 0.30), rgb(mint, 0.10), rgb(mint, 0)] as CFArray,
    locations: [0, 0.35, 1]
)!
ctx.drawRadialGradient(glow, startCenter: light, startRadius: 0, endCenter: light, endRadius: 0.30, options: [])

// The arch: two legs and a round head, traced as one stroke with a slow,
// deterministic wobble so it reads as brushed rather than drawn.
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

let image = ctx.makeImage()!
let url = URL(fileURLWithPath: args[1])
let dest = CGImageDestinationCreateWithURL(url as CFURL, UTType.png.identifier as CFString, 1, nil)!
CGImageDestinationAddImage(dest, image, nil)
guard CGImageDestinationFinalize(dest) else { exit(1) }
