// Draws the app icon into an .iconset directory, for iconutil: swift icon.swift build/AppIcon.iconset
import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

func draw(_ size: Int) -> CGImage {
    let context = CGContext(
        data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: 0,
        space: CGColorSpace(name: CGColorSpace.sRGB)!, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    let scale = CGFloat(size) / 1024
    context.scaleBy(x: scale, y: -scale)
    context.translateBy(x: 0, y: -1024)

    // The body on Apple's grid: 824 points square with a continuous corner, and a soft shadow under it.
    let body = CGPath(
        roundedRect: CGRect(x: 100, y: 100, width: 824, height: 824), cornerWidth: 186, cornerHeight: 186,
        transform: nil)
    context.saveGState()
    context.setShadow(offset: CGSize(width: 0, height: 12), blur: 28, color: CGColor(gray: 0, alpha: 0.35))
    context.addPath(body)
    context.setFillColor(CGColor(gray: 0, alpha: 1))
    context.fillPath()
    context.restoreGState()

    context.saveGState()
    context.addPath(body)
    context.clip()
    let background = CGGradient(
        colorsSpace: nil,
        colors: [
            CGColor(srgbRed: 0.20, green: 0.32, blue: 0.78, alpha: 1),
            CGColor(srgbRed: 0.07, green: 0.11, blue: 0.33, alpha: 1),
        ] as CFArray,
        locations: [0, 1])!
    context.drawLinearGradient(background, start: CGPoint(x: 512, y: 100), end: CGPoint(x: 512, y: 924), options: [])
    context.restoreGState()

    let shield = CGMutablePath()
    shield.move(to: CGPoint(x: 512, y: 232))
    shield.addCurve(to: CGPoint(x: 732, y: 306), control1: CGPoint(x: 590, y: 286), control2: CGPoint(x: 662, y: 306))
    shield.addLine(to: CGPoint(x: 732, y: 500))
    shield.addCurve(to: CGPoint(x: 512, y: 800), control1: CGPoint(x: 732, y: 650), control2: CGPoint(x: 640, y: 746))
    shield.addCurve(to: CGPoint(x: 292, y: 500), control1: CGPoint(x: 384, y: 746), control2: CGPoint(x: 292, y: 650))
    shield.addLine(to: CGPoint(x: 292, y: 306))
    shield.addCurve(to: CGPoint(x: 512, y: 232), control1: CGPoint(x: 362, y: 306), control2: CGPoint(x: 434, y: 286))
    shield.closeSubpath()

    // Filled and stroked with round joins, so the shield's points are softened like SF Symbols' shield.
    let outline = shield.union(shield.copy(strokingWithWidth: 44, lineCap: .round, lineJoin: .round, miterLimit: 1))
    func fill(_ alpha: CGFloat) {
        context.addPath(outline)
        context.setFillColor(CGColor(gray: 1, alpha: alpha))
        context.fillPath()
    }

    context.saveGState()
    context.setShadow(offset: CGSize(width: 0, height: 10), blur: 24, color: CGColor(gray: 0, alpha: 0.3))
    fill(0.28)
    context.restoreGState()

    context.saveGState()
    context.clip(to: CGRect(x: 0, y: 0, width: 512, height: 1024))
    fill(1)
    context.restoreGState()

    return context.makeImage()!
}

let directory = URL(filePath: CommandLine.arguments[1])
try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
for points in [16, 32, 128, 256, 512] {
    for (pixels, suffix) in [(points, ""), (points * 2, "@2x")] {
        let url = directory.appending(path: "icon_\(points)x\(points)\(suffix).png")
        let destination = CGImageDestinationCreateWithURL(url as CFURL, UTType.png.identifier as CFString, 1, nil)!
        CGImageDestinationAddImage(destination, draw(pixels), nil)
        CGImageDestinationFinalize(destination)
    }
}
