import AppKit
import CoreGraphics
import Foundation
import ImageIO
import Vision

struct WinInfo: Codable {
    let id: Int
    let title: String
    let x: Double
    let y: Double
    let w: Double
    let h: Double
    let area: Double
}

struct OCRHit: Codable {
    let text: String
    let cx: Double
    let cy: Double
    let w: Double
    let h: Double
}

func listWeChatWindows() -> [WinInfo] {
    let opts: CGWindowListOption = [.optionOnScreenOnly, .excludeDesktopElements]
    guard let list = CGWindowListCopyWindowInfo(opts, kCGNullWindowID) as? [[String: Any]] else {
        return []
    }
    var out: [WinInfo] = []
    for item in list {
        guard let owner = item[kCGWindowOwnerName as String] as? String else { continue }
        if owner != "WeChat" && owner != "微信" { continue }
        let layer = (item[kCGWindowLayer as String] as? Int) ?? 0
        if layer != 0 { continue }
        guard let wid = item[kCGWindowNumber as String] as? Int,
              let bounds = item[kCGWindowBounds as String] as? [String: Any],
              let x = bounds["X"] as? Double,
              let y = bounds["Y"] as? Double,
              let w = bounds["Width"] as? Double,
              let h = bounds["Height"] as? Double,
              w >= 120, h >= 120 else {
            continue
        }
        let title = (item[kCGWindowName as String] as? String) ?? ""
        out.append(WinInfo(id: wid, title: title, x: x, y: y, w: w, h: h, area: w * h))
    }
    out.sort { $0.area > $1.area }
    return out
}

func loadCGImage(at url: URL) -> CGImage? {
    guard let src = CGImageSourceCreateWithURL(url as CFURL, nil) else {
        return nil
    }
    let props = CGImageSourceCopyPropertiesAtIndex(src, 0, nil) as? [CFString: Any]
    let pxW = (props?[kCGImagePropertyPixelWidth] as? Int) ?? 0
    let pxH = (props?[kCGImagePropertyPixelHeight] as? Int) ?? 0
    // Downscale huge Retina screenshots (>1800px) inside ImageIO to slash OCR CPU/Neural Engine cost.
    if max(pxW, pxH) > 1800 {
        let opts: [CFString: Any] = [
            kCGImageSourceCreateThumbnailFromImageAlways: true,
            kCGImageSourceCreateThumbnailWithTransform: true,
            kCGImageSourceThumbnailMaxPixelSize: 1800,
        ]
        if let thumb = CGImageSourceCreateThumbnailAtIndex(src, 0, opts as CFDictionary) {
            return thumb
        }
    }
    return CGImageSourceCreateImageAtIndex(src, 0, nil)
}

func runOCR(imagePath: String) throws -> [OCRHit] {
    let url = URL(fileURLWithPath: imagePath)
    guard let cg = loadCGImage(at: url) else {
        throw NSError(domain: "ocr", code: 1, userInfo: [NSLocalizedDescriptionKey: "无法读取截图文件"])
    }
    let req = VNRecognizeTextRequest()
    req.recognitionLevel = .accurate
    req.recognitionLanguages = ["zh-Hans", "en-US"]
    req.usesLanguageCorrection = false
    try VNImageRequestHandler(cgImage: cg).perform([req])
    var hits: [OCRHit] = []
    for obs in req.results ?? [] {
        guard let top = obs.topCandidates(1).first else { continue }
        let b = obs.boundingBox
        hits.append(OCRHit(
            text: top.string,
            cx: b.midX,
            cy: 1.0 - b.midY,
            w: b.width,
            h: b.height
        ))
    }
    return hits
}

func currentMouseJSON() -> String {
    let p = NSEvent.mouseLocation
    let h = NSScreen.screens.first?.frame.size.height ?? 0
    let x = Int(p.x.rounded())
    let y = Int((h - p.y).rounded())
    return "{\"x\":\(x),\"y\":\(y)}"
}

func clickAtPoint(x: Double, y: Double) -> Bool {
    let pt = CGPoint(x: x, y: y)
    guard let move = CGEvent(mouseEventSource: nil, mouseType: .mouseMoved, mouseCursorPosition: pt, mouseButton: .left),
          let down = CGEvent(mouseEventSource: nil, mouseType: .leftMouseDown, mouseCursorPosition: pt, mouseButton: .left),
          let up = CGEvent(mouseEventSource: nil, mouseType: .leftMouseUp, mouseCursorPosition: pt, mouseButton: .left) else {
        return false
    }
    move.post(tap: .cghidEventTap)
    usleep(35_000)
    down.post(tap: .cghidEventTap)
    usleep(35_000)
    up.post(tap: .cghidEventTap)
    return true
}

let args = CommandLine.arguments
let enc = JSONEncoder()
if args.count >= 2 && args[1] == "--wechat-windows" {
    let wins = listWeChatWindows()
    let data = try enc.encode(wins)
    print(String(data: data, encoding: .utf8) ?? "[]")
} else if args.count >= 3 && args[1] == "--ocr" {
    let hits = try runOCR(imagePath: args[2])
    let data = try enc.encode(hits)
    print(String(data: data, encoding: .utf8) ?? "[]")
} else if args.count >= 2 && args[1] == "--mouse" {
    print(currentMouseJSON())
} else if args.count >= 4 && args[1] == "--click",
          let x = Double(args[2]), let y = Double(args[3]) {
    if !clickAtPoint(x: x, y: y) {
        fputs("click event creation failed\n", stderr)
        exit(1)
    }
} else {
    fputs("usage: ocr-helper --wechat-windows | --ocr <png> | --mouse | --click <x> <y>\n", stderr)
    exit(2)
}
