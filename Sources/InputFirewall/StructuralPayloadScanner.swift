// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation
import GatewayCore

// MARK: - Malware-Stufe: strukturelle Pruefung
//
// WAS DAS HIER NICHT IST: eine Virenerkennung. Signaturen zu pflegen ist eine
// eigene Industrie, und ein selbstgebauter Scanner waere dasselbe Fehlurteil
// wie ein selbstgebauter TLS-Stack. DECISIONS spricht deshalb von der
// **ClamAV-Naht** — `PayloadScanner` ist diese Naht, und wer eine echte
// Engine will, haengt sie dort ein.
//
// WAS ES IST: die billige, abhaengigkeitsfreie erste Schicht, die ohne
// Signaturen auskommt und genau die Faelle erwischt, in denen ein Anhang schon
// an seiner STRUKTUR auffaellt:
//
//   • ausfuehrbare Formate, unabhaengig vom behaupteten Typ,
//   • ein behaupteter Typ, der nicht zum Inhalt passt,
//   • Archive — nicht weil sie boese sind, sondern weil ihr Inhalt hier
//     ungeprueft bleibt und das SICHTBAR sein muss,
//   • schiere Groesse.
//
// Der behauptete Medientyp und der Dateiname sind Angreifer-kontrolliert. Sie
// werden deshalb nie geglaubt, sondern nur GEGEN den Inhalt geprueft: ein
// `image/png`, das mit `MZ` beginnt, ist der interessante Fall.

public struct StructuralPayloadScanner: PayloadScanner {

    public let stageName = "malware"

    /// Ab dieser Groesse gilt ein Anhang als Anomalie.
    private let maxBytes: Int
    /// Sollen Archive als ungeprueft gemeldet werden?
    private let flagArchives: Bool

    public init(maxBytes: Int = 10 * 1024 * 1024, flagArchives: Bool = true) {
        self.maxBytes = maxBytes
        self.flagArchives = flagArchives
    }

    public func scan(_ bytes: Data, name: String?, mediaType: String?) -> ScanResult {
        var findings: [Finding] = []
        var raw = 0.0

        if bytes.count > maxBytes {
            raw += 0.5
            findings.append(Finding(
                ruleID: Self.ruleOversizedPayload, category: .anomaly, severity: .medium,
                weight: 0.5,
                message: "payload exceeds \(maxBytes) bytes (\(bytes.count))"))
        }

        let actual = Self.sniff(bytes)

        if actual == .executable {
            // Der harte Fall: ausfuehrbarer Code als Anhang an ein Sprachmodell
            // hat keinen legitimen Grund.
            raw += 1.0
            findings.append(Finding(
                ruleID: Self.ruleExecutablePayload, category: .malware, severity: .critical,
                weight: 1.0,
                message: "payload is an executable image"))
        }

        // Behaupteter Typ gegen tatsaechlichen Inhalt. Nur melden, wenn der
        // Inhalt ueberhaupt erkannt wurde — „unbekannt" ist kein Widerspruch.
        if let mediaType, actual != .unknown, !actual.matches(declared: mediaType) {
            raw += 0.4
            findings.append(Finding(
                ruleID: Self.ruleTypeMismatch, category: .malware, severity: .high,
                weight: 0.4,
                message: "declared '\(mediaType)' does not match content (\(actual.rawValue))"))
        }

        if flagArchives, actual == .archive {
            // Kein Verstoss, sondern eine Wissensluecke: was im Archiv liegt,
            // hat niemand gesehen. Das gehoert ins Audit, damit die Luecke
            // nicht als Freigabe durchgeht.
            raw += 0.3
            findings.append(Finding(
                ruleID: Self.ruleUnscannedArchive, category: .malware, severity: .medium,
                weight: 0.3,
                message: "archive contents were not inspected"))
        }

        // `content` bleibt leer und `wasModified` falsch — ein Byte-Scanner
        // bereinigt nicht (siehe `PayloadScanner`).
        return ScanResult(findings: findings, content: "", rawScore: raw,
                          trustMultiplier: 1.0, wasModified: false)
    }

    // MARK: - Stabile Regel-IDs

    public static let ruleExecutablePayload: RuleID = "MAL-001"
    public static let ruleTypeMismatch: RuleID = "MAL-002"
    public static let ruleUnscannedArchive: RuleID = "MAL-003"
    public static let ruleOversizedPayload: RuleID = "MAL-004"

    // MARK: - Magische Bytes

    enum PayloadShape: String {
        case executable, archive, image, pdf, text, unknown

        /// Passt der erkannte Inhalt zum behaupteten Medientyp?
        func matches(declared: String) -> Bool {
            let type = declared.lowercased()
            switch self {
            case .image: return type.hasPrefix("image/")
            case .pdf: return type.contains("pdf")
            case .archive:
                // Viele Office- und OpenDocument-Formate SIND ZIP-Archive.
                return type.contains("zip") || type.contains("compressed")
                    || type.contains("officedocument") || type.contains("opendocument")
                    || type.contains("gzip") || type.contains("tar")
            case .text: return type.hasPrefix("text/") || type.contains("json")
                    || type.contains("xml") || type.contains("csv")
            case .executable: return type.contains("executable") || type.contains("octet-stream")
            case .unknown: return true
            }
        }
    }

    /// Erkennt das Format an den ersten Bytes.
    ///
    /// Bewusst kurz gehalten: dies ist kein Format-Detektor, sondern die Frage
    /// „sieht das aus wie etwas, das hier nichts zu suchen hat".
    static func sniff(_ bytes: Data) -> PayloadShape {
        let head = [UInt8](bytes.prefix(8))
        guard head.count >= 4 else { return bytes.isEmpty ? .unknown : .text }

        // Ausfuehrbares
        if head[0] == 0x4D, head[1] == 0x5A { return .executable }                 // MZ (PE/DOS)
        if head[0] == 0x7F, head[1] == 0x45, head[2] == 0x4C, head[3] == 0x46 {
            return .executable                                                     // \x7FELF
        }
        // Mach-O, 32/64 Bit, beide Byte-Reihenfolgen, plus Universal Binary
        let magic32 = UInt32(head[0]) << 24 | UInt32(head[1]) << 16
            | UInt32(head[2]) << 8 | UInt32(head[3])
        if [0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE, 0xCAFEBABE].contains(magic32) {
            return .executable
        }

        // Archive
        if head[0] == 0x50, head[1] == 0x4B { return .archive }                    // PK (ZIP)
        if head[0] == 0x1F, head[1] == 0x8B { return .archive }                    // GZIP
        if head[0] == 0x37, head[1] == 0x7A { return .archive }                    // 7z
        if head[0] == 0x52, head[1] == 0x61, head[2] == 0x72 { return .archive }   // Rar

        // Harmloses
        if head[0] == 0x25, head[1] == 0x50, head[2] == 0x44, head[3] == 0x46 { return .pdf }
        if head[0] == 0x89, head[1] == 0x50, head[2] == 0x4E, head[3] == 0x47 { return .image }
        if head[0] == 0xFF, head[1] == 0xD8, head[2] == 0xFF { return .image }      // JPEG
        if head[0] == 0x47, head[1] == 0x49, head[2] == 0x46 { return .image }      // GIF

        // Alles Druckbare gilt als Text; alles andere bleibt unbekannt, damit
        // der Typvergleich daraus keinen Widerspruch konstruiert.
        let printable = head.filter { $0 == 0x09 || $0 == 0x0A || $0 == 0x0D || (0x20...0x7E).contains($0) }
        return printable.count == head.count ? .text : .unknown
    }
}
