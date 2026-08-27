// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import XCTest
import GatewayCore
import InputFirewall
@testable import GatewayServer

// MARK: - Secrets verlassen die Box nicht (M7)
//
// Die Injection-Stufe ERKENNT Secrets (SEC-00x, Gewicht), aber ein einzelnes
// Secret in einer user-Nachricht scort unter der Blockschwelle. Die DLP-Stufe
// REDIGIERT sie — nach der Maskierung und VOR dem Cache-Schluessel, also bevor
// das Secret den Provider oder den Cache-Index erreicht.

final class SecretRedactionTests: XCTestCase {

    private func pipeline() -> GatewayPipeline {
        var policy = GatewayPolicy.standard
        policy.stageBudgetMilliseconds = 10_000
        return GatewayPipeline(
            pii: PIIGate(policy: .gatewayDefault, baseDirectory: nil),
            dlp: DLPScanner(),
            policy: policy,
            cache: SemanticCache(policy: .on))
    }

    func testSecretIsRedactedBeforeUpstream() async {
        let secret = "AKIAIOSFODNN7EXAMPLE"
        let outcome = await pipeline().process(
            ChatRequest(model: "m", messages: [ChatMessage(role: .user, content: "Token \(secret) nutzen")]),
            principal: .anonymous)

        let forwarded = outcome.forward?.scannableText ?? ""
        XCTAssertFalse(forwarded.contains(secret), "das Secret darf den Provider nicht erreichen")
        XCTAssertTrue(forwarded.contains("[SECRET]"))
        // Erkennung UND Handlung stehen im Audit.
        XCTAssertTrue(outcome.decision.findings.contains { $0.ruleID == "SEC-002" },
                      "Injection erkennt das Secret")
        XCTAssertTrue(outcome.decision.findings.contains { $0.ruleID == "DLP-011" },
                      "DLP redigiert es")
    }

    /// Ein Format, beide Stufen: das Secret verlaesst die Box nicht, und
    /// Erkennung (SEC) wie Handlung (DLP) stehen im Audit.
    private func assertRedacted(_ secret: String, sec: RuleID, dlp: RuleID,
                                file: StaticString = #filePath,
                                line: UInt = #line) async {
        let outcome = await pipeline().process(
            ChatRequest(model: "m", messages: [ChatMessage(
                role: .user, content: "Nimm bitte \(secret) dafuer.")]),
            principal: .anonymous)
        let forwarded = outcome.forward?.scannableText ?? ""
        XCTAssertFalse(forwarded.contains(secret),
                       "\(sec): das Secret darf den Provider nicht erreichen",
                       file: file, line: line)
        XCTAssertTrue(forwarded.contains("[SECRET]"), file: file, line: line)
        XCTAssertTrue(outcome.decision.findings.contains { $0.ruleID == sec },
                      "\(sec) erkennt", file: file, line: line)
        XCTAssertTrue(outcome.decision.findings.contains { $0.ruleID == dlp },
                      "\(dlp) redigiert", file: file, line: line)
    }

    func testGoogleAPIKeyIsRedacted() async {
        await assertRedacted("AIzaFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAK",
                             sec: "SEC-008", dlp: "DLP-017")
    }

    func testStripeLiveKeyIsRedacted() async {
        await assertRedacted("sk_live_FAKEFAKEFAKEFAKEFAKE",
                             sec: "SEC-009", dlp: "DLP-018")
    }

    func testStripeTestKeyPassesUntouched() async {
        // Die Gegenprobe zur live-Entscheidung: Test-Schluessel sind wertlos
        // und stehen legitim in Doku — kein Fund, keine Redaktion.
        let outcome = await pipeline().process(
            ChatRequest(model: "m", messages: [ChatMessage(
                role: .user, content: "Beispiel: sk_test_FAKEFAKEFAKEFAKEFAKE")]),
            principal: .anonymous)
        let forwarded = outcome.forward?.scannableText ?? ""
        XCTAssertTrue(forwarded.contains("sk_test_FAKEFAKEFAKEFAKEFAKE"))
        XCTAssertFalse(outcome.decision.findings.contains { $0.ruleID == "SEC-009" })
    }

    func testGitLabTokenIsRedacted() async {
        await assertRedacted("glpat-FAKEFAKEFAKEFAKEFAKE",
                             sec: "SEC-010", dlp: "DLP-019")
    }

    func testNpmTokenIsRedacted() async {
        await assertRedacted("npm_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE",
                             sec: "SEC-011", dlp: "DLP-020")
    }

    func testHuggingFaceTokenIsRedacted() async {
        await assertRedacted("hf_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAK",
                             sec: "SEC-012", dlp: "DLP-021")
    }

    func testGermanPasswordAssignmentIsRedacted() async {
        await assertRedacted(#"passwort = "S3hrGeheim99""#,
                             sec: "SEC-013", dlp: "DLP-022")
    }

    func testPasswordTalkWithoutValueIsNoFinding() async {
        // Die Enge der Regel: ohne zitierten Wert kein Fund — normale Rede
        // ueber Passwoerter ist kein Secret.
        let outcome = await pipeline().process(
            ChatRequest(model: "m", messages: [ChatMessage(
                role: .user, content: "Mein Passwort ist sicher und bleibt geheim.")]),
            principal: .anonymous)
        XCTAssertFalse(outcome.decision.findings.contains { $0.ruleID == "SEC-013" })
        XCTAssertTrue(outcome.forward?.scannableText.contains("Passwort ist sicher") ?? false)
    }

    func testGenericSkPatternCoversOpenAIAndAnthropicKeys() async {
        // SEC-006 (sk-...) deckt die Schluessel der grossen Modellanbieter
        // GENERISCH ab — deshalb gibt es fuer OpenAI und Anthropic keine
        // eigenen Regeln. Dieser Test nagelt die Abdeckung fest: wer das
        // sk-Muster enger zieht, verliert sie nicht still.
        await assertRedacted("sk-FAKEFAKEFAKEFAKEFAKEFAKE",
                             sec: "SEC-006", dlp: "DLP-015")
        await assertRedacted("sk-ant-FAKEFAKEFAKEFAKEFAKEFAKE",
                             sec: "SEC-006", dlp: "DLP-015")
    }

    func testRedactedSecretDoesNotEnterTheCacheKey() async {
        // Der Cache-Schluessel entsteht aus dem forwarded-Text NACH der DLP-Stufe.
        // Ist das Secret dort weg, kann es nicht im Cache-Index landen.
        let secret = "AKIAIOSFODNN7EXAMPLE"
        let pipe = pipeline()
        let outcome = await pipe.process(
            ChatRequest(model: "m", messages: [ChatMessage(role: .user, content: "Key \(secret)")]),
            principal: .anonymous)
        let key = CacheKey(partition: Principal.anonymous.cachePartition, request: outcome.forward!)
        XCTAssertFalse(key.prompt.contains(secret), "kein Secret im Cache-Schluessel")
    }
}
