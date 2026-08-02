// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: Apache-2.0

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
