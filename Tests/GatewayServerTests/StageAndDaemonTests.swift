// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import XCTest
import GatewayCore
import InputFirewall
@testable import GatewayServer

// MARK: - Uebergabe an die naechste Stufe

final class StageDownstreamTests: XCTestCase {

    private func handoff(disposition: Disposition = .allowModified,
                         findings: [Finding] = [],
                         principal: Principal = Principal(subject: "s", tenant: "t",
                                                          scopes: ["b", "a"]),
                         request: ChatRequest? = nil) -> GatewayHandoff {
        GatewayHandoff(
            correlationID: "corr-1",
            principal: principal,
            request: request ?? ChatRequest(model: "m", messages: [
                ChatMessage(role: .user, content: "Hallo [Person-1]"),
            ]),
            disposition: disposition,
            riskScore: 0.4,
            findings: findings)
    }

    private func encoded(_ handoff: GatewayHandoff, stream: Bool = false) -> [String: Any] {
        let data = try! StageDownstream.encode(handoff, stream: stream)
        return try! JSONSerialization.jsonObject(with: data) as! [String: Any]
    }

    func testTheVerdictTravelsWithTheRequest() async {
        // Der Unterschied zum Provider-Ziel: die naechste Stufe soll die
        // Bewertung nicht wiederholen muessen.
        let body = encoded(handoff(findings: [
            Finding(ruleID: "INJ-001", category: .injection, severity: .high,
                    weight: 0.6, message: "Anzeigetext", occurrences: 2),
        ]))
        let verdict = body["verdict"] as! [String: Any]
        XCTAssertEqual(verdict["disposition"] as? String, "allowModified")
        XCTAssertEqual(verdict["risk_score"] as? Double, 0.4)

        let finding = (verdict["findings"] as! [[String: Any]]).first!
        XCTAssertEqual(finding["rule"] as? String, "INJ-001")
        XCTAssertEqual(finding["category"] as? String, "injection")
        XCTAssertEqual(finding["occurrences"] as? Int, 2)
    }

    func testTheDisplayTextOfAFindingIsNotSent() {
        // `message` darf laut Konvention frei umformuliert werden — eine
        // Gegenstelle, die darauf prueft, bricht beim naechsten Textlauf.
        let body = encoded(handoff(findings: [
            Finding(ruleID: "INJ-001", category: .injection, severity: .high,
                    weight: 0.6, message: "streng geheimer Anzeigetext"),
        ]))
        let text = String(data: try! JSONSerialization.data(withJSONObject: body),
                          encoding: .utf8) ?? ""
        XCTAssertFalse(text.contains("Anzeigetext"))
    }

    func testOnlyTheMaskedRequestGoesOut() {
        let body = encoded(handoff())
        let request = body["request"] as! [String: Any]
        let messages = request["messages"] as! [[String: String]]
        XCTAssertEqual(messages.first?["content"], "Hallo [Person-1]")
        XCTAssertEqual(messages.first?["role"], "user")
    }

    func testStreamFlagIsSetByTheCaller() {
        XCTAssertEqual((encoded(handoff(), stream: true)["request"]
                        as! [String: Any])["stream"] as? Bool, true)
        XCTAssertEqual((encoded(handoff(), stream: false)["request"]
                        as! [String: Any])["stream"] as? Bool, false)
    }

    func testScopesAreSortedSoTheLineIsStable() {
        let principal = encoded(handoff())["principal"] as! [String: Any]
        XCTAssertEqual(principal["scopes"] as? [String], ["a", "b"])
        XCTAssertEqual(principal["tenant"] as? String, "t")
    }

    func testAbsentOptionalsAreOmittedNotZeroed() {
        // Eine 0 waere eine Behauptung; das Fehlen ist die Wahrheit.
        let request = encoded(handoff())["request"] as! [String: Any]
        XCTAssertNil(request["temperature"])
        XCTAssertNil(request["max_tokens"])

        let withValues = encoded(handoff(request: ChatRequest(
            model: "m", messages: [ChatMessage(role: .user, content: "x")],
            temperature: 0.2, maxTokens: 64)))
        let payload = withValues["request"] as! [String: Any]
        XCTAssertEqual(payload["temperature"] as? Double, 0.2)
        XCTAssertEqual(payload["max_tokens"] as? Int, 64)
    }

    // MARK: Antwort lesen

    func testResponseIsReadTolerantly() throws {
        let json = #"{"model":"next","content":"ok","extra":1,"#
            + #""usage":{"prompt_tokens":3,"completion_tokens":4}}"#
        let data = Data(json.utf8)
        let response = try StageDownstream.decodeResponse(data)
        XCTAssertEqual(response.content, "ok")
        XCTAssertEqual(response.model, "next")
        XCTAssertEqual(response.usage, TokenUsage(promptTokens: 3, completionTokens: 4))
    }

    func testResponseWithoutContentIsAnError() {
        XCTAssertThrowsError(try StageDownstream.decodeResponse(Data(#"{"model":"x"}"#.utf8)))
    }

    func testMissingUsageStaysNil() throws {
        let response = try StageDownstream.decodeResponse(Data(#"{"content":"ok"}"#.utf8))
        XCTAssertNil(response.usage, "geschaetzt wird nie")
    }

    // MARK: Strom

    func testDeltasAreAssembledAcrossChunkBoundaries() {
        let state = StageDownstream.collector()
        XCTAssertEqual(state.consume(Data("{\"delta\":\"Hal\"}\n".utf8)), ["Hal"])
        // Eine halbe Zeile darf nichts liefern.
        XCTAssertEqual(state.consume(Data("{\"delta\":\"l".utf8)), [])
        XCTAssertEqual(state.consume(Data("o\"}\n".utf8)), ["lo"])
    }

    func testUsageInTheStreamIsCollected() {
        let state = StageDownstream.collector()
        _ = state.consume(Data("{\"usage\":{\"prompt_tokens\":7}}\n".utf8))
        _ = state.consume(Data("{\"usage\":{\"completion_tokens\":9}}\n".utf8))
        XCTAssertEqual(state.reportedUsage(), TokenUsage(promptTokens: 7, completionTokens: 9))
    }

    func testAnErrorInTheStreamIsRememberedNotSwallowed() {
        // Still verschluckt saehe er fuer den Client wie eine vollstaendige
        // Antwort aus.
        let state = StageDownstream.collector()
        _ = state.consume(Data("{\"error\":\"policy engine down\"}\n".utf8))
        XCTAssertEqual(state.pendingFailure(),
                       GatewayServerError.upstream(status: 502, body: "policy engine down"))
    }

    func testGarbageLinesAreSkipped() {
        let state = StageDownstream.collector()
        XCTAssertEqual(state.consume(Data("nicht json\n{\"delta\":\"ok\"}\n".utf8)), ["ok"])
    }
}

// MARK: - Konfiguration aus einer Datei

final class DaemonConfigurationTests: XCTestCase {

    private func parse(_ json: [String: Any],
                       environment: [String: String] = [:]) throws -> DaemonConfiguration {
        try DaemonConfiguration.parse(
            try JSONSerialization.data(withJSONObject: json), environment: environment)
    }

    func testDefaultsSurviveAnEmptyFile() throws {
        let config = try parse([:])
        XCTAssertEqual(config.gateway.port, 8080)
        XCTAssertTrue(config.gateway.loopbackOnly)
        XCTAssertTrue(config.pii)
        XCTAssertFalse(config.cache.enabled)
        XCTAssertFalse(config.rateLimit.enabled)
    }

    func testSectionsAreRead() throws {
        let config = try parse([
            "server": ["port": 9000, "loopbackOnly": false, "upstream": "anthropic"],
            "policy": ["blockThreshold": 0.5, "maxMessages": 12, "failClosed": false],
            "stages": ["pii": false, "dlp": true, "malware": false],
            "cache": ["enabled": true, "maxEntriesPerPartition": 7],
            "rateLimit": ["enabled": true, "burst": 3],
            "quarantine": ["enabled": true, "detail": "counts"],
            "maskingSessions": ["enabled": true, "timeToLive": 60],
            "nextStage": "https://policy.internal/v1/decide",
            "drainSeconds": 5,
        ])

        XCTAssertEqual(config.gateway.port, 9000)
        XCTAssertFalse(config.gateway.loopbackOnly)
        XCTAssertEqual(config.gateway.upstream, .anthropic)
        XCTAssertEqual(config.policy.blockThreshold, 0.5, accuracy: 0.0001)
        XCTAssertEqual(config.policy.maxMessages, 12)
        XCTAssertEqual(config.policy.failureMode, .failOpen)
        XCTAssertFalse(config.pii)
        XCTAssertTrue(config.dlp)
        XCTAssertFalse(config.malware)
        XCTAssertEqual(config.cache.maxEntriesPerPartition, 7)
        XCTAssertEqual(config.rateLimit.burst, 3)
        XCTAssertEqual(config.quarantine.detail, .counts)
        XCTAssertEqual(config.maskingSessions?.timeToLive, 60)
        XCTAssertEqual(config.nextStageURL?.absoluteString, "https://policy.internal/v1/decide")
        XCTAssertEqual(config.drainSeconds, 5)
    }

    func testTheAPIKeyComesFromTheEnvironmentOnly() throws {
        // Eine Konfigurationsdatei landet in der Versionsverwaltung, in
        // Backups und in Fehlerberichten. Ein Feld dafuer anzubieten hiesse,
        // genau das zu erlauben — also gibt es keines.
        let config = try parse(["server": ["port": 8080]],
                               environment: ["AIGATEWAY_UPSTREAM_API_KEY": "sk-geheim"])
        XCTAssertEqual(config.gateway.apiKey, "sk-geheim")

        XCTAssertThrowsError(try parse(["server": ["apiKey": "sk-in-der-datei"]])) { error in
            guard case DaemonConfiguration.ConfigurationError.unknownKeys(let keys, _) = error else {
                return XCTFail("erwartet: unbekannter Schluessel, bekommen: \(error)")
            }
            XCTAssertEqual(keys, ["apiKey"])
        }
    }

    func testATypoIsAnErrorNotASilentDefault() throws {
        // Still ignoriert liefe das Gateway mit einer Einstellung, die der
        // Betreiber gesetzt zu haben glaubt.
        XCTAssertThrowsError(try parse(["cache": ["similarityTreshold": 0.9]])) { error in
            guard case DaemonConfiguration.ConfigurationError.unknownKeys(_, let section) = error else {
                return XCTFail("erwartet: unbekannter Schluessel")
            }
            XCTAssertEqual(section, "cache")
        }
    }

    func testBadValuesAreNamed() {
        XCTAssertThrowsError(try parse(["server": ["port": 70_000]]))
        XCTAssertThrowsError(try parse(["server": ["upstream": "gemini"]]))
        XCTAssertThrowsError(try parse(["quarantine": ["detail": "everything"]]))
        XCTAssertThrowsError(try parse(["policy": "nicht-objekt"]))
    }

    func testMalformedJSONIsRejected() {
        XCTAssertThrowsError(try DaemonConfiguration.parse(Data("[1,2,3]".utf8)))
    }

    // MARK: Zusammenbau

    func testStagesAreBuiltAsConfigured() async {
        var config = DaemonConfiguration()
        config.dlp = true
        config.rateLimit.enabled = true
        // Grosszuegiges Budget: ein kalter Regex-Start auf CI darf nicht blocken.
        config.policy.stageBudgetMilliseconds = 10_000
        let pipeline = config.makePipeline()

        // Nachgewiesen ueber das Verhalten, nicht ueber die Bestueckung: eine
        // interne Adresse wird redigiert, also laeuft die DLP-Stufe.
        let outcome = await pipeline.process(
            ChatRequest(model: "m", messages: [
                ChatMessage(role: .user, content: "Siehe https://wiki.intern/x"),
            ]),
            principal: .anonymous)
        XCTAssertFalse(outcome.forward?.scannableText.contains("wiki.intern") ?? true)
        XCTAssertNotNil(config.makeRateGuard())
    }

    func testDisabledRateLimitBuildsNoGuard() {
        XCTAssertNil(DaemonConfiguration().makeRateGuard())
    }

    func testCacheIsOnlyBuiltWhenEnabled() async {
        var config = DaemonConfiguration()
        let without = await config.makePipeline().cacheStatistics()
        config.cache.enabled = true
        let with = await config.makePipeline().cacheStatistics()

        XCTAssertNil(without)
        XCTAssertNotNil(with)
    }
}
