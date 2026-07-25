// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import XCTest
import GatewayCore
@testable import InputFirewall

// In-Memory-Vault (baseDirectory nil) — kein Dateisystem, deterministisch.
private func makeGate(_ policy: PseudonymizationPolicy = .gatewayDefault) -> PIIGate {
    PIIGate(policy: policy, baseDirectory: nil)
}

// MARK: - Round-Trip: die eigentliche Gateway-Leistung

final class PIIRoundTripTests: XCTestCase {

    func testMaskThenUnmaskRestoresOriginal() async {
        let gate = makeGate()
        let original = "Bitte an Frau Anna Schmidt senden, IBAN DE02120300000000202051."
        let out = await gate.mask(original)

        XCTAssertFalse(out.maskedContent.contains("Anna Schmidt"))
        XCTAssertFalse(out.maskedContent.contains("DE02120300000000202051"))
        XCTAssertEqual(out.session.unmask(out.maskedContent), original)
    }

    func testModelAnswerIsUnmasked() async {
        // Der eigentliche Zweck: die Antwort kommt mit Platzhaltern zurueck und
        // wird fuer den Nutzer wieder aufgeloest.
        let gate = makeGate()
        let out = await gate.mask("Herr Klaus Mueller hat zugestimmt.")
        let answer = out.session.unmask("Ich habe [Person-1] notiert.")
        XCTAssertEqual(answer, "Ich habe Klaus Mueller notiert.")
    }

    func testUnmaskLeavesUnknownTokensAlone() async {
        let gate = makeGate()
        let out = await gate.mask("Frau Anna Schmidt")
        // Ein Token, das nie vergeben wurde, bleibt stehen — kein Raten.
        XCTAssertEqual(out.session.unmask("[Person-99] unbekannt"), "[Person-99] unbekannt")
    }

    func testSessionIsSelfContained() async {
        let gate = makeGate()
        let out = await gate.mask("Herr Klaus Mueller")
        // Die Session traegt die Zuordnung selbst — unabhaengig vom Gate.
        let isolated = MaskingSession(mapping: out.session.mapping)
        XCTAssertEqual(isolated.unmask("[Person-1]"), "Klaus Mueller")
    }

    func testEmptySessionIsIdentity() {
        XCTAssertEqual(MaskingSession.empty.unmask("unveraendert"), "unveraendert")
        XCTAssertTrue(MaskingSession.empty.isEmpty)
    }

    func testDisabledPolicyPassesThrough() async {
        let gate = makeGate(PseudonymizationPolicy(enabled: false))
        let out = await gate.mask("Frau Anna Schmidt, IBAN DE02120300000000202051")
        XCTAssertEqual(out.maskedContent, "Frau Anna Schmidt, IBAN DE02120300000000202051")
        XCTAssertTrue(out.session.isEmpty)
        XCTAssertTrue(out.scan.findings.isEmpty)
    }
}

// MARK: - Erkennung

final class PIIDetectionTests: XCTestCase {

    func testHonorificPersonIsMaskedButSalutationRemains() async {
        let out = await makeGate().mask("Bitte Herrn Mueller informieren.")
        XCTAssertTrue(out.maskedContent.contains("Herrn"), out.maskedContent)
        XCTAssertFalse(out.maskedContent.contains("Mueller"))
    }

    func testCompanyIsNotAPerson() async {
        let out = await makeGate().mask("Die Acme GmbH hat geliefert.")
        XCTAssertEqual(out.maskedContent, "Die Acme GmbH hat geliefert.")
    }

    func testAmountIsNotMistakenForPostcode() async {
        // Regression: ohne Lookahead wurde 'Streitwert 50000 Euro' zu [Ort-1].
        let out = await makeGate().mask("Der Streitwert 50000 Euro steht fest.")
        XCTAssertEqual(out.maskedContent, "Der Streitwert 50000 Euro steht fest.")
    }

    func testDateIsNotMistakenForPhone() async {
        let out = await makeGate().mask("Termin am 01.02.2026 bestaetigt.")
        XCTAssertEqual(out.maskedContent, "Termin am 01.02.2026 bestaetigt.")
    }

    func testStopwordDoesNotBecomeSurname() async {
        // 'Herrn Mueller Bescheid' darf nicht 'Mueller Bescheid' als Namen lernen.
        let out = await makeGate().mask("Herrn Mueller Bescheid geben.")
        XCTAssertTrue(out.maskedContent.contains("Bescheid"), out.maskedContent)
    }

    func testMailAndIbanAreMasked() async {
        let out = await makeGate().mask("Mail a.schmidt@kanzlei.de, IBAN DE02120300000000202051")
        XCTAssertFalse(out.maskedContent.contains("@kanzlei.de"))
        XCTAssertFalse(out.maskedContent.contains("DE02120300000000202051"))
    }

    func testNamesakesGetDistinctTokens() async {
        // Namensvettern-Schutz: gleicher Nachname, verschiedene Personen.
        let gate = makeGate()
        let a = await gate.mask("Frau Anna Schmidt")
        let b = await gate.mask("Herr Bernd Schmidt")
        let tokenA = a.session.mapping.first(where: { $0.value == "Anna Schmidt" })?.key
        let tokenB = b.session.mapping.first(where: { $0.value == "Bernd Schmidt" })?.key
        XCTAssertNotNil(tokenA)
        XCTAssertNotNil(tokenB)
        XCTAssertNotEqual(tokenA, tokenB)
    }

    func testSamePersonKeepsStableTokenAcrossCalls() async {
        // Stabilitaet haelt Antworten kohaerent und erhoeht die Cache-Trefferquote.
        let gate = makeGate()
        let first = await gate.mask("Frau Anna Schmidt")
        let second = await gate.mask("Anna Schmidt kommt spaeter.")
        XCTAssertTrue(first.maskedContent.contains("[Person-1]"), first.maskedContent)
        XCTAssertTrue(second.maskedContent.contains("[Person-1]"), second.maskedContent)
    }
}

// MARK: - Steuerung

final class PIIPolicyTests: XCTestCase {

    func testAllowlistKeepsTermInClear() async {
        let policy = PseudonymizationPolicy(enabled: true, profile: "standard",
                                            allowlist: ["Anna Schmidt"])
        let out = await makeGate(policy).mask("Frau Anna Schmidt ruft an.")
        XCTAssertTrue(out.maskedContent.contains("Anna Schmidt"))
    }

    func testDenylistMasksArbitraryTerm() async {
        let policy = PseudonymizationPolicy(enabled: true, profile: "standard",
                                            denylist: ["Projekt Nordlicht"])
        let out = await makeGate(policy).mask("Status zu Projekt Nordlicht ist gruen.")
        XCTAssertFalse(out.maskedContent.contains("Nordlicht"))
        XCTAssertTrue(out.scan.findings.contains { $0.ruleID == PseudonymCategory.custom.ruleID })
    }

    func testKeepQueriedEntityLeavesAskedPersonInClear() async {
        let out = await makeGate().mask("Frau Anna Schmidt und Herr Klaus Mueller waren da.",
                                        sparingQuery: "Was ist mit Anna Schmidt?")
        XCTAssertTrue(out.maskedContent.contains("Anna Schmidt"), out.maskedContent)
        XCTAssertFalse(out.maskedContent.contains("Klaus Mueller"), out.maskedContent)
    }

    func testMinimalProfileSkipsPersons() async {
        let policy = PseudonymizationPolicy(enabled: true, profile: "minimal")
        let out = await makeGate(policy).mask("Frau Anna Schmidt, Mail a@b.de")
        XCTAssertTrue(out.maskedContent.contains("Anna Schmidt"))
        XCTAssertFalse(out.maskedContent.contains("a@b.de"))
    }

    func testAliasModeUsesGenericNamesAndStillUnmasks() async {
        let policy = PseudonymizationPolicy(enabled: true, profile: "standard",
                                            categoryModes: ["person": "alias"])
        let out = await makeGate(policy).mask("Frau Anna Schmidt kommt.")
        XCTAssertFalse(out.maskedContent.contains("Anna Schmidt"))
        XCTAssertFalse(out.maskedContent.contains("[Person-"), out.maskedContent)
        XCTAssertEqual(out.session.unmask(out.maskedContent), "Frau Anna Schmidt kommt.")
    }

    func testAliasNameIsDeterministic() {
        XCTAssertEqual(Pseudonymizer.aliasName(forToken: "[Person-1]"), "Alex A.")
        XCTAssertEqual(Pseudonymizer.aliasName(forToken: "[Person-2]"), "Bela B.")
        XCTAssertNil(Pseudonymizer.aliasName(forToken: "[Mail-1]"))
    }
}

// MARK: - Zusammenspiel mit der Gateway-Policy

final class PIIDispositionTests: XCTestCase {

    func testMaskedContentIsAllowedNotBlocked() async {
        // Ein PII-Treffer ist kein Verstoss — er wird behoben. Sonst waere jeder
        // realistische Prompt blockiert.
        let out = await makeGate().mask("Frau Anna Schmidt, IBAN DE02120300000000202051")
        let (disposition, risk) = GatewayPolicy.standard.disposition(for: out.scan)
        XCTAssertEqual(disposition, .allowModified)
        XCTAssertEqual(risk, 0, accuracy: 0.0001)
        XCTAssertFalse(out.scan.findings.isEmpty, "Befunde muessen im Audit sichtbar bleiben")
    }

    func testFindingsCarryPIIRuleIDs() async {
        let out = await makeGate().mask("Frau Anna Schmidt, Mail a@b.de")
        let ids = Set(out.scan.findings.map(\.ruleID))
        XCTAssertTrue(ids.contains(PseudonymCategory.person.ruleID))
        XCTAssertTrue(ids.contains(PseudonymCategory.mail.ruleID))
        XCTAssertTrue(out.scan.findings.allSatisfy { $0.category == .pii })
    }

    func testAuditFromPIIDecisionCarriesNoClearData() async throws {
        let out = await makeGate().mask("Frau Anna Schmidt, IBAN DE02120300000000202051")
        let (disposition, risk) = GatewayPolicy.standard.disposition(for: out.scan)
        let decision = GatewayDecision(
            correlationID: "c-1", disposition: disposition, riskScore: risk,
            findings: out.scan.findings, content: out.maskedContent)
        let event = AuditEvent(decision: decision, principal: Principal(subject: "u1"))
        let json = String(data: try JSONEncoder().encode(event), encoding: .utf8) ?? ""

        XCTAssertFalse(json.contains("Anna Schmidt"))
        XCTAssertFalse(json.contains("DE02120300000000202051"))
        XCTAssertTrue(json.contains("PII-001"))
    }

    func testDensityAbstainBlocks() async {
        let policy = PseudonymizationPolicy(
            enabled: true, profile: "streng",
            maxTokenDensity: 0.01, onDensityExceeded: "abstain")
        let out = await makeGate(policy).mask("Frau Anna Schmidt traf Herrn Klaus Mueller.")
        XCTAssertTrue(out.scan.findings.contains { $0.ruleID == PIIGate.ruleDensityExceeded })
        XCTAssertEqual(GatewayPolicy.standard.disposition(for: out.scan).0, .block)
    }

    func testDensityWarnDoesNotBlock() async {
        let policy = PseudonymizationPolicy(
            enabled: true, profile: "streng",
            maxTokenDensity: 0.01, onDensityExceeded: "warn")
        let out = await makeGate(policy).mask("Frau Anna Schmidt traf Herrn Klaus Mueller.")
        XCTAssertTrue(out.scan.findings.contains { $0.ruleID == PIIGate.ruleDensityExceeded })
        XCTAssertNotEqual(GatewayPolicy.standard.disposition(for: out.scan).0, .block)
    }
}

// MARK: - Vault

final class PseudonymVaultTests: XCTestCase {

    func testPartitionPathIsFilesystemSafe() {
        let base = URL(fileURLWithPath: "/tmp/gw")
        let url = PseudonymVault.url(baseDirectory: base, partition: "acme|hr.read,../etc")
        XCTAssertFalse(url.path.contains(".."))
        XCTAssertFalse(url.path.contains("|"))
        XCTAssertTrue(url.lastPathComponent.hasPrefix("pseudonyms-"))
    }

    func testDifferentPartitionsGetDifferentFiles() {
        let base = URL(fileURLWithPath: "/tmp/gw")
        XCTAssertNotEqual(PseudonymVault.url(baseDirectory: base, partition: "acme"),
                          PseudonymVault.url(baseDirectory: base, partition: "globex"))
    }

    func testTokensPersistAcrossVaultInstances() async throws {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("aigw-test-\(ProcessInfo.processInfo.processIdentifier)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = PseudonymVault.url(baseDirectory: dir, partition: "t1")

        let first = Pseudonymizer(vault: PseudonymVault(fileURL: url), policy: .gatewayDefault)
        let a = await first.mask("Frau Anna Schmidt")
        let tokenA = a.mapping.first(where: { $0.value == "Anna Schmidt" })?.key

        // Neue Instanz auf derselben Datei -> gleiches Token.
        let second = Pseudonymizer(vault: PseudonymVault(fileURL: url), policy: .gatewayDefault)
        let b = await second.mask("Anna Schmidt meldet sich.")
        let tokenB = b.mapping.first(where: { $0.value == "Anna Schmidt" })?.key

        XCTAssertNotNil(tokenA)
        XCTAssertEqual(tokenA, tokenB)
    }
}
