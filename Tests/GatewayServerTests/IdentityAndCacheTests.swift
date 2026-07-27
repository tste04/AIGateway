// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import XCTest
import GatewayCore
import InputFirewall
@testable import GatewayServer

// MARK: - Identitaet
//
// Die Vorbedingung des Cache. Geprueft wird vor allem, was NICHT passiert:
// eine unbelegte Behauptung darf keine Partition waehlen.

final class PrincipalResolverTests: XCTestCase {

    private func request(_ headers: [String: String]) -> HTTPRequest {
        HTTPRequest(method: "POST", path: "/v1/chat/completions",
                    headers: headers, body: Data())
    }

    private let claim = [
        "x-gateway-subject": "mallory",
        "x-gateway-tenant": "fremd-ag",
        "x-gateway-scopes": "finance,hr",
    ]

    func testAnonymousResolverIgnoresClaimsInsteadOfBelievingThem() {
        // Der Default darf die Header nicht glauben — und auch nicht abweisen.
        // Er uebergeht sie: es gibt dann nur eine Partition.
        let resolution = AnonymousPrincipalResolver().resolve(request(claim))
        XCTAssertEqual(resolution, .anonymous)
    }

    func testSharedSecretAcceptsClaimWithValidCredential() throws {
        let resolver = try XCTUnwrap(SharedSecretPrincipalResolver(secret: "s3cret"))
        var headers = claim
        headers["x-gateway-auth"] = "s3cret"

        guard case .identified(let principal) = resolver.resolve(request(headers)) else {
            return XCTFail("gueltiges Geheimnis muss die Behauptung tragen")
        }
        XCTAssertEqual(principal.subject, "mallory")
        XCTAssertEqual(principal.tenant, "fremd-ag")
        XCTAssertEqual(principal.scopes, ["finance", "hr"])
    }

    func testSharedSecretRejectsClaimWithoutCredential() throws {
        let resolver = try XCTUnwrap(SharedSecretPrincipalResolver(secret: "s3cret"))
        guard case .rejected = resolver.resolve(request(claim)) else {
            return XCTFail("Behauptung ohne Beleg muss abgewiesen werden")
        }
    }

    func testSharedSecretRejectsClaimWithWrongCredential() throws {
        let resolver = try XCTUnwrap(SharedSecretPrincipalResolver(secret: "s3cret"))
        var headers = claim
        headers["x-gateway-auth"] = "s3cres"
        guard case .rejected = resolver.resolve(request(headers)) else {
            return XCTFail("falsches Geheimnis darf nicht tragen")
        }
    }

    func testSharedSecretLetsUnclaimedRequestsThroughAsAnonymous() throws {
        let resolver = try XCTUnwrap(SharedSecretPrincipalResolver(secret: "s3cret"))
        XCTAssertEqual(resolver.resolve(request([:])), .anonymous)
    }

    func testSharedSecretCanDemandCredentialForEveryRequest() throws {
        let resolver = try XCTUnwrap(
            SharedSecretPrincipalResolver(secret: "s3cret", allowAnonymous: false))
        guard case .rejected = resolver.resolve(request([:])) else {
            return XCTFail("ohne anonyme Zulassung muss jede Anfrage belegen")
        }
    }

    func testEmptySecretIsRefusedAtConstruction() {
        // Ein leeres Geheimnis wuerde jede Anfrage ohne Header als belegt gelten
        // lassen — das darf gar nicht erst konstruierbar sein.
        XCTAssertNil(SharedSecretPrincipalResolver(secret: ""))
    }

    func testConstantTimeCompareKeepsNormalSemantics() {
        let equals = SharedSecretPrincipalResolver.constantTimeEquals
        XCTAssertTrue(equals("abc", "abc"))
        XCTAssertFalse(equals("abc", "abd"))
        XCTAssertFalse(equals("abc", "ab"), "ein Praefix ist kein Treffer")
        XCTAssertFalse(equals("ab", "abc"))
        XCTAssertTrue(equals("", ""))
    }
}

// MARK: - Cachebarkeit

final class CacheEligibilityTests: XCTestCase {

    private let policy = SemanticCachePolicy.on

    private func request(_ content: String, role: ChatMessage.Role = .user,
                         temperature: Double? = nil) -> ChatRequest {
        ChatRequest(model: "m", messages: [ChatMessage(role: role, content: content)],
                    temperature: temperature)
    }

    func testPlainQuestionIsCacheable() {
        XCTAssertTrue(CacheEligibility.isCacheable(request("Was ist ein Gateway?"), policy: policy))
    }

    func testToolMessagesAreNotCacheable() {
        // Werkzeug-Ausgaben gelten nur fuer den einen Vorgang.
        XCTAssertFalse(CacheEligibility.isCacheable(
            request("Ergebnis: 42", role: .tool), policy: policy))
    }

    func testHighTemperatureIsNotCacheable() {
        XCTAssertFalse(CacheEligibility.isCacheable(
            request("Erzaehl mir etwas", temperature: 0.9), policy: policy))
    }

    func testUnsetTemperatureIsCacheable() {
        // Wer nichts sagt, fordert keine Varianz an.
        XCTAssertTrue(CacheEligibility.isCacheable(request("Was ist X?"), policy: policy))
    }

    func testTimeReferencesAreNotCacheable() {
        for phrase in ["Was ist heute los?", "Nenne die aktuellen Zahlen",
                       "What is the latest release?", "Wie ist der Stand gerade?"] {
            XCTAssertFalse(CacheEligibility.isCacheable(request(phrase), policy: policy),
                           "Zeitbezug nicht erkannt: \(phrase)")
        }
    }

    func testDisabledPolicyMakesNothingCacheable() {
        XCTAssertFalse(CacheEligibility.isCacheable(
            request("Was ist X?"), policy: SemanticCachePolicy(enabled: false)))
    }
}

// MARK: - Schluessel und Entitaeten

final class CacheKeyTests: XCTestCase {

    func testRoleBoundariesCannotCollapse() {
        // Ohne Rollen-Trenner ergaeben diese beiden denselben Schluessel — und
        // eine Systemanweisung liesse sich als Nutzertext einschmuggeln.
        let split = ChatRequest(model: "m", messages: [
            ChatMessage(role: .system, content: "a"),
            ChatMessage(role: .user, content: "b"),
        ])
        let joined = ChatRequest(model: "m", messages: [
            ChatMessage(role: .user, content: "a\nb"),
        ])
        XCTAssertNotEqual(CacheKey(partition: "p", request: split),
                          CacheKey(partition: "p", request: joined))
    }

    func testPartitionIsPartOfTheKey() {
        let request = ChatRequest(model: "m", messages: [ChatMessage(role: .user, content: "x")])
        XCTAssertNotEqual(CacheKey(partition: "acme|", request: request),
                          CacheKey(partition: "other|", request: request))
    }

    func testModelAndSamplingArePartOfTheKey() {
        let base = ChatRequest(model: "m", messages: [ChatMessage(role: .user, content: "x")])
        let otherModel = ChatRequest(model: "n", messages: base.messages)
        let otherTemp = ChatRequest(model: "m", messages: base.messages, temperature: 0.1)
        XCTAssertNotEqual(CacheKey(partition: "p", request: base),
                          CacheKey(partition: "p", request: otherModel))
        XCTAssertNotEqual(CacheKey(partition: "p", request: base),
                          CacheKey(partition: "p", request: otherTemp))
    }

    func testSignatureSeparatesQuarters() {
        // Der Fall aus DECISIONS: im Einbettungsraum dicht, inhaltlich verschieden.
        XCTAssertNotEqual(EntitySignature.of("Umsatz Q3"), EntitySignature.of("Umsatz Q4"))
    }

    func testSignatureSeesPlaceholders() {
        XCTAssertNotEqual(EntitySignature.of("Bericht fuer [Person-1]"),
                          EntitySignature.of("Bericht fuer [Person-2]"))
    }

    func testSignatureIgnoresWordingWithoutEntities() {
        XCTAssertEqual(EntitySignature.of("Bitte fasse zusammen"),
                       EntitySignature.of("Fasse das bitte zusammen"))
    }
}

// MARK: - Der Cache

final class SemanticCacheTests: XCTestCase {

    private func request(_ content: String, model: String = "m") -> ChatRequest {
        ChatRequest(model: model, messages: [ChatMessage(role: .user, content: content)])
    }

    private func key(_ content: String, partition: String = "acme|", model: String = "m") -> CacheKey {
        CacheKey(partition: partition, request: request(content, model: model))
    }

    private let answer = ChatResponse(model: "m", content: "eine Antwort")

    func testExactHitReturnsStoredResponse() async {
        let cache = SemanticCache()
        let k = key("Was ist X?")
        await cache.store(key: k, maskedResponse: answer, embedding: nil,
                          entities: EntitySignature.of(k.prompt))
        let hit = await cache.lookup(key: k, embedding: nil, entities: EntitySignature.of(k.prompt))
        XCTAssertEqual(hit?.response.content, "eine Antwort")
        XCTAssertEqual(hit?.kind, .exact)
    }

    func testUnknownRequestMisses() async {
        let cache = SemanticCache()
        let k = key("Was ist X?")
        await cache.store(key: k, maskedResponse: answer, embedding: nil,
                          entities: EntitySignature.of(k.prompt))
        let other = key("Was ist Y?")
        let hit = await cache.lookup(key: other, embedding: nil,
                                     entities: EntitySignature.of(other.prompt))
        XCTAssertNil(hit)
    }

    func testPartitionsDoNotShareEntries() async {
        // Die wichtigste Zusicherung des Cache: gleiche Frage, andere
        // Berechtigung -> kein Treffer. Auch semantisch nicht.
        let cache = SemanticCache()
        let mine = key("Gehalt der Geschaeftsfuehrung", partition: "acme|finance")
        let theirs = key("Gehalt der Geschaeftsfuehrung", partition: "acme|")
        let signature = EntitySignature.of(mine.prompt)

        await cache.store(key: mine, maskedResponse: answer, embedding: [1, 0, 0],
                          entities: signature)
        let exact = await cache.lookup(key: theirs, embedding: [1, 0, 0], entities: signature)
        XCTAssertNil(exact, "fremde Partition darf weder exakt noch semantisch treffen")
    }

    func testSemanticHitNeedsThreshold() async {
        let cache = SemanticCache()
        let stored = key("Erklaere das Routing")
        await cache.store(key: stored, maskedResponse: answer, embedding: [1, 0, 0],
                          entities: EntitySignature.of(stored.prompt))

        let similar = key("Erklaere mir bitte das Routing")
        let signature = EntitySignature.of(similar.prompt)
        let near = await cache.lookup(key: similar, embedding: [0.99, 0.1, 0], entities: signature)
        XCTAssertEqual(near?.kind, .semantic)

        let far = key("Wie ist das Wetter")
        let farHit = await cache.lookup(key: far, embedding: [0, 1, 0],
                                        entities: EntitySignature.of(far.prompt))
        XCTAssertNil(farHit)
    }

    func testEntityGuardBeatsPerfectSimilarity() async {
        // Identischer Vektor, aber abweichende Zahl -> kein Treffer.
        let cache = SemanticCache()
        let stored = key("Umsatz Q3")
        await cache.store(key: stored, maskedResponse: answer, embedding: [1, 0, 0],
                          entities: EntitySignature.of(stored.prompt))

        let other = key("Umsatz Q4")
        let hit = await cache.lookup(key: other, embedding: [1, 0, 0],
                                     entities: EntitySignature.of(other.prompt))
        XCTAssertNil(hit, "der Waechter muss vor der Aehnlichkeit greifen")
    }

    func testDifferentModelsDoNotShareSemanticEntries() async {
        let cache = SemanticCache()
        let stored = key("Erklaere das Routing", model: "m")
        await cache.store(key: stored, maskedResponse: answer, embedding: [1, 0, 0],
                          entities: EntitySignature.of(stored.prompt))

        let otherModel = key("Erklaere mir das Routing", model: "n")
        let hit = await cache.lookup(key: otherModel, embedding: [1, 0, 0],
                                     entities: EntitySignature.of(otherModel.prompt))
        XCTAssertNil(hit)
    }

    func testEntriesExpire() async {
        let cache = SemanticCache(policy: SemanticCachePolicy(enabled: true, timeToLive: 60))
        let k = key("Was ist X?")
        let signature = EntitySignature.of(k.prompt)
        let stored = Date(timeIntervalSince1970: 1000)
        await cache.store(key: k, maskedResponse: answer, embedding: nil,
                          entities: signature, now: stored)

        let fresh = await cache.lookup(key: k, embedding: nil, entities: signature,
                                       now: stored.addingTimeInterval(30))
        XCTAssertNotNil(fresh)
        let stale = await cache.lookup(key: k, embedding: nil, entities: signature,
                                       now: stored.addingTimeInterval(90))
        XCTAssertNil(stale)
    }

    func testEvictionDropsTheLeastRecentlyUsed() async {
        let cache = SemanticCache(policy: SemanticCachePolicy(enabled: true, maxEntries: 2))
        let a = key("A"), b = key("B"), c = key("C")
        for k in [a, b] {
            await cache.store(key: k, maskedResponse: answer, embedding: nil,
                              entities: EntitySignature.of(k.prompt))
        }
        // A anfassen, damit B der aelteste Zugriff ist.
        _ = await cache.lookup(key: a, embedding: nil, entities: EntitySignature.of(a.prompt))
        await cache.store(key: c, maskedResponse: answer, embedding: nil,
                          entities: EntitySignature.of(c.prompt))

        let count = await cache.count()
        XCTAssertEqual(count, 2)
        let keptA = await cache.lookup(key: a, embedding: nil, entities: EntitySignature.of(a.prompt))
        let droppedB = await cache.lookup(key: b, embedding: nil, entities: EntitySignature.of(b.prompt))
        XCTAssertNotNil(keptA)
        XCTAssertNil(droppedB)
    }

    func testEmptyAnswersAreNotStored() async {
        let cache = SemanticCache()
        let k = key("Was ist X?")
        await cache.store(key: k, maskedResponse: ChatResponse(model: "m", content: ""),
                          embedding: nil, entities: EntitySignature.of(k.prompt))
        let count = await cache.count()
        XCTAssertEqual(count, 0, "ein leerer Text ist kein Ergebnis")
    }

    func testDisabledCacheNeverHits() async {
        let cache = SemanticCache(policy: SemanticCachePolicy(enabled: false))
        let k = key("Was ist X?")
        await cache.store(key: k, maskedResponse: answer, embedding: nil,
                          entities: EntitySignature.of(k.prompt))
        let hit = await cache.lookup(key: k, embedding: nil, entities: EntitySignature.of(k.prompt))
        XCTAssertNil(hit)
    }
}

// MARK: - Kosinus

final class VectorMathTests: XCTestCase {

    func testIdenticalVectorsScoreOne() {
        XCTAssertEqual(VectorMath.cosineSimilarity([1, 2, 3], [1, 2, 3]) ?? 0, 1, accuracy: 1e-9)
    }

    func testOrthogonalVectorsScoreZero() {
        XCTAssertEqual(VectorMath.cosineSimilarity([1, 0], [0, 1]) ?? 1, 0, accuracy: 1e-9)
    }

    func testIncomparableVectorsHaveNoScore() {
        // Keine erfundene Zahl: unterschiedliche Laenge und Nullvektor liefern
        // `nil`, damit daraus nie ein Treffer wird.
        XCTAssertNil(VectorMath.cosineSimilarity([1, 0], [1, 0, 0]))
        XCTAssertNil(VectorMath.cosineSimilarity([0, 0], [1, 0]))
        XCTAssertNil(VectorMath.cosineSimilarity([], []))
    }
}

// MARK: - Antwortformen des Embedders

final class HTTPEmbedderTests: XCTestCase {

    func testReadsAllThreeCommonShapes() {
        XCTAssertEqual(HTTPEmbedder.vector(from: ["embedding": [1.0, 2.0]]), [1, 2])
        XCTAssertEqual(HTTPEmbedder.vector(from: ["embeddings": [[3.0, 4.0]]]), [3, 4])
        XCTAssertEqual(HTTPEmbedder.vector(from: ["data": [["embedding": [5.0, 6.0]]]]), [5, 6])
    }

    func testMissingVectorIsNil() {
        XCTAssertNil(HTTPEmbedder.vector(from: ["error": "no model"]))
        XCTAssertNil(HTTPEmbedder.vector(from: ["embedding": [Double]()]))
    }
}
