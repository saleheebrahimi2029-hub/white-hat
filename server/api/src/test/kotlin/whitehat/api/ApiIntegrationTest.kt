package whitehat.api

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import io.ktor.client.HttpClient
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.testing.*
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.zonky.test.db.postgres.embedded.EmbeddedPostgres
import kotlinx.coroutines.*
import kotlinx.serialization.json.*
import org.flywaydb.core.Flyway
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.BeforeClass
import org.junit.AfterClass
import org.postgresql.ds.PGSimpleDataSource
import java.net.URI
import java.net.http.HttpClient as JdkHttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse as JdkHttpResponse
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.sql.SQLException
import java.time.Duration
import java.time.Instant
import java.util.Date
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.Callable
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.*
import whitehat.adapters.*
import whitehat.application.RunWorker
import whitehat.contracts.Mode
import whitehat.domain.*

class ApiIntegrationTest {
    companion object {
        private lateinit var pg: EmbeddedPostgres
        private val pair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        private val signer = Algorithm.RSA256(pair.public as RSAPublicKey, pair.private as RSAPrivateKey)
        private val verifier = JWT.require(Algorithm.RSA256(pair.public as RSAPublicKey, null)).withIssuer("https://issuer.test").withAudience("whitehat-api").build()
        @JvmStatic @BeforeClass fun startDatabase() { pg = EmbeddedPostgres.builder().setPort(0).setServerConfig("unix_socket_directories", "").start() }
        @JvmStatic @AfterClass fun stopDatabase() { if (::pg.isInitialized) pg.close() }
    }
    private lateinit var source: PGSimpleDataSource
    private lateinit var store: PostgresStore
    private lateinit var workspace: Workspace
    private val policy = EnginePolicy()
    private val validOutputs = Json.parseToJsonElement(requireNotNull(javaClass.getResourceAsStream("/legacy-output-fixtures.json")).use { it.readBytes().toString(Charsets.UTF_8) }).jsonObject

    private fun createDatabase(instance: EmbeddedPostgres = pg): PGSimpleDataSource {
        val name = "test_" + UUID.randomUUID().toString().replace("-", "")
        instance.postgresDatabase.connection.use { it.createStatement().use { s -> s.execute("CREATE DATABASE $name") } }
        return PGSimpleDataSource().apply {
            setURL("jdbc:postgresql://127.0.0.1:${instance.port}/$name")
            user = "postgres"
            password = "postgres"
        }
    }

    @Before fun prepare() {
        source = createDatabase()
        assertEquals(8, PostgresStore.migrate(source))
        store = PostgresStore(source, policy.hash)
        workspace = store.createWorkspace("alice", "تیم ما")
    }

    private fun token(subject: String = "alice", audience: String = "whitehat-api", kind: String = "access", expires: Boolean = true): String {
        val builder = JWT.create().withIssuer("https://issuer.test").withAudience(audience).withSubject(subject).withClaim("token_use", kind)
        if (expires) builder.withExpiresAt(Date.from(Instant.now().plusSeconds(300)))
        return builder.sign(signer)
    }
    private suspend fun HttpClient.requestJson(method: HttpMethod, path: String, actor: String? = "alice", body: String? = null, key: String? = null): HttpResponse = request(path) {
        this.method = method
        if (actor != null) bearerAuth(token(actor))
        if (body != null) { contentType(ContentType.Application.Json); setBody(body) }
        if (key != null) header("Idempotency-Key", key)
    }
    private suspend fun HttpResponse.obj() = Json.parseToJsonElement(bodyAsText()).jsonObject
    private fun path(suffix: String = "") = "/api/v1/workspaces/${workspace.id}$suffix"
    private fun draft(mode: Mode = Mode.CHALLENGE) = store.createDecision("alice", workspace.id, DecisionInput("تصمیم", "آیا پایلوت اجرا شود؟", "سنجش پرداخت", mode = mode))
    private fun output(mode: Mode) = validOutputs.getValue(mode.wireId).toString()
    private inner class Fixture : DecisionProvider {
        override val configured = true
        val calls = AtomicInteger()
        var action: suspend (Decision) -> String = { output(it.input.mode) }
        override suspend fun analyze(decision: Decision): ProviderResponse {
            calls.incrementAndGet()
            return ProviderResponse(action(decision), Receipt("fixture-not-live", "fixture-receipt", 100, 80))
        }
    }

    @Test fun scopedSupportCanRecordDispositionWithoutAccessingPrivateDataOrChangingRunState() {
        val id = workspace.id
        val other = store.createWorkspace("other-owner", "Other workspace")
        store.setMember("alice", id, "staff", Role.SUPPORT, true)
        store.setMember("alice", id, "admin", Role.ADMIN, true)
        assertEquals(403, assertFailsWith<Fault> { store.incidents("staff", id) }.status)
        assertEquals(403, assertFailsWith<Fault> { store.setIncidentPermission("admin", id, "staff", true) }.status)
        assertEquals(404, assertFailsWith<Fault> { store.incidents("staff", other.id) }.status)
        val decision = draft()
        val run = store.enqueue("alice", id, decision.id, decision.revision, "fixture-incident")
        val claim = requireNotNull(store.claim())
        store.complete(claim, Completion(error = "PROVIDER_OUTCOME_UNKNOWN", uncertain = true))
        store.setIncidentPermission("alice", id, "staff", true)
        assertTrue(store.members("alice", id).first { it.subject == "staff" }.canReviewIncidents)
        assertEquals(emptyList(), store.runHistory("admin", id))
        assertEquals(403, assertFailsWith<Fault> { store.runHistory("staff", id) }.status)
        assertEquals(403, assertFailsWith<Fault> { store.members("staff", id) }.status)
        assertEquals(403, assertFailsWith<Fault> { store.adminUsage("staff", id) }.status)
        assertEquals(listOf(RunIncident(run.id, null)), store.incidents("staff", id))
        store.reviewIncident("staff", id, run.id, IncidentDisposition.RECEIPT_REVIEWED)
        store.reviewIncident("staff", id, run.id, IncidentDisposition.RECEIPT_REVIEWED)
        assertEquals(listOf(RunIncident(run.id, IncidentDisposition.RECEIPT_REVIEWED)), store.incidents("alice", id))
        assertEquals("reconciliation_required", store.runHistory("alice", id).single().status)
        assertEquals(409, assertFailsWith<Fault> { store.enqueue("alice", id, decision.id, 1, "fixture-new-key") }.status)
        source.connection.use { connection ->
            connection.createStatement().use { statement ->
                statement.executeQuery("SELECT count(*) FROM audit WHERE action='incident.receipt_reviewed'").use {
                    assertTrue(it.next()); assertEquals(1, it.getInt(1))
                }
            }
        }
        store.setMember("alice", id, "staff", Role.SUPPORT, false)
        assertEquals(404, assertFailsWith<Fault> { store.incidents("staff", id) }.status)
        store.setMember("alice", id, "staff", Role.SUPPORT, true)
        assertEquals(403, assertFailsWith<Fault> { store.incidents("staff", id) }.status)
    }

    @Test fun metricsCostsFeedbackAndPermissionsRemainIndependent() {
        val id = workspace.id
        val decision = draft()
        val run = store.enqueue("alice", id, decision.id, decision.revision, "feedback-fixture")
        store.complete(requireNotNull(store.claim()), Completion(output=output(Mode.CHALLENGE)))
        store.setMember("alice", id, "staff", Role.SUPPORT, true)
        store.setMember("alice", id, "member", Role.MEMBER, true)
        assertEquals(409, assertFailsWith<Fault> { store.submitFeedback("alice", id, run.id, 4) }.status)
        store.setFeedbackEnabled("alice", id, true)
        assertEquals(404, assertFailsWith<Fault> { store.submitFeedback("member", id, run.id, 4) }.status)
        store.submitFeedback("alice", id, run.id, 4)
        assertEquals(403, assertFailsWith<Fault> { store.qualityQueue("staff", id) }.status)
        store.setOperatorPermission("alice", id, "staff", OperatorPermission.REVIEW_QUALITY_FEEDBACK, true)
        store.setOperatorPermission("alice", id, "staff", OperatorPermission.READ_RUN_METRICS, true)
        assertEquals(403, assertFailsWith<Fault> { store.incidents("staff", id) }.status)
        assertEquals(1L, store.operationsMetrics("staff", id)["latency_samples"])
        assertNull(store.confirmedCosts("alice", id)["confirmed_usd_micros"])
        assertEquals(403, assertFailsWith<Fault> { store.confirmedCosts("staff", id) }.status)
        store.recordConfirmedCost("alice", id, run.id, 43, "verified-fixture-receipt")
        store.recordConfirmedCost("alice", id, run.id, 43, "verified-fixture-receipt")
        assertEquals(409, assertFailsWith<Fault> {
            store.recordConfirmedCost("alice", id, run.id, 44, "verified-fixture-receipt")
        }.status)
        assertEquals(43L, store.confirmedCosts("alice", id)["confirmed_usd_micros"])
        store.markFeedbackReviewed("staff", id, run.id)
        assertEquals(listOf(QualityFeedback(run.id, 4, true)), store.qualityQueue("staff", id))
        store.submitFeedback("alice", id, run.id, 4)
        assertTrue(store.qualityQueue("staff", id).single().reviewed)
        store.setOperatorPermission("alice", id, "staff", OperatorPermission.REVIEW_QUALITY_FEEDBACK, false)
        assertEquals(403, assertFailsWith<Fault> { store.qualityQueue("staff", id) }.status)
        assertEquals(1L, store.operationsMetrics("staff", id)["runs"])
        store.setFeedbackEnabled("alice", id, false)
        store.withdrawFeedback("alice", id, run.id)
        assertEquals(emptyList(), store.qualityQueue("alice", id))
    }

    @Test fun pauseRejectsNewAnalysisAndReturnsExistingIdempotentRun() {
        val id=workspace.id
        val decision=draft()
        val run=store.enqueue("alice",id,decision.id,1,"before-pause")
        store.setAnalysisPaused("alice",id,true)
        assertTrue(store.analysisPaused("alice",id))
        assertEquals(run,store.enqueue("alice",id,decision.id,1,"before-pause"))
        assertEquals("ANALYSIS_PAUSED",assertFailsWith<Fault> {
            store.enqueue("alice",id,decision.id,1,"while-paused")
        }.code)
        store.setAnalysisPaused("alice",id,false)
        store.cancel("alice",id,run.id)
        assertEquals("queued",store.enqueue("alice",id,decision.id,1,"after-pause").status)
    }

    @Test fun correctionIsIdempotentAndPreservesAuditHistory() {
        val id=workspace.id
        val decision=draft()
        val run=store.enqueue("alice",id,decision.id,1,"cost-correction")
        store.complete(requireNotNull(store.claim()),Completion(output=output(Mode.CHALLENGE)))
        store.recordConfirmedCost("alice",id,run.id,50,"synthetic-first")
        val key=UUID.randomUUID()
        store.correctConfirmedCost("alice",id,run.id,key,50,75,"synthetic-corrected")
        store.correctConfirmedCost("alice",id,run.id,key,50,75,"synthetic-corrected")
        assertEquals(75L,store.confirmedCosts("alice",id)["confirmed_usd_micros"])
        assertEquals(409,assertFailsWith<Fault> {
            store.correctConfirmedCost("alice",id,run.id,UUID.randomUUID(),50,90,"stale")
        }.status)
        source.connection.use { connection ->
            connection.createStatement().use { statement ->
                statement.executeQuery("SELECT count(*) FROM run_cost_corrections").use {
                    assertTrue(it.next()); assertEquals(1,it.getInt(1))
                }
                assertFails { statement.executeUpdate("DELETE FROM run_cost_corrections") }
            }
        }
    }

    @Test fun customSupportRoleRevocationAndWorkspaceBoundary() {
        val id = workspace.id
        val other = store.createWorkspace("alice", "Other")
        val template = SupportRole(UUID.randomUUID(),"Operations",setOf(OperatorPermission.READ_RUN_METRICS))
        store.setMember("alice",id,"support",Role.SUPPORT,true)
        store.setMember("alice",other.id,"support",Role.SUPPORT,true)
        store.saveSupportRole("alice",id,template)
        assertEquals(listOf(template),store.supportRoles("alice",id))
        assertEquals(403,assertFailsWith<Fault> { store.saveSupportRole("support",id,template) }.status)
        assertEquals(404,assertFailsWith<Fault> { store.assignSupportRole("alice",other.id,"support",template.id) }.status)
        store.assignSupportRole("alice",id,"support",template.id)
        assertEquals(template.id,store.members("alice",id).first { it.subject=="support" }.supportRoleId)
        assertEquals(0L,store.operationsMetrics("support",id)["runs"])
        assertEquals(403,assertFailsWith<Fault> { store.confirmedCosts("support",id) }.status)
        store.saveSupportRole("alice",id,template.copy(permissions=emptySet()))
        assertEquals(403,assertFailsWith<Fault> { store.operationsMetrics("support",id) }.status)
        store.saveSupportRole("alice",id,template)
        store.setMember("alice",id,"support",Role.SUPPORT,false)
        store.setMember("alice",id,"support",Role.SUPPORT,true)
        assertNull(store.members("alice",id).first { it.subject=="support" }.supportRoleId)
        assertEquals(403,assertFailsWith<Fault> { store.operationsMetrics("support",id) }.status)
    }

    @Test fun feedbackRetentionFiltersAndPurgesOnlyExpiredWorkspaceRows() {
        val id=workspace.id
        assertNull(store.feedbackRetention("alice",id))
        assertEquals(409,assertFailsWith<Fault> { store.purgeExpiredFeedback("alice",id) }.status)
        store.setFeedbackRetention("alice",id,30)
        store.setFeedbackEnabled("alice",id,true)
        assertEquals(30,store.feedbackRetention("alice",id))
        val decision=draft()
        val old=store.enqueue("alice",id,decision.id,1,"old-retention")
        store.complete(requireNotNull(store.claim()),Completion(output=output(Mode.CHALLENGE)))
        val fresh=store.enqueue("alice",id,decision.id,1,"new-retention")
        store.complete(requireNotNull(store.claim()),Completion(output=output(Mode.CHALLENGE)))
        store.submitFeedback("alice",id,old.id,4)
        store.submitFeedback("alice",id,fresh.id,5)
        source.connection.use { connection ->
            connection.prepareStatement("UPDATE run_quality_feedback SET submitted_at=now()-interval '31 days' WHERE run_id=?").use {
                it.setObject(1,old.id); assertEquals(1,it.executeUpdate())
            }
        }
        assertEquals(listOf(fresh.id),store.qualityQueue("alice",id).map { it.runId })
        assertEquals(1,store.sweepExpiredFeedback())
        assertEquals(0,store.sweepExpiredFeedback())
        assertEquals(0,store.purgeExpiredFeedback("alice",id))
        assertEquals(listOf(fresh.id),store.qualityQueue("alice",id).map { it.runId })
    }

    @Test fun tenantRlsDeniesCrossWorkspaceAndResetsAtTransactionEnd() {
        val other = store.createWorkspace("other", "Other")
        draft()
        store.createDecision("other", other.id, DecisionInput("Other", "Private"))
        source.connection.use { connection ->
            connection.createStatement().use { statement ->
                val role = "rls_" + UUID.randomUUID().toString().replace("-", "")
                statement.execute("CREATE ROLE $role NOLOGIN NOBYPASSRLS")
                statement.execute("GRANT SELECT, INSERT ON decisions TO $role")
                statement.execute("SET ROLE $role")
                connection.autoCommit = false
                fun visible(): List<String> = statement.executeQuery("SELECT title FROM decisions").use { rows ->
                    buildList { while (rows.next()) add(rows.getString(1)) }
                }
                assertEquals(emptyList(), visible())
                statement.execute("SELECT set_config('whitehat.workspace', '${workspace.id}', true)")
                assertEquals(listOf("تصمیم"), visible())
                assertFails {
                    statement.execute("""INSERT INTO decisions(workspace_id,id,owner_subject,title,decision,objective,context,source_notes,mode)
                        VALUES ('${other.id}','${UUID.randomUUID()}','other','forged','synthetic','','','','challenge')""")
                }
                connection.rollback()
                assertEquals(emptyList(), visible())
                connection.rollback()
            }
        }
    }

    @Test fun migrationIsRepeatableAndAuthCannotBeBypassed() = testApplication {
        assertEquals(0, PostgresStore.migrate(source))
        PostgresStore.validate(source)
        application { whiteHatApi(store, verifier) { true } }
        assertEquals(HttpStatusCode.OK, client.get("/api/v1/health").status)
        val noAuth = client.get("/api/v1/me")
        assertEquals(HttpStatusCode.Unauthorized, noAuth.status)
        assertNotNull(noAuth.headers["X-Request-ID"])
        for (jwt in listOf(token(audience = "wrong"), token(kind = "id"), token(expires = false), "not.a.token")) {
            assertEquals(HttpStatusCode.Unauthorized, client.get("/api/v1/me") { bearerAuth(jwt) }.status)
        }
        val expired = JWT.create().withIssuer("https://issuer.test").withAudience("whitehat-api").withSubject("alice").withClaim("token_use", "access").withExpiresAt(Date.from(Instant.now().minusSeconds(60))).sign(signer)
        val wrongAlgorithm = JWT.create().withIssuer("https://issuer.test").withAudience("whitehat-api").withSubject("alice").withClaim("token_use", "access").withExpiresAt(Date.from(Instant.now().plusSeconds(60))).sign(Algorithm.HMAC256("fixture-only-not-a-key"))
        for (jwt in listOf(expired, wrongAlgorithm)) assertEquals(HttpStatusCode.Unauthorized, client.get("/api/v1/me") { bearerAuth(jwt) }.status)
        assertEquals("alice", client.requestJson(HttpMethod.Get, "/api/v1/me").obj().getValue("subject").jsonPrimitive.content)
    }

    @Test fun actualHttpRouteQueuesAndWorkerCompletesAllSevenModes() = testApplication {
        application { whiteHatApi(store, verifier) { true } }
        val fixture = Fixture(); val worker = RunWorker(store, fixture)
        for (mode in Mode.entries) {
            val create = client.requestJson(HttpMethod.Post, path("/decisions"), body = """{"title":"پایلوت","decision":"پایلوت را اجرا کنیم؟","objective":"سنجش پرداخت","mode":"${mode.wireId}"}""")
            assertEquals(HttpStatusCode.Created, create.status)
            val id = create.obj().getValue("id").jsonPrimitive.content
            val queued = client.requestJson(HttpMethod.Post, path("/decisions/$id/runs"), body = """{"expected_revision":1}""", key = "test_${mode.wireId}_0001")
            assertEquals(HttpStatusCode.Accepted, queued.status)
            val run = queued.obj().getValue("id").jsonPrimitive.content
            assertTrue(worker.tick())
            val result = client.requestJson(HttpMethod.Get, path("/runs/$run")).obj()
            val sample = java.io.File("build/contract-samples/run-${mode.wireId}.json")
            sample.parentFile.mkdirs(); sample.writeText(result.toString())
            assertEquals("succeeded", result.getValue("status").jsonPrimitive.content)
            assertEquals(mode.wireId, result.getValue("result").jsonObject.getValue("mode").jsonPrimitive.content)
            assertEquals(100, result.getValue("input_tokens").jsonPrimitive.int)
            assertEquals("no-store", client.requestJson(HttpMethod.Get, path("/runs/$run")).headers["Cache-Control"])
        }
        assertEquals(7, fixture.calls.get())
        assertEquals("3.1.0", client.get("/api/v1/openapi.json").obj().getValue("openapi").jsonPrimitive.content)
    }

    @Test fun organizationMemberSupportAndOwnerBoundariesAreEnforced() = testApplication {
        val decision = draft()
        store.setMember("alice", workspace.id, "bob", Role.MEMBER, true)
        store.setMember("alice", workspace.id, "support", Role.SUPPORT, true)
        val outside = store.createWorkspace("mallory", "دیگر")
        application { whiteHatApi(store, verifier) { true } }
        assertEquals(HttpStatusCode.NotFound, client.requestJson(HttpMethod.Get, path("/decisions/${decision.id}"), "bob").status)
        assertEquals(HttpStatusCode.NotFound, client.requestJson(HttpMethod.Get, path("/decisions"), "mallory").status)
        assertEquals(HttpStatusCode.NotFound, client.requestJson(HttpMethod.Get, "/api/v1/workspaces/${outside.id}/decisions").status)
        assertEquals(HttpStatusCode.Forbidden, client.requestJson(HttpMethod.Get, path("/decisions"), "support").status)
        assertEquals(HttpStatusCode.Forbidden, client.requestJson(HttpMethod.Get, path("/admin/usage"), "bob").status)
        assertEquals(HttpStatusCode.Forbidden, client.requestJson(HttpMethod.Post, path("/members"), "bob", """{"subject":"bob","role":"ADMIN","active":true}""").status)
        store.setMember("alice", workspace.id, "bob", Role.MEMBER, false)
        assertEquals(HttpStatusCode.NotFound, client.requestJson(HttpMethod.Get, path("/decisions"), "bob").status)
        val fail = assertFailsWith<Fault> { store.setMember("alice", workspace.id, "alice", Role.ADMIN, false) }
        assertEquals("OWNER_TRANSFER_REQUIRED", fail.code)
    }

    @Test fun revisionsAndIdempotencyAreBoundToAnImmutableInput() = testApplication {
        val d = draft(); val fixture = Fixture()
        application { whiteHatApi(store, verifier) { true } }
        val edited = client.requestJson(HttpMethod.Put, path("/decisions/${d.id}"), body = """{"expected_revision":1,"title":"بازنگری","decision":"آزمون جدید؟"}""")
        assertEquals(2, edited.obj().getValue("revision").jsonPrimitive.int)
        assertEquals(HttpStatusCode.Conflict, client.requestJson(HttpMethod.Post, path("/decisions/${d.id}/runs"), body = """{"expected_revision":1}""", key = "stale_key_001").status)
        val r = store.enqueue("alice", workspace.id, d.id, 2, "repeat_key_001")
        assertEquals(r.id, store.enqueue("alice", workspace.id, d.id, 2, "repeat_key_001").id)
        assertEquals("IDEMPOTENCY_CONFLICT", assertFailsWith<Fault> { store.enqueue("alice", workspace.id, d.id, 1, "repeat_key_001") }.code)
        assertEquals("ACTIVE_RUN_EXISTS", assertFailsWith<Fault> { store.editDecision("alice", workspace.id, d.id, 2, d.input) }.code)
        assertTrue(RunWorker(store, fixture).tick()); assertEquals(1, fixture.calls.get())
    }

    @Test fun concurrentDuplicatesCreateOneReservationAndOneProviderCall() = runBlocking {
        val d = draft(); val pool = Executors.newFixedThreadPool(8)
        try {
            val results = pool.invokeAll(List(8) { Callable { store.enqueue("alice", workspace.id, d.id, 1, "concurrent_0001").id } }).map { it.get() }
            assertEquals(1, results.toSet().size)
            val fixture = Fixture(); val worker = RunWorker(store, fixture)
            coroutineScope { listOf(async { worker.tick() }, async { worker.tick() }).awaitAll() }
            assertEquals(1, fixture.calls.get())
            source.connection.use { c -> c.createStatement().executeQuery("SELECT attempts FROM usage_counters").use { it.next(); assertEquals(1, it.getInt(1)) } }
        } finally { pool.shutdownNow() }
    }

    @Test fun quotaReservationsRemainAtomicAcrossDifferentDecisions() {
        val limited = PostgresStore(source, policy.hash, 2)
        val drafts = List(8) { draft() }; val pool = Executors.newFixedThreadPool(8)
        try {
            val results = pool.invokeAll(drafts.mapIndexed { index, d -> Callable {
                try { limited.enqueue("alice", workspace.id, d.id, 1, "quota_key_$index"); 202 } catch (f: Fault) { f.status }
            } }).map { it.get() }
            assertEquals(2, results.count { it == 202 }); assertEquals(6, results.count { it == 429 })
            assertEquals(2L, store.adminUsage("alice", workspace.id)["runs"])
            assertNull(store.adminUsage("alice", workspace.id)["input_tokens"])
        } finally { pool.shutdownNow() }
    }

    private fun publishPilotEntitlement(workspace: UUID, revision: Long, limit: Int) {
        source.connection.use { connection ->
            connection.autoCommit = false
            connection.prepareStatement("SELECT id FROM workspaces WHERE id=? FOR UPDATE").use {
                it.setObject(1, workspace)
                it.executeQuery().use { rows -> check(rows.next()) }
            }
            connection.prepareStatement("""
                INSERT INTO workspace_pilot_entitlements(workspace_id,revision,monthly_attempt_limit) VALUES (?,?,?)
            """).use { statement ->
                statement.setObject(1, workspace)
                statement.setLong(2, revision)
                statement.setInt(3, limit)
                statement.executeUpdate()
            }
            connection.commit()
        }
    }

    @Test fun pilotEntitlementMetersOnlyNewRunsAndKeepsReplayAvailable() = testApplication {
        application { whiteHatApi(store, verifier) { true } }
        val legacy = store.enqueue("alice", workspace.id, draft().id, 1, "legacy_pilot_001")
        publishPilotEntitlement(workspace.id, 1, 0)
        val d = draft()
        suspend fun submit(key: String) = client.requestJson(
            HttpMethod.Post, path("/decisions/${d.id}/runs"), body = """{"expected_revision":1}""", key = key,
        )
        val denied = submit("pilot_run_001")
        assertEquals(HttpStatusCode.TooManyRequests, denied.status)
        assertEquals("PILOT_LIMIT_REACHED", denied.obj().getValue("error").jsonPrimitive.content)

        publishPilotEntitlement(workspace.id, 2, 1)
        val run = store.enqueue("alice", workspace.id, d.id, 1, "pilot_run_001")
        store.cancel("alice", workspace.id, run.id)
        assertEquals(run.id, store.enqueue("alice", workspace.id, d.id, 1, "pilot_run_001").id)
        assertEquals(HttpStatusCode.TooManyRequests, submit("pilot_run_002").status)

        publishPilotEntitlement(workspace.id, 3, 2)
        val second = store.enqueue("alice", workspace.id, d.id, 1, "pilot_run_002")
        source.connection.use { connection ->
            connection.prepareStatement("SELECT id,pilot_entitlement_revision FROM runs WHERE workspace_id=?").use {
                it.setObject(1, workspace.id)
                it.executeQuery().use { rows ->
                    val revisions = buildMap {
                        while (rows.next()) put(rows.getObject(1, UUID::class.java), rows.getObject(2, Long::class.javaObjectType))
                    }
                    assertEquals(mapOf(legacy.id to null, run.id to 2L, second.id to 3L), revisions)
                }
            }
        }
    }

    @Test fun pilotCapIsWorkspaceScopedWithAtomicMeteringAcrossOwners() {
        publishPilotEntitlement(workspace.id, 1, 3)
        store.setMember("alice", workspace.id, "bob", Role.MEMBER, true)
        val requests = List(16) { index ->
            val subject = if (index % 2 == 0) "alice" else "bob"
            subject to store.createDecision(subject, workspace.id, DecisionInput("Pilot", "Synthetic", mode = Mode.CHALLENGE))
        }
        val pool = Executors.newFixedThreadPool(8)
        try {
            val results = pool.invokeAll(requests.mapIndexed { index, (subject, decision) -> Callable {
                try {
                    store.enqueue(subject, workspace.id, decision.id, 1, "pilot_load_$index")
                    "accepted"
                } catch (failure: Fault) {
                    failure.code
                }
            } }).map { it.get() }
            assertEquals(3, results.count { it == "accepted" })
            assertEquals(13, results.count { it == "PILOT_LIMIT_REACHED" })

            val other = store.createWorkspace("alice", "Another workspace")
            val d = store.createDecision("alice", other.id, DecisionInput("Control", "Synthetic", mode = Mode.CHALLENGE))
            assertEquals("queued", store.enqueue("alice", other.id, d.id, 1, "control_run_001").status)
            source.connection.use { connection ->
                connection.createStatement().use { statement ->
                    statement.executeQuery("""
                        SELECT (SELECT sum(attempts) FROM workspace_pilot_usage),
                               (SELECT count(*) FROM runs WHERE pilot_entitlement_revision IS NOT NULL),
                               (SELECT sum(attempts) FROM usage_counters)
                    """).use { rows ->
                        assertTrue(rows.next())
                        assertEquals(3, rows.getInt(1))
                        assertEquals(3, rows.getInt(2))
                        assertEquals(4, rows.getInt(3))
                    }
                    val role = "pilot_" + UUID.randomUUID().toString().replace("-", "")
                    statement.execute("CREATE ROLE $role NOLOGIN NOBYPASSRLS")
                    statement.execute("GRANT SELECT ON workspace_pilot_entitlements, workspace_pilot_usage TO $role")
                    statement.execute("GRANT INSERT ON workspace_pilot_usage TO $role")
                    statement.execute("SET ROLE $role")
                    connection.autoCommit = false
                    for (tenant in listOf(other.id, workspace.id)) {
                        statement.execute("SELECT set_config('whitehat.workspace', '$tenant', true)")
                        statement.executeQuery("""
                            SELECT (SELECT count(*) FROM workspace_pilot_entitlements),
                                   (SELECT count(*) FROM workspace_pilot_usage)
                        """).use { rows ->
                            assertTrue(rows.next())
                            val visible = if (tenant == workspace.id) 1 else 0
                            assertEquals(visible, rows.getInt(1))
                            assertEquals(visible, rows.getInt(2))
                        }
                    }
                    statement.execute("SELECT set_config('whitehat.workspace', '${other.id}', true)")
                    assertEquals("42501", assertFailsWith<SQLException> {
                        statement.executeUpdate("""
                            INSERT INTO workspace_pilot_usage(workspace_id,period_start,attempts)
                            VALUES ('${workspace.id}', DATE '2000-01-01', 1)
                        """)
                    }.sqlState)
                    connection.rollback()
                }
            }
        } finally {
            pool.shutdownNow()
        }
    }

    @Test fun upgradesV7WorkspaceWithoutEnrollingItInPilot() {
        val previous = createDatabase()
        assertEquals(7, Flyway.configure().dataSource(previous)
            .locations("classpath:db/migration").target("7").load().migrate().migrationsExecuted)
        val previousStore = PostgresStore(previous, policy.hash)
        val existing = previousStore.createWorkspace("alice", "Pre-migration workspace")
        val decision = previousStore.createDecision("alice", existing.id, DecisionInput("Before", "Synthetic"))
        val run = UUID.randomUUID()
        previous.connection.use { connection ->
            connection.prepareStatement("""
                INSERT INTO runs(workspace_id,id,decision_id,owner_subject,input_revision,idempotency_key,
                    request_hash,snapshot_json,status,engine_hash) VALUES (?, ?, ?, 'alice', 1, 'pre_v8_run',
                    ?, '{}'::jsonb, 'cancelled', ?)
            """).use { statement ->
                statement.setObject(1, existing.id)
                statement.setObject(2, run)
                statement.setObject(3, decision.id)
                statement.setString(4, "0".repeat(64))
                statement.setString(5, policy.hash)
                assertEquals(1, statement.executeUpdate())
            }
        }
        assertEquals(1, PostgresStore.migrate(previous))
        assertEquals(0, PostgresStore.migrate(previous))
        PostgresStore.validate(previous)
        assertEquals("cancelled", previousStore.run("alice", existing.id, run).status)
        assertEquals("queued", previousStore.enqueue("alice", existing.id, decision.id, 1, "post_v8_run").status)
        previous.connection.use { connection ->
            connection.createStatement().executeQuery("""
                SELECT count(*) FROM runs WHERE pilot_entitlement_revision IS NULL
            """).use { rows ->
                assertTrue(rows.next())
                assertEquals(2, rows.getInt(1))
            }
        }
    }

    @Test fun restoresPilotUsageAndReplayProtectionFromPostgresArchive() {
        val binDir = System.getenv("WH_TEST_PG_BIN_DIR")
        assumeTrue("Set WH_TEST_PG_BIN_DIR to run the PostgreSQL backup drill", !binDir.isNullOrBlank())
        val tools = Path.of(requireNotNull(binDir))
        val directory = Files.createTempDirectory("whitehat-pilot-backup-")
        val archive = directory.resolve("pilot.dump")
        val log = directory.resolve("tools.log")
        fun runTool(tool: String, port: Int, vararg args: String) {
            val process = ProcessBuilder(
                tools.resolve(tool).toString(), "--host=127.0.0.1", "--port=$port", "--username=postgres",
                "--no-password", *args,
            ).redirectErrorStream(true).redirectOutput(log.toFile()).start()
            if (!process.waitFor(30, TimeUnit.SECONDS)) {
                process.destroyForcibly().waitFor()
                error("$tool timed out")
            }
            assertEquals(0, process.exitValue(), Files.readString(log))
        }
        try {
            publishPilotEntitlement(workspace.id, 1, 1)
            val d = draft()
            val r = store.enqueue("alice", workspace.id, d.id, 1, "backup_pilot_001")
            store.cancel("alice", workspace.id, r.id)
            store.recordConfirmedCost("alice", workspace.id, r.id, 250, "synthetic-backup-receipt")
            runTool("pg_dump", pg.port, "--format=custom", "--file=$archive", requireNotNull(source.databaseName))

            EmbeddedPostgres.builder().setPort(0).setServerConfig("unix_socket_directories", "").start().use { target ->
                assertNotEquals(pg.port, target.port)
                val restored = createDatabase(target)
                runTool("pg_restore", target.port, "--exit-on-error", "--single-transaction", "--no-owner", "--no-privileges",
                    "--dbname=${restored.databaseName}", archive.toString())
                PostgresStore.validate(restored)
                val recoveredStore = PostgresStore(restored, policy.hash)
                assertEquals(r.id, recoveredStore.enqueue("alice", workspace.id, d.id, 1, "backup_pilot_001").id)
                assertEquals("cancelled", recoveredStore.run("alice", workspace.id, r.id).status)
                assertEquals(store.pilotUsage("alice", workspace.id), recoveredStore.pilotUsage("alice", workspace.id))
                assertEquals("PILOT_LIMIT_REACHED", assertFailsWith<Fault> {
                    recoveredStore.enqueue("alice", workspace.id, d.id, 1, "backup_pilot_002")
                }.code)
            }
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test fun invalidOutputFailsButKeepsActualUsage() = runBlocking {
        val d = draft(); val r = store.enqueue("alice", workspace.id, d.id, 1, "invalid_output_001")
        val fixture = Fixture().apply { action = { "{}" } }
        RunWorker(store, fixture).tick()
        val result = store.run("alice", workspace.id, r.id)
        assertEquals("failed", result.status); assertEquals("INVALID_MODEL_OUTPUT", result.error)
        assertNull(result.result); assertEquals(100L, result.inputTokens)
    }

    @Test fun uncertainProviderOutcomeIsNeverAutomaticallyRetried() = runBlocking {
        val d = draft(); val r = store.enqueue("alice", workspace.id, d.id, 1, "uncertain_001")
        val fixture = Fixture().apply { action = { throw ProviderFailure("PROVIDER_OUTCOME_UNKNOWN", true) } }
        val worker = RunWorker(store, fixture)
        worker.tick(); assertFalse(worker.tick())
        assertEquals("reconciliation_required", store.run("alice", workspace.id, r.id).status)
        assertEquals("reconciliation_required", store.enqueue("alice", workspace.id, d.id, 1, "uncertain_001").status)
        assertEquals("ACTIVE_RUN_EXISTS", assertFailsWith<Fault> { store.enqueue("alice", workspace.id, d.id, 1, "uncertain_002") }.code)
        assertEquals(1, fixture.calls.get())
    }

    @Test fun expiredLeaseRejectsLateOutputAndPreservesItsReceiptOnce() {
        val d = draft(); val r = store.enqueue("alice", workspace.id, d.id, 1, "lease_expiry_001")
        val claim = store.claim()!!
        source.connection.use { c -> c.createStatement().use { it.executeUpdate("UPDATE runs SET lease_until=now()-interval '1 second'") } }
        assertNull(store.claim())
        val completion = Completion(output(d.input.mode), receipt = Receipt("fixture-not-live", "late-receipt", 21, 13))
        store.complete(claim, completion); store.complete(claim, completion)
        val result = store.run("alice", workspace.id, r.id)
        assertEquals("reconciliation_required", result.status); assertNull(result.result); assertEquals(21L, result.inputTokens)
        source.connection.use { c -> c.createStatement().executeQuery("SELECT count(*) FROM provider_receipts").use { it.next(); assertEquals(1, it.getInt(1)) } }
    }

    @Test fun queuedAndInFlightCancellationsDiscardOutputWithoutHidingCost() = runBlocking {
        val d = draft(); val fixture = Fixture(); val worker = RunWorker(store, fixture)
        val r = store.enqueue("alice", workspace.id, d.id, 1, "cancel_queued_001")
        assertEquals("cancelled", store.cancel("alice", workspace.id, r.id).status)
        assertEquals("cancelled", store.cancel("alice", workspace.id, r.id).status)
        assertFalse(worker.tick()); assertEquals(0, fixture.calls.get())
        val started = CompletableDeferred<Unit>(); val finish = CompletableDeferred<Unit>()
        fixture.action = { started.complete(Unit); finish.await(); output(it.input.mode) }
        val running = store.enqueue("alice", workspace.id, d.id, 1, "cancel_running_001")
        val job = async { worker.tick() }; started.await()
        assertEquals("cancellation_requested", store.cancel("alice", workspace.id, running.id).status)
        finish.complete(Unit); job.await()
        val result = store.run("alice", workspace.id, running.id)
        assertEquals("cancelled", result.status); assertNull(result.result); assertEquals(100L, result.inputTokens)
    }

    @Test fun noProviderOrInvalidInputsCannotConsumeRunsOrInventAResult() = testApplication {
        val d = draft(); application { whiteHatApi(store, verifier) { false } }
        assertEquals(HttpStatusCode.Conflict, client.requestJson(HttpMethod.Post, path("/decisions/${d.id}/runs"), body = """{"expected_revision":1}""", key = "no_provider_001").status)
        assertEquals(0L, store.adminUsage("alice", workspace.id)["runs"])
        assertEquals(HttpStatusCode.BadRequest, client.requestJson(HttpMethod.Post, path("/decisions"), body = """{"title":"x","decision":"x","mode":"negotiation"}""").status)
        assertEquals(HttpStatusCode.BadRequest, client.requestJson(HttpMethod.Post, path("/decisions"), body = """{"title":"x","decision":"x","owner":"mallory"}""").status)
        assertEquals(HttpStatusCode.PayloadTooLarge, client.requestJson(HttpMethod.Post, path("/decisions"), body = "x".repeat(140001)).status)
    }

    @Test fun persistedStateAndAppendOnlyAuditSurviveRepositoryReconstruction() {
        val d = draft(); val r = store.enqueue("alice", workspace.id, d.id, 1, "persistent_001")
        val reopened = PostgresStore(source, policy.hash)
        assertEquals(d, reopened.decision("alice", workspace.id, d.id))
        assertEquals(r.id, reopened.run("alice", workspace.id, r.id).id)
        assertFails { source.connection.use { it.createStatement().executeUpdate("DELETE FROM audit") } }
        val compare = store.createDecision("alice", workspace.id, DecisionInput("مقایسه", "کدام؟", mode = Mode.COMPARE))
        assertEquals("COMPARE_OBJECTIVE_REQUIRED", assertFailsWith<Fault> { store.enqueue("alice", workspace.id, compare.id, 1, "compare_001") }.code)
    }

    @Test fun recoveryRunsEvenWithoutProviderConfiguration() = runBlocking {
        val d = draft(); val r = store.enqueue("alice", workspace.id, d.id, 1, "recover_no_provider_001")
        store.claim()
        source.connection.use { c -> c.createStatement().use { it.executeUpdate("UPDATE runs SET lease_until=now()-interval '1 second'") } }
        val absent = object : DecisionProvider {
            override val configured = false
            override suspend fun analyze(decision: Decision): ProviderResponse = error("Must not execute")
        }
        assertFalse(RunWorker(store, absent).tick())
        assertEquals("reconciliation_required", store.run("alice", workspace.id, r.id).status)
    }

    @Test fun revokedMemberCannotTriggerAPreviouslyQueuedProviderCall() = runBlocking {
        store.setMember("alice", workspace.id, "bob", Role.MEMBER, true)
        val d = store.createDecision("bob", workspace.id, DecisionInput("پایلوت", "آزمون اجرا شود؟"))
        store.enqueue("bob", workspace.id, d.id, 1, "revoked_member_001")
        store.setMember("alice", workspace.id, "bob", Role.MEMBER, false)
        val fixture = Fixture(); assertFalse(RunWorker(store, fixture).tick()); assertEquals(0, fixture.calls.get())
        source.connection.use { c -> c.createStatement().executeQuery("SELECT error_code FROM runs").use { it.next(); assertEquals("MEMBERSHIP_REVOKED", it.getString(1)) } }
    }

    @Test fun pilotReportIsScopedAndDistinguishesDriftFromUnknownCost() = testApplication {
        application { whiteHatApi(store, verifier) { true } }
        val suffix = "/admin/pilot-usage"
        store.setMember("alice", workspace.id, "admin", Role.ADMIN, true)
        store.setMember("alice", workspace.id, "member", Role.MEMBER, true)
        store.setMember("alice", workspace.id, "support", Role.SUPPORT, true)
        for (actor in listOf("member", "support")) {
            assertEquals(HttpStatusCode.Forbidden, client.requestJson(HttpMethod.Get, path(suffix), actor).status)
        }
        assertEquals(HttpStatusCode.NotFound, client.requestJson(HttpMethod.Get, path(suffix), "outsider").status)
        assertEquals(HttpStatusCode.Unauthorized, client.requestJson(HttpMethod.Get, path(suffix), null).status)

        val empty = client.requestJson(HttpMethod.Get, path(suffix), "admin").obj()
        assertEquals(JsonNull, empty["entitlement_revision"])
        assertEquals(JsonNull, empty["confirmed_usd_micros"])
        assertEquals(0L, empty.getValue("pilot_runs").jsonPrimitive.long)
        val legacy = store.enqueue("alice", workspace.id, draft().id, 1, "non_pilot_001")
        store.cancel("alice", workspace.id, legacy.id)
        store.recordConfirmedCost("alice", workspace.id, legacy.id, 999, "legacy-cost-receipt")

        publishPilotEntitlement(workspace.id, 1, 2)
        val run = store.enqueue("alice", workspace.id, draft().id, 1, "report_run_001")
        store.cancel("alice", workspace.id, run.id)
        val pending = client.requestJson(HttpMethod.Get, path(suffix)).obj()
        assertEquals(JsonNull, pending["confirmed_usd_micros"])
        assertEquals(1L, pending.getValue("unconfirmed_cost_runs").jsonPrimitive.long)
        store.recordConfirmedCost("alice", workspace.id, run.id, 0, "zero-cost-receipt")
        val confirmed = client.requestJson(HttpMethod.Get, path(suffix)).obj()
        assertEquals(JsonPrimitive("0"), confirmed["confirmed_usd_micros"])
        assertEquals(1L, confirmed.getValue("confirmed_cost_runs").jsonPrimitive.long)
        assertEquals(0L, confirmed.getValue("unconfirmed_cost_runs").jsonPrimitive.long)
        assertEquals(JsonPrimitive(true), confirmed["reconciled"])

        source.connection.use { connection ->
            connection.createStatement().executeUpdate("UPDATE workspace_pilot_usage SET attempts=2")
        }
        val drift = client.requestJson(HttpMethod.Get, path(suffix)).obj()
        assertEquals(JsonPrimitive(false), drift["reconciled"])
        assertEquals(2L, drift.getValue("metered_attempts").jsonPrimitive.long)
        assertEquals(1L, drift.getValue("pilot_runs").jsonPrimitive.long)
    }

    @org.junit.Test(timeout = 45000) fun localPilotBurstExercisesHttpMeterAndWorker() {
        val subjects = listOf("alice", "bob", "charlie", "dora")
        subjects.drop(1).forEach { store.setMember("alice", workspace.id, it, Role.MEMBER, true) }
        val admissions = subjects.flatMap { subject ->
            List(16) { store.createDecision(subject, workspace.id, DecisionInput("Local pilot", "Synthetic")) }.map {
                subject to it.id
            }
        }
        val cap = 24
        publishPilotEntitlement(workspace.id, 1, cap)
        val fixture = Fixture()
        val server = embeddedServer(Netty, host = "127.0.0.1", port = 0) { whiteHatApi(store, verifier) { true } }.start(wait = false)
        try {
            val port = runBlocking { server.engine.resolvedConnectors().single().port }
            val base = "http://127.0.0.1:$port"
            val tokens = subjects.associateWith(::token)
            JdkHttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build().use { http ->
                fun request(path: String, subject: String) = HttpRequest.newBuilder(URI.create(base + path))
                    .timeout(Duration.ofSeconds(20)).header("Authorization", "Bearer ${tokens.getValue(subject)}")
                val start = System.nanoTime()
                val futures = admissions.mapIndexed { index, (subject, decision) ->
                    val request = request(path("/decisions/$decision/runs"), subject)
                        .header("Idempotency-Key", "local_pilot_$index")
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString("""{"expected_revision":1}""")).build()
                    val sent = System.nanoTime()
                    http.sendAsync(request, JdkHttpResponse.BodyHandlers.ofString()).thenApply { response ->
                        response to (System.nanoTime() - sent)
                    }
                }
                CompletableFuture.allOf(*futures.toTypedArray()).get(25, TimeUnit.SECONDS)
                val totalMs = (System.nanoTime() - start) / 1_000_000
                val results = futures.map { it.join() }
                val accepted = results.filter { it.first.statusCode() == 202 }
                val rejected = results.filter { it.first.statusCode() == 429 }
                assertEquals(cap, accepted.size)
                assertEquals(admissions.size - cap, rejected.size)
                assertTrue(rejected.all {
                    Json.parseToJsonElement(it.first.body()).jsonObject["error"] == JsonPrimitive("PILOT_LIMIT_REACHED")
                })

                val worker = RunWorker(store, fixture)
                runBlocking {
                    repeat(cap) { assertTrue(worker.tick()) }
                    assertFalse(worker.tick())
                }
                assertEquals(cap, fixture.calls.get())
                val firstRun = Json.parseToJsonElement(accepted.first().first.body()).jsonObject
                store.recordConfirmedCost("alice", workspace.id, UUID.fromString(firstRun.getValue("id").jsonPrimitive.content),
                    1250, "synthetic-local-pilot")
                val response = http.send(request(path("/admin/pilot-usage"), "alice").GET().build(),
                    JdkHttpResponse.BodyHandlers.ofString())
                assertEquals(200, response.statusCode())
                val report = Json.parseToJsonElement(response.body()).jsonObject
                assertEquals(JsonPrimitive(cap), report["metered_attempts"])
                assertEquals(JsonPrimitive(cap), report["pilot_runs"])
                assertEquals(JsonPrimitive(true), report["reconciled"])
                assertEquals(JsonPrimitive("1250"), report["confirmed_usd_micros"])
                assertEquals(JsonPrimitive(cap - 1), report["unconfirmed_cost_runs"])
                java.io.File("build/contract-samples/pilot-usage.json").apply {
                    parentFile.mkdirs()
                    writeText(report.toString())
                }
                val latencyMs = results.map { it.second / 1_000_000 }.sorted()
                java.io.File("build/c6-evidence/local-pilot-http.json").apply {
                    parentFile.mkdirs()
                    writeText(buildJsonObject {
                        put("fixture_only", true)
                        put("requests", admissions.size)
                        put("subjects", subjects.size)
                        put("admitted", accepted.size)
                        put("quota_rejected", rejected.size)
                        put("fixture_worker_calls", fixture.calls.get())
                        put("burst_elapsed_ms", totalMs)
                        put("http_client_p95_ms", latencyMs[(latencyMs.size * 95 + 99) / 100 - 1])
                        put("http_client_max_ms", latencyMs.last())
                        put("pilot_usage", report)
                    }.toString())
                }
            }
        } finally {
            server.stop(0, 3000)
        }
    }

    @org.junit.Test(timeout = 20000) fun nettyServesAuthenticatedApiOverActualLoopbackHttp() {
        val server = embeddedServer(Netty, host = "127.0.0.1", port = 0) { whiteHatApi(store, verifier) { false } }.start(wait = false)
        try {
            val port = runBlocking { server.engine.resolvedConnectors().single().port }
            java.net.http.HttpClient.newBuilder().connectTimeout(java.time.Duration.ofSeconds(5)).build().use { http ->
                val request = java.net.http.HttpRequest.newBuilder(java.net.URI("http://127.0.0.1:$port/api/v1/me")).timeout(java.time.Duration.ofSeconds(5)).header("Authorization", "Bearer ${token()}").GET().build()
                val response = http.send(request, java.net.http.HttpResponse.BodyHandlers.ofString())
                assertEquals(200, response.statusCode())
                assertEquals("alice", Json.parseToJsonElement(response.body()).jsonObject.getValue("subject").jsonPrimitive.content)
            }
        } finally { server.stop(0, 3000) }
    }

    @org.junit.Test(timeout = 5000) fun lockContentionReturnsBoundedBusyAndRollsBackWithoutChangingTheDecision() {
        val decision = draft()
        source.connection.use { lock ->
            lock.autoCommit = false
            lock.prepareStatement("SELECT id FROM decisions WHERE id=? FOR UPDATE").use {
                it.setObject(1, decision.id); it.executeQuery().close()
            }
            val bounded = PostgresStore(source, policy.hash, statementTimeoutMillis = 1000, lockTimeoutMillis = 50)
            val busy = assertFailsWith<Fault> {
                bounded.editDecision("alice", workspace.id, decision.id, 1, decision.input.copy(title = "blocked"))
            }
            assertEquals(503, busy.status); assertEquals("DATABASE_BUSY", busy.code)
            lock.rollback()
        }
        assertEquals(1L, store.decision("alice", workspace.id, decision.id).revision)
        assertEquals(2L, store.editDecision("alice", workspace.id, decision.id, 1, decision.input.copy(title = "recovered")).revision)
    }

    @org.junit.Test(timeout = 5000) fun statementTimeoutRollsBackWritesAndReleasesTheConnection() {
        source.connection.use { c -> c.createStatement().use { s ->
            s.execute("""CREATE FUNCTION synthetic_slow_insert() RETURNS trigger AS
                $$ BEGIN PERFORM pg_sleep(0.2); RETURN NEW; END; $$ LANGUAGE plpgsql""")
            s.execute("CREATE TRIGGER synthetic_delay BEFORE INSERT ON decisions FOR EACH ROW EXECUTE FUNCTION synthetic_slow_insert()")
        } }
        val bounded = PostgresStore(source, policy.hash, statementTimeoutMillis = 50, lockTimeoutMillis = 20)
        val busy = assertFailsWith<Fault> { bounded.createDecision("alice", workspace.id, DecisionInput("delay", "synthetic")) }
        assertEquals(503, busy.status); assertEquals("DATABASE_BUSY", busy.code)
        assertTrue(store.decisions("alice", workspace.id).isEmpty())
        source.connection.use { c -> c.createStatement().use { it.execute("DROP TRIGGER synthetic_delay ON decisions") } }
        assertNotNull(bounded.createDecision("alice", workspace.id, DecisionInput("recovered", "synthetic")))
    }

    @Test fun readinessDistinguishesLivenessFromDatabaseFailureWithoutLeakingDetails() = testApplication {
        val unavailable = PostgresStore(object : javax.sql.DataSource by source {
            override fun getConnection(): java.sql.Connection = throw java.sql.SQLTransientConnectionException("synthetic-password-and-sql")
        }, policy.hash)
        application { whiteHatApi(unavailable, verifier) { true } }
        assertEquals(HttpStatusCode.OK, client.get("/api/v1/health").status)
        val response = client.get("/api/v1/ready")
        assertEquals(HttpStatusCode.ServiceUnavailable, response.status)
        val body = response.bodyAsText()
        assertTrue(body.contains("DATABASE_UNAVAILABLE")); assertFalse(body.contains("synthetic-password"))
    }

    @Test fun commercialPreviewIsScopedExactAndNeverChangesEntitlements() = testApplication {
        store.setMember("alice", workspace.id, "admin", Role.ADMIN, true)
        store.setMember("alice", workspace.id, "member", Role.MEMBER, true)
        store.setMember("alice", workspace.id, "support", Role.SUPPORT, true)
        application { whiteHatApi(store, verifier) { true } }
        assertEquals(HttpStatusCode.OK, client.get("/api/v1/ready").status)
        val url = path("/admin/plan-preview")
        assertEquals(HttpStatusCode.Unauthorized, client.requestJson(HttpMethod.Get, url, actor = null).status)
        for (actor in listOf("support", "member")) assertEquals(HttpStatusCode.Forbidden, client.requestJson(HttpMethod.Get, url, actor).status)
        assertEquals(HttpStatusCode.NotFound, client.requestJson(HttpMethod.Get, url, "outside").status)
        assertEquals(HttpStatusCode.OK, client.requestJson(HttpMethod.Get, url, "admin").status)
        val before = store.pilotUsage("alice", workspace.id)
        val catalog = client.requestJson(HttpMethod.Get, url).obj()
        assertEquals(false, catalog["billing_enabled"]!!.jsonPrimitive.boolean)
        assertTrue(catalog["items"]!!.jsonArray.all { it.jsonObject["revenue_floor_usd_micros"] == JsonNull })
        val estimate = client.requestJson(HttpMethod.Post, url, body = """{"assumed_cost_per_run_usd_micros":1,"fixed_monthly_cost_usd_micros":0,"target_margin_bps":7000}""")
        assertEquals(HttpStatusCode.OK, estimate.status)
        val estimated = estimate.obj()
        assertEquals("334", estimated["items"]!!.jsonArray.first().jsonObject["revenue_floor_usd_micros"]!!.jsonPrimitive.content)
        for ((name, sample) in listOf("plan-catalog" to catalog, "plan-estimate" to estimated)) {
            java.io.File("build/contract-samples/$name.json").apply { parentFile.mkdirs(); writeText(sample.toString()) }
        }
        val invalid = client.requestJson(HttpMethod.Post, url, body = """{"assumed_cost_per_run_usd_micros":-1,"fixed_monthly_cost_usd_micros":0,"target_margin_bps":7000}""")
        assertEquals(HttpStatusCode.BadRequest, invalid.status)
        assertEquals(before, store.pilotUsage("alice", workspace.id))
    }

    @org.junit.Test(timeout = 120000)
    fun stageCBrowserWithRealKtorAndPostgres() {
        assumeTrue("Enable WH_BROWSER_E2E with Node, Playwright and BFF dependencies", System.getenv("WH_BROWSER_E2E") == "true")
        val repo = Path.of(requireNotNull(System.getenv("WH_REVIEW_REPO")))
        val evidence = repo.resolve("server/api/build/browser-evidence")
        Files.createDirectories(evidence)
        store.setMember("alice", workspace.id, "support", Role.SUPPORT, true)
        store.setMember("alice", workspace.id, "member", Role.MEMBER, true)
        store.setMember("alice", workspace.id, "admin", Role.ADMIN, true)
        store.createWorkspace("outside", "Second tenant")
        val decision = draft()
        publishPilotEntitlement(workspace.id, 1, 1)
        val run = store.enqueue("alice", workspace.id, decision.id, 1, "browser-synthetic-receipt")
        store.cancel("alice", workspace.id, run.id)
        store.recordConfirmedCost("alice", workspace.id, run.id, 1250, "synthetic-receipt")
        val server = embeddedServer(Netty, host = "127.0.0.1", port = 0) {
            whiteHatApi(store, verifier) { true }
        }.start(wait = false)
        try {
            val port = runBlocking { server.engine.resolvedConnectors().single().port }
            val actors = listOf("alice", "admin", "support", "member", "outside")
            val log = evidence.resolve("joint-browser.log")
            val process = ProcessBuilder("node", repo.resolve("apps/web-bff/test/e2e/stage-c-browser.mjs").toString()).apply {
                environment().putAll(mapOf(
                    "WH_AUDIT_REPO" to repo.toString(), "WH_AUDIT_API" to "http://127.0.0.1:$port",
                    "WH_AUDIT_WORKSPACE" to workspace.id.toString(),
                    "WH_AUDIT_DB" to "postgresql://postgres@127.0.0.1:${pg.port}/${source.databaseName}",
                    "WH_AUDIT_TOKENS" to buildJsonObject { actors.forEach { put(it, token(it)) } }.toString()
                ))
            }.redirectErrorStream(true).redirectOutput(log.toFile()).start()
            if (!process.waitFor(100, TimeUnit.SECONDS)) {
                process.destroyForcibly()
                error("Browser E2E timed out; inspect browser-evidence/joint-browser.log")
            }
            assertEquals(0, process.exitValue(), Files.readString(log))
        } finally { server.stop(0, 3000) }
    }
}
