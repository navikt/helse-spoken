package no.nav.helse.spoken

import com.auth0.jwk.JwkProviderBuilder
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import com.github.navikt.tbd_libs.signedjwt.SignedJwt
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.cio.*
import io.ktor.server.engine.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.util.*
import java.net.URI

private val String.env get() = checkNotNull(System.getenv(this)) { "Fant ikke environment variable $this" }
private val String.jwk get(): Map<String, Any?> = objectMapper.readValue(this.env)
private val objectMapper = jacksonObjectMapper()
private fun Map<String, String>.plusIfMissing(pair: Pair<String, String>) = if (keys.contains(pair.first)) this else this.plus(pair)

fun main() {
    embeddedServer(CIO, port = 8080, module = Application::spoken).start(wait = true)
}

internal fun Application.spoken() {
    authentication {
        jwt {
            val jwkProvider = JwkProviderBuilder(URI("AZURE_OPENID_CONFIG_JWKS_URI".env).toURL()).build()
            verifier(jwkProvider, "AZURE_OPENID_CONFIG_ISSUER".env) {
                withAudience("AZURE_APP_CLIENT_ID".env)
            }
            validate { credentials -> JWTPrincipal(credentials.payload) }
        }
    }

    val maskinporten = SignedJwt("MASKINPORTEN_CLIENT_JWK".jwk)

    routing {
        get("/isalive") { call.respondText("ALIVE!") }
        get("/isready") { call.respondText("READY!") }
        authenticate {
            get("/velkommen") {
                call.respondText("Heihei!")
            }
            get("/assertion") {
                val issuer = call.request.queryParameters["issuer"] ?: return@get call.respondText("Mangler issuer query.")
                if (issuer != "maskinporten") return@get call.respondText { "Støtter bare maskinporten." }
                val claims = call.claims
                    .plusIfMissing("aud" to "https://test.maskinporten.no/")
                    .plusIfMissing("iss" to "MASKINPORTEN_CLIENT_ID".env)
                val jwt = maskinporten.generate(call.headers, claims)
                call.respondText(jwt)
            }
        }
    }
}


internal val ApplicationCall.headers get() = request.queryParameters.toMap().filterKeys { it.startsWith("header") }.map { (key, value) ->
    key.removePrefix("header") to value.first()
}.toMap()
internal val ApplicationCall.claims get() = request.queryParameters.toMap().filterKeys { it.startsWith("claim") }.map { (key, value) ->
    key.removePrefix("claim") to value.first()
}.toMap()