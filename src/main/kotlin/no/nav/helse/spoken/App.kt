package no.nav.helse.spoken

import com.auth0.jwk.JwkProviderBuilder
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import io.ktor.http.ContentType.Application.Json
import io.ktor.http.HttpStatusCode.Companion.BadRequest
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.cio.*
import io.ktor.server.engine.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import java.net.URI

private val String.env get() = checkNotNull(System.getenv(this)) { "Fant ikke environment variable $this" }
private val String.jwk get(): Map<String, Any?> = objectMapper.readValue(this.env)
private val objectMapper = jacksonObjectMapper()

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

    val issuers = mapOf(
        "maskinporten" to Maskinporten(
            jwk = "MASKINPORTEN_CLIENT_JWK".jwk,
            clientId = "MASKINPORTEN_CLIENT_ID".env,
            tokenEndpoint = URI("MASKINPORTEN_TOKEN_ENDPOINT".env),
            issuer = "MASKINPORTEN_ISSUER".env,
            tilgjengeligeScopes = "MASKINPORTEN_SCOPES".env
        ),
        "azure" to Azure(
            jwk = "AZURE_APP_JWK".jwk,
            clientId = "AZURE_APP_CLIENT_ID".env,
            tokenEndpoint = URI("AZURE_OPENID_CONFIG_TOKEN_ENDPOINT".env)
        )
    )

    routing {
        get("/isalive") { call.respondText("ALIVE!") }
        get("/isready") { call.respondText("READY!") }
        authenticate {
            get("/token") {
                val issuerQuery = call.request.queryParameters["issuer"] ?: return@get call.respondText("Mangler issuer query.", status = BadRequest)
                val issuer = issuers[issuerQuery] ?: return@get call.respondText("Støtter ikke issuer $issuerQuery. Støtter kun ${issuers.keys.joinToString()}", status = BadRequest)
                call.respondText(issuer.token(call), contentType = Json)
            }
        }
    }
}


