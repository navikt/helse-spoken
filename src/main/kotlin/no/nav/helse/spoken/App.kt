package no.nav.helse.spoken

import com.auth0.jwk.JwkProviderBuilder
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.cio.*
import io.ktor.server.engine.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import java.net.URI

internal val String.env get() = checkNotNull(System.getenv(this)) { "Fant ikke environment variable $this" }

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

    routing {
        get("/isalive") { call.respondText("ALIVE!") }
        get("/isready") { call.respondText("READY!") }
        authenticate {
            get("/velkommen") {
                call.respondText("Heihei!")
            }
        }
    }
}

