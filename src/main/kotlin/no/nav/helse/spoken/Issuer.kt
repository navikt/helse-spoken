package no.nav.helse.spoken

import com.github.navikt.tbd_libs.signedjwt.SignedJwt
import io.ktor.server.application.*
import io.ktor.util.*
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse

private fun Map<String, Any>.plusIfMissing(pair: Pair<String, Any>) = if (keys.contains(pair.first)) this else this.plus(pair)
private fun ApplicationCall.fraQuery(prefix: String) = request.queryParameters.toMap().filterKeys { it.startsWith(prefix) }.map { (key, value) -> key.removePrefix(prefix) to value.first() }.toMap()
private val ApplicationCall.headers get() = fraQuery("header_")
private val ApplicationCall.claims get() = fraQuery("claim_")
private val ApplicationCall.params get() = fraQuery("parameter_")


sealed class Issuer(jwk: Map<String, Any?>, protected val tokenEndpoint: URI) {
    private val signedJwt = SignedJwt(jwk)
    private val httpClient = HttpClient.newHttpClient()

    open fun defaultHeaders(headers: Map<String, Any>) = headers

    abstract fun defaultClaims(claims: Map<String, Any>): Map<String, Any>

    open fun defaultParameters(parameters: Map<String, Any>): Map<String, Any> = parameters

    fun assertion(call: ApplicationCall) = signedJwt.generate(
        headers = defaultHeaders(call.headers),
        claims = defaultClaims(call.claims)
    )

    fun token(call: ApplicationCall): String {
        val assertion = assertion(call)

        val body = defaultParameters(call.params)
            .plus("grant_type" to "urn:ietf:params:oauth:grant-type:jwt-bearer")
            .plus("assertion" to assertion)
            .entries.joinToString(separator = "&") { (key, value) -> "$key=$value"}

        val request = HttpRequest.newBuilder(tokenEndpoint)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build()

        return httpClient.send(request, HttpResponse.BodyHandlers.ofString()).body()
    }
}

internal class Maskinporten(jwk: Map<String, Any?>, private val clientId: String, tokenEndpoint: URI): Issuer(jwk, tokenEndpoint) {
    override fun defaultClaims(claims: Map<String, Any>) = claims
        .plusIfMissing("aud" to "https://test.maskinporten.no/")
        .plusIfMissing("iss" to clientId)
}

internal class Azure(jwk: Map<String, Any?>, private val clientId: String, tokenEndpoint: URI): Issuer(jwk, tokenEndpoint) {
    override fun defaultClaims(claims: Map<String, Any>) = claims
        .plusIfMissing("aud" to "$tokenEndpoint")
        .plusIfMissing("sub" to clientId)
        .plusIfMissing("iss" to clientId)

    override fun defaultParameters(parameters: Map<String, Any>) = parameters
        .plusIfMissing("client_id" to clientId)
}