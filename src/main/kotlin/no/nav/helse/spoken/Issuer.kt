package no.nav.helse.spoken

import com.fasterxml.jackson.databind.node.ObjectNode
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.github.navikt.tbd_libs.signedjwt.SignedJwt
import io.ktor.server.application.*
import io.ktor.util.*
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.util.*

private fun Map<String, Any>.plusIfMissing(pair: Pair<String, Any>) = if (keys.contains(pair.first)) this else this.plus(pair)
private fun ApplicationCall.fraQuery(prefix: String) = request.queryParameters.toMap().filterKeys { it.startsWith(prefix) }.map { (key, value) -> key.removePrefix(prefix) to value.first() }.toMap()
private val ApplicationCall.headers get() = fraQuery("header_")
private val ApplicationCall.claims get() = fraQuery("claim_")
private val ApplicationCall.params get() = fraQuery("parameter_")


sealed class Issuer(jwk: Map<String, Any?>, protected val tokenEndpoint: URI) {
    private val signedJwt = SignedJwt(jwk)
    private val httpClient = HttpClient.newHttpClient()

    open fun headers(customHeaders: Map<String, Any>) = customHeaders

    abstract fun claims(customClaims: Map<String, Any>): Map<String, Any>

    abstract fun parameters(customParameters: Map<String, Any>, assertion: String): Map<String, Any>

    open fun response(objectNode: ObjectNode) = objectNode

    fun token(call: ApplicationCall): String {
        val assertion = signedJwt.generate(headers = headers(call.headers), claims = claims(call.claims))

        val body = parameters(call.params, assertion).entries.joinToString(separator = "&") { (key, value) -> "$key=$value"}

        val request = HttpRequest.newBuilder(tokenEndpoint)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build()

        val tokenResponse = json(httpClient.send(request, HttpResponse.BodyHandlers.ofString()).body())
        val accessToken = tokenResponse.path("access_token").asText()

        val response =  objectMapper.createObjectNode().apply {
            replace("assertion", jwtInfo(assertion))
            replace("access_token", jwtInfo(accessToken))
            put("token_request", body)
            put("token_endpoint", "$tokenEndpoint")
            replace("token_response", tokenResponse)
        }
        return response(response).toString()
    }

    private companion object {
        private val objectMapper = jacksonObjectMapper()
        private val base64Decoder = Base64.getUrlDecoder()
        private fun jwtInfo(jwt: String) = objectMapper.createObjectNode().apply {
            put("raw", jwt)
            replace("headers", partOrNull(jwt, 0) )
            replace("claims", partOrNull(jwt, 1))
        }
        private fun json(raw: String) = kotlin.runCatching { objectMapper.readTree(raw) }.fold(
            onSuccess = { it },
            onFailure = { objectMapper.nullNode() }
        )

        private fun partOrNull(jwt: String, part: Int) = kotlin.runCatching { objectMapper.readTree(base64Decoder.decode(jwt.split(".")[part])) }.fold(
            onSuccess = { it },
            onFailure = { objectMapper.nullNode() }
        )
    }
}

internal class Maskinporten(jwk: Map<String, Any?>, private val clientId: String, tokenEndpoint: URI): Issuer(jwk, tokenEndpoint) {
    override fun claims(customClaims: Map<String, Any>) = customClaims
        .plusIfMissing("aud" to "MASKINPORTEN_ISSUER".env)
        .plusIfMissing("iss" to clientId)

    override fun parameters(customParameters: Map<String, Any>, assertion: String) = customParameters
        .plusIfMissing("grant_type" to "urn:ietf:params:oauth:grant-type:jwt-bearer")
        .plusIfMissing("assertion" to assertion)

    override fun response(objectNode: ObjectNode): ObjectNode = objectNode
        .put("available_scopes", "MASKINPORTEN_SCOPES".env)
}

internal class Azure(jwk: Map<String, Any?>, private val clientId: String, tokenEndpoint: URI): Issuer(jwk, tokenEndpoint) {
    override fun claims(customClaims: Map<String, Any>) = customClaims
        .plusIfMissing("aud" to "$tokenEndpoint")
        .plusIfMissing("sub" to clientId)
        .plusIfMissing("iss" to clientId)

    override fun parameters(customParameters: Map<String, Any>, assertion: String) = customParameters
        .plusIfMissing("client_id" to clientId)
        .plusIfMissing("grant_type" to "client_credentials")
        .plusIfMissing("client_assertion" to assertion)
        .plusIfMissing("client_assertion_type" to "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
}