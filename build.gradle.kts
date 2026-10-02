plugins {
    alias(libs.plugins.sykepenger.deployable)
}

sykepengerDeployable {
    mainClass = "no.nav.helse.spoken.AppKt"
}

dependencies {
    implementation(libs.logback.classic)
    implementation(libs.logstash.logback.encoder)

    implementation(libs.bundles.ktor.server)
    implementation(libs.ktor.server.auth.jwt) {
        exclude(group = "junit")
    }
    implementation(libs.jackson.module.kotlin)
    implementation(libs.tbdLibs.signedJwt)
}
