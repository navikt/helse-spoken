# Spoken

Henter access tokens for deg!
Den bruker Spokens JWK'er for å signere en assertion som sendes til issuer for å få et access token.

Du må være logget inn på NAV-kontoen din, og være medlem av TBD-teamet for å bruke tjenesten.

Inntil videre er Spoken kun i test.

## Input

Her setter bare fantasien begrensninger.

`claim_<$x>` -> `x` legges til som en claim i assertionen som sendes til issuer.

`header_<$y>` -> `y` legges til som en header i assertione som sendes til issuer.

`parameter_<$z>` -> `z` legges til som parameter på token-request til issuer.

## Issuers

### Maskinporten
Alle headers/claims/parameters defaulter til det som trengs, men man må sende med scopet som skal etterspørres. Også `resource` om det er et audience restricted (https://docs.digdir.no/docs/Maskinporten/maskinporten_func_audience_restricted_tokens)

Applikasjonen som har definert scopet må legge til NAV (889640782) som consumer + at scopet må legges inn i "Spoken" sin nais yml som scope den konsumerer.

Eksempel:

https://spoken.intern.dev.nav.no/token?issuer=maskinporten&claim_scope=nav:sykepenger:avtalefestetpensjon.read&claim_resource=https://spapi.ekstern.dev.nav.no

### Azure
Alle headers/claims/parametes defaulter til det som trengs for `client_credentials`, men man må sende med scopet som skal etterspørres.

Applikasjonen som eier scopet må legge til Spoken i sin acl for at det skal fungere.

Eksempel:

https://spoken.intern.dev.nav.no/token?issuer=azure&parameter_scope=api://dev-gcp.tbd.spekemat/.default

## Henvendelser
Spørsmål knyttet til koden eller prosjektet kan stilles som issues her på GitHub.

### For NAV-ansatte
Interne henvendelser kan sendes via Slack i kanalen ![#team-bømlo-værsågod](https://nav-it.slack.com/archives/C019637N90X).
