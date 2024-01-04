# tapLock <a><img src="https://storage.googleapis.com/ix-paquetes-internos/logo-tapLock.png" align="right" width="30%"></a>

Secure your R applications with OpenID Connect and OAuth 2.0.

## Summary

tapLock is an R library that provides a simple interface to
integrate OpenID Connect / OAuth 2.0 authentication into you Shiny
applications and Plumber APIs. tapLock uses a unique approach to
effectively secure your applications without the need to write almost
any code.

## Authentication providers

tapLock supports the following authentication providers:

- [Google](https://developers.google.com/identity/protocols/oauth2/openid-connect)
- [Microsoft Entra ID](https://www.microsoft.com/en-us/security/business/identity-access/microsoft-entra-id)

> If you need support for other providers, please contact us at
> [hola@ixpantia.com](mailto:hola@ixpantia.com). Or, if you are a
> developer, you can contribute to the project by adding support for
> additional providers.

## Security Model

tapLock is unique in its approach to securing Shiny applications and
Plumber APIs. tapLock utilizes middlewares that intercept all incoming
requests (both HTTP and WebSocket requests) and validates the
authentication token. This approach allows tapLock to be lean and
efficient since no expensive WebSocket connections are started until
the user is authenticated. It also prevents sensitive data in the UI
portion of the application from being exposed to unauthenticated users.

## How to use tapLock with Shiny

#### 1. Install tapLock

``` r
pak::pak("ixpantia/taplock")
```

#### 2. Create an authentication configuration

``` r
library(taplock)

auth_config <- new_openid_config(
  provider = "entra_id",
  # The following values are obtained from the authentication provider
  tenant_id = Sys.getenv("TENANT_ID"),
  client_id = Sys.getenv("CLIENT_ID"),
  client_secret = Sys.getenv("CLIENT_SECRET"),
  # This should be the URL of your application
  app_url = Sys.getenv("APP_URL")
)
```

#### 3. Secure your Shiny application

To secure your Shiny Application you will simply need to expose
an `sso_shiny_app` instead of a regular `shinyApp` at the end of your
`app.R` file.

Here is an example of a Shiny application that uses tapLock to secure
itself:

``` r
library(shiny)
library(tapLock)

auth_config <- new_openid_config(
  provider = "entra_id",
  tenant_id = Sys.getenv("TENANT_ID"),
  client_id = Sys.getenv("CLIENT_ID"),
  client_secret = Sys.getenv("CLIENT_SECRET"),
  app_url = Sys.getenv("APP_URL")
)

ui <- fluidPage(
  tags$h1("r.sso example"),
  textOutput("user")
)

server <- function(input, output, session) {

  output$user <- renderText({
    given_name <- get_token_field(token(), "given_name")
    family_name <- get_token_field(token(), "family_name")
    expires_at <- expires_at(token())
    glue::glue(
      "Hello {given_name} {family_name}!",
      "Your authenticated session will expire at {expires_at}.",
      .sep = " "
    )
  })

}

sso_shiny_app(auth_config, ui, server)
```
