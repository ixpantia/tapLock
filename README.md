# tapLock <a><img src="https://storage.googleapis.com/ix-paquetes-internos/logo-tapLock.png" align="right" width="30%"></a>

<!-- badges: start -->
[![R-CMD-check](https://github.com/maurolepore/tapLock/actions/workflows/R-CMD-check.yaml/badge.svg)](https://github.com/ixpantia/tapLock/actions/workflows/R-CMD-check.yaml)
<!-- badges: end -->

The goal of tapLock is to secure your R applications with OpenID Connect and
OAuth 2.0.

tapLock is an R library that provides a simple interface to integrate OpenID
Connect / OAuth 2.0 authentication into you Shiny applications and Plumber APIs.
tapLock uses a unique approach to effectively secure your applications without
the need to write almost any code.

## Installation

You can install tapLock from CRAN with:

``` r
install.packages("tapLock")
```

You can install the development version of tapLock from [GitHub](https://github.com/) with:

``` r
# install.packages("pak")
pak::pak("ixpantia/tapLock")
```

## Example

### 1. Create an authentication configuration

``` r
library(taplock)

auth_config <- new_openid_config(
  provider = "google",
  client_id = Sys.getenv("CLIENT_ID"),
  client_secret = Sys.getenv("CLIENT_SECRET"),
  app_url = Sys.getenv("APP_URL")
)
```

### 2. Secure your Shiny application

To secure your Shiny Application you will need to add the middleware layers
using [tower](https://github.com/ixpantia/tower) and configure the
client credentials.

Here is an example of a Shiny application that uses tapLock to secure
itself:

``` r
library(shiny)
library(tapLock)

auth_config <- new_openid_config(
  provider = "google",
  client_id = Sys.getenv("CLIENT_ID"),
  client_secret = Sys.getenv("CLIENT_SECRET"),
  app_url = Sys.getenv("APP_URL")
)

ui <- fluidPage(
  tags$h1("r.sso example"),
  uiOutput("profile"),
  textOutput("user")
)

server <- function(input, output, session) {


  output$profile <- renderUI({
    tags$img(src = get_token_field(token(), "picture"))
  })

  output$user <- renderText({
    given_name <- get_token_field(token(), "given_name")
    family_name <- get_token_field(token(), "family_name")
    expires_at <- expires_at(token())
    glue::glue(
      "Hello {given_name} {family_name}!",
      "Your authenticated session will expire at {expires_at}.",
      .sep = " "
    )
  }) |>
    bindEvent(TRUE)

}
shinyApp(ui, server) |>
  tower::create_tower() |>
  tapLock::add_auth_layers(auth_config) |>
  tower::build_tower()
```

## Authentication providers

tapLock supports the following authentication providers:

- [Google](https://developers.google.com/identity/protocols/oauth2/openid-connect)
- [Microsoft Entra ID](https://www.microsoft.com/en-us/security/business/identity-access/microsoft-entra-id)

> If you need support for other providers, please contact us at
> [hola@ixpantia.com](mailto:hola@ixpantia.com). Or, if you are a
> developer, you can contribute to the project by adding support for
> additional providers.

## Security Model

tapLock is unique in its approach to securing Shiny applications. tapLock
utilizes middlewares that intercept all incoming requests (both HTTP and
WebSocket requests) and validates the authentication token. This approach
allows tapLock to be lean and efficient since no expensive WebSocket
connections are started until the user is authenticated. It also prevents
sensitive data in the UI portion of the application from being exposed to
unauthenticated users.

