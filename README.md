# R.SSO

## Example Shiny App with Entra ID Authentication

```R
library(shiny)
library(r.sso)

auth_config <- new_openid_config(
  provider = "google",
  client_id = Sys.getenv("CLIENT_ID"),
  client_secret = Sys.getenv("CLIENT_SECRET"),
  app_url = Sys.getenv("APP_URL")
)

ui <- fluidPage(
  tags$h1("r.sso example"),
  tags$a(
    tags$button(
      "Logout",
      class = "btn btn-primary"
    ),
    href = "/logout"
  ),
  textOutput("user")
)

server <- function(input, output, session) {

  output$user <- renderText({
    given_name <- get_token_field(token(), "given_name")
    family_name <- get_token_field(token(), "family_name")
    expires_at <- expires_at(token())
    glue::glue(
      "Hello {given_name} {family_name}! Your authenticated session will expire at {expires_at}."
    )
  })

}

sso_shiny_app(auth_config, ui, server)
```

## Example Shiny App with Google Authentication

```R
library(shiny)
library(r.sso)

auth_config <- new_openid_config(
  provider = "google",
  client_id = Sys.getenv("CLIENT_ID"),
  client_secret = Sys.getenv("CLIENT_SECRET"),
  app_url = Sys.getenv("APP_URL")
)

ui <- fluidPage(
  tags$h1("r.sso example"),
  tags$a(
    tags$button(
      "Logout",
      class = "btn btn-primary"
    ),
    href = "/logout"
  ),
  textOutput("user")
)

server <- function(input, output, session) {

  output$user <- renderText({
    given_name <- get_token_field(token(), "given_name")
    family_name <- get_token_field(token(), "family_name")
    expires_at <- expires_at(token())
    glue::glue(
      "Hello {given_name} {family_name}! Your authenticated session will expire at {expires_at}."
    )
  })

}

sso_shiny_app(auth_config, ui, server)
```

