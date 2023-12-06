# R.SSO


## Example Shiny App

```R
library(shiny)
library(r.sso)

auth_config <- new_openid_config(
  provider = "entra_id",
  tenant_id = Sys.getenv("TENANT_ID"),
  client_id = Sys.getenv("CLIENT_ID"),
  client_secret = Sys.getenv("CLIENT_SECRET"),
  redirect_uri = Sys.getenv("REDIRECT_URI")
)

ui <- fluidPage(
  tags$h1("r.sso example"),
  textOutput("user")
)

server <- function(input, output, session) {
  output$user <- renderText({
    given_name <- get_given_name(token())
    family_name <- get_family_name(token())
    expires_at <- expires_at(token())
    print(token())
    glue::glue(
      "Hello {given_name} {family_name}! Your authenticated session will expire at {expires_at}."
    )
  })
}

sso_shiny_app(auth_config, ui, server)
```
