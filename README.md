# R.SSO


## Example Shiny App

```R
library(shiny)

config <- r.sso::entra_id_config$new(
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
    paste0("Hello, ", r.sso::token()$get_given_name())
  })
}

config$shiny_app(ui, server)
```
