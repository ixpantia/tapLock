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
    given_name <- r.sso::token()$get_given_name()
    family_name <- r.sso::token()$get_family_name()
    expires_at <- r.sso::token()$expires_at()
    glue::glue(
      "Hello {given_name} {family_name}! Your authenticated session will expire at {expires_at}."
    )
  })
}

config$shiny_app(ui, server)
