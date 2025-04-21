library(shiny)
#library(tapLock)
devtools::load_all("../..")

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
    tags$img(src = token()$picture)
  })

  output$user <- renderText({
    given_name <- token()$given_name
    family_name <- token()$family_name
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
