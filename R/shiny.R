rsso_server <- function(config, server_func) {
  function(input, output, session) {
    cookies <- parse_cookies(session$request$HTTP_COOKIE)

    if (is.null(cookies$access_token)) {
      stop("No access token")
    }

    token <- access_token(config, remove_bearer(cookies$access_token))

    if (is_expired(token)) {
      stop("Token expired")
    }

    session$userData$token <- token

    server_func(input, output, session)
  }
}

#' @export
shiny_app <- function(config, app) {
  UseMethod("shiny_app")
}

#' @export
token <- function(session = shiny::getDefaultReactiveDomain()) {
  session$userData$token
}

#' @export
sso_shiny_app <- function(config, ui, server) {
  app <- shiny::shinyApp(ui = ui, server = rsso_server(config, server))
  shiny_app(config, app)
}
