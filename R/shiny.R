#' @keywords internal
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

#' @keywords internal
shiny_app <- function(config, app) {
  UseMethod("shiny_app")
}

#' @title Get the access token
#'
#' @description Gets the access token from the session to be used
#'   for internal logic.
#'
#' @param session A Shiny session
#'
#' @return An access_token object
#' @export
token <- function(session = shiny::getDefaultReactiveDomain()) {
  session$userData$token
}

#' @title Create a Shiny app with SSO
#'
#' @description Creates a Shiny app with SSO (single sign-on)
#'   based on the given configuration.
#'
#' @param config An openid_config object
#' @param ui A Shiny UI function
#' @param server A Shiny server function. This function requires
#'   all three arguments:  `input`, `output`, and `session`.
#'
#' @seealso [tapLock::new_openid_config()]
#' @return A Shiny app (Compatible with [`shinyApp()`][shiny::shinyApp])
#' @export
sso_shiny_app <- function(config, ui, server) {
  app <- shiny::shinyApp(ui = ui, server = rsso_server(config, server))
  shiny_app(config, app)
}
