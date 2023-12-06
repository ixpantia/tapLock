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

shiny_app <- function(config, app) {
  app_handler <- app$httpHandler
  login_handler <- function(req) {

    # If the user sends a POST request to /login, we'll get a code
    # and exchange it for an access token. We'll then redirect the
    # user to the root path, setting a cookie with the access token.
    if (req$REQUEST_METHOD == "POST" && req$PATH_INFO == "/login") {
      form <- shiny::parseQueryString(req[["rook.input"]]$read_lines())
      token <- promises::future_promise({
        request_token(config, form[["code"]])
      })
      return(
        promises::then(
          token,
          onFulfilled = function(token) {
            shiny::httpResponse(
              status = 302,
              headers = list(
                Location = "/",
                "Set-Cookie" = build_cookie("access_token", get_bearer(token))
              )
            )
          },
          onRejected = function(e) {
            shiny::httpResponse(
              status = 302,
              headers = list(
                Location = "/",
                "Set-Cookie" = build_cookie("access_token", "")
              )
            )
          }
        )
      )
    }

    # Get eh HTTP cookies from the request
    cookies <- parse_cookies(req$HTTP_COOKIE)

    # If the user requests the root path, we'll check if they have
    # an access token. If they don't, we'll redirect them to the
    # login page.
    if (req$PATH_INFO == "/") {
      token <- tryCatch(
        expr = access_token(config, remove_bearer(cookies$access_token)),
        error = function(e) {
          return(NULL)
        }
      )
      if (is.null(token)) {
        return(
          shiny::httpResponse(
            status = 302,
            headers = list(
              Location = get_login_url(config)
            )
          )
        )
      }
    }

    # If the user requests any other path, we'll check if they have
    # an access token. If they don't, we'll return a 403 Forbidden
    # response.
    token <- tryCatch(
      expr = access_token(config, remove_bearer(cookies$access_token)),
      error = function(e) {
        return(NULL)
      }
    )

    if (is.null(token)) {
      return(
        shiny::httpResponse(
          status = 403,
          content_type = "text/plain",
          content = "Forbidden"
        )
      )
    }

    # If we have reached this point, the user has a valid access
    # token and therefore we can return NULL, which will cause the
    # app handler to be called.
    return(NULL)
  }

  handlers <- list(
    login_handler,
    app_handler
  )

  app$httpHandler <- function(req) {
    for (handler in handlers) {
      response <- handler(req)
      if (!is.null(response)) {
        return(response)
      }
    }
  }

  return(app)
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
