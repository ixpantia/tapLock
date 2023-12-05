rsso_server <- function(config, server_func) {
  function(input, output, session) {
    cookies <- parse_cookies(session$request$HTTP_COOKIE)

    if (is.null(cookies$access_token)) {
      stop("No access token")
    }

    token <- access_token$new(remove_bearer(cookies$access_token), config)

    if (token$is_expired()) {
      stop("Token expired")
    }

    session$userData$token <- token

    server_func(input, output, session)
  }
}

rsso_shiny_app <- function(config, app) {
  app_handler <- app$httpHandler

  login_handler <- function(req) {
    if (req$REQUEST_METHOD == "POST" && req$PATH_INFO == "/login") {
      form <- shiny::parseQueryString(req[["rook.input"]]$read_lines())
      token <- promises::future_promise({
        config$request_token(form[["code"]])
      })
      return(
        promises::then(
          token,
          onFulfilled = function(token) {
            shiny::httpResponse(
              status = 302,
              headers = list(
                Location = "/",
                "Set-Cookie" = build_cookie("access_token", token$get_bearer())
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

    cookies <- parse_cookies(req$HTTP_COOKIE)

    if (req$PATH_INFO == "/") {
      token <- tryCatch(
        expr = access_token$new(remove_bearer(cookies$access_token), config),
        error = function(e) {
          return(NULL)
        }
      )
      if (is.null(token)) {
        return(
          shiny::httpResponse(
            status = 302,
            headers = list(
              Location = config$get_login_url()
            )
          )
        )
      }
    }

    token <- tryCatch(
      expr = access_token$new(remove_bearer(cookies$access_token), config),
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
