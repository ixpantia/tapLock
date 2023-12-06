build_google_login_url <- function(auth_url, client_id, redirect_uri) {
  url <- httr2::url_parse(auth_url)
  url$query <- list(
    client_id = client_id,
    redirect_uri = redirect_uri,
    response_type = "code",
    prompt = "select_account",
    scope = "openid email profile"
  )
  httr2::url_build(url)
}

new_google_config <- function(client_id, client_secret, app_url) {
  auth_url <- "https://accounts.google.com/o/oauth2/v2/auth"
  token_url <- "https://oauth2.googleapis.com/token"
  jwks_url <- "https://www.googleapis.com/oauth2/v2/certs"
  redirect_uri <- build_redirect_uri(app_url)
  login_url <- build_google_login_url(auth_url, client_id, redirect_uri)
  structure(
    list(
      client_id = client_id,
      client_secret = client_secret,
      redirect_uri = redirect_uri,
      auth_url = auth_url,
      token_url = token_url,
      jwks_url = jwks_url,
      login_url = login_url,
      jwks = fetch_jwks(jwks_url)
    ),
    class = c("google_config", "openid_config")
  )
}

#' @export
get_login_url.google_config <- function(config) {
  config$login_url
}

#' @export
get_logout_url.google_config <- function(config) {
  stop("Logout not implemented for Entra ID")
}

#' @export
request_token.google_config <- function(config, authorization_code) {
  res <- httr2::request(config$token_url) |>
    httr2::req_method("POST") |>
    httr2::req_body_form(
      code = authorization_code,
      client_id = config$client_id,
      client_secret = config$client_secret,
      grant_type = "authorization_code",
      redirect_uri = config$redirect_uri
    ) |>
    httr2::req_perform()
  resp_status <- httr2::resp_status(res)
  if (resp_status != 200) {
    stop(httr2::resp_body_string(res))
  }
  resp_body <- httr2::resp_body_json(res)
  access_token(config, resp_body$id_token)
}

#' @export
decode_token.google_config <- function(config, token) {
  decoded <- config$jwks |>
    purrr::map(function(jwk) {
      tryCatch(
        jose::jwt_decode_sig(token, jwk),
        error = function(e) {
          NULL
        }
      )
    }) |>
    purrr::discard(is.null) |>
    purrr::pluck(1, .default = NULL)
  if (is.null(decoded)) {
    stop("Unable to decode token")
  }
  return(decoded)
}

#' @export
get_client_id.google_config <- function(config) {
  config$client_id
}

#' @export
shiny_app.google_config <- function(config, app) {
  app_handler <- app$httpHandler
  login_handler <- function(req) {

    # If the user sends a POST request to /login, we'll get a code
    # and exchange it for an access token. We'll then redirect the
    # user to the root path, setting a cookie with the access token.
    if (req$PATH_INFO == "/login") {
      query <- shiny::parseQueryString(req$QUERY_STRING)
      token <- promises::future_promise({
        request_token(config, query[["code"]])
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

    if (req$PATH_INFO == "/logout") {
      return(
        shiny::httpResponse(
          status = 302,
          headers = list(
            Location = "/",
            "Set-Cookie" = build_cookie("access_token", "")
          )
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
