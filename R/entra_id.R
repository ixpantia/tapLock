ENTRA_ID_BASE_URL <- "https://login.microsoftonline.com"

#' @keywords internal
build_entra_id_login_url <- function(auth_url, client_id, redirect_uri) {
  url <- httr2::url_parse(auth_url)
  url$query <- list(
    client_id = client_id,
    redirect_uri = redirect_uri,
    response_mode = "form_post",
    response_type = "code",
    prompt = "login",
    scope = glue::glue("{client_id}/.default")
  )
  httr2::url_build(url)
}

#' @title Create a new entra_id_config object
#' @description Creates a new entra_id_config object
#'
#' @param tenant_id The tenant ID for the app
#' @param client_id The client ID for the app
#' @param client_secret The client secret for the app
#' @param app_url The URL for the app
#'
#' @return An entra_id_config object
#' @export
new_entra_id_config <- function(tenant_id, client_id, client_secret, app_url) {
  app_url <- add_trailing_slash(app_url)
  auth_url <- glue::glue("{ENTRA_ID_BASE_URL}/{tenant_id}/oauth2/v2.0/authorize")
  token_url <- glue::glue("{ENTRA_ID_BASE_URL}/{tenant_id}/oauth2/v2.0/token")
  jwks_url <- glue::glue("{ENTRA_ID_BASE_URL}/{tenant_id}/discovery/v2.0/keys")
  redirect_uri <- build_redirect_uri(app_url)
  login_url <- build_entra_id_login_url(auth_url, client_id, redirect_uri)
  structure(
    list(
      app_url = app_url,
      tenant_id = tenant_id,
      client_id = client_id,
      client_secret = client_secret,
      redirect_uri = redirect_uri,
      auth_url = auth_url,
      token_url = token_url,
      jwks_url = jwks_url,
      login_url = login_url,
      jwks = fetch_jwks(jwks_url)
    ),
    class = c("entra_id_config", "openid_config")
  )
}

#' @keywords internal
get_login_url.entra_id_config <- function(config) {
  config$login_url
}

#' @keywords internal
get_logout_url.entra_id_config <- function(config) {
  stop("Logout not implemented for Entra ID")
}

#' @keywords internal
request_token.entra_id_config <- function(config, authorization_code) {
  res <- httr2::request(config$token_url) |>
    httr2::req_method("POST") |>
    httr2::req_body_form(
      code = authorization_code,
      client_id = config$client_id,
      client_secret = config$client_secret,
      grant_type = "authorization_code",
      redirect_uri = config$redirect_uri,
      scope = "profile openid email offline_access"
    ) |>
    httr2::req_perform_promise()


  promises::then(
    res,
    onFulfilled = function(res) {
      resp_status <- httr2::resp_status(res)
      if (resp_status != 200) {
        stop(httr2::resp_body_string(res))
      }
      resp_body <- httr2::resp_body_json(res)
      list(
        at = access_token(config, resp_body$access_token),
        rt = resp_body$refresh_token
      )
    }
  )

}

#' @keywords internal
request_token_refresh.entra_id_config <- function(config, refresh_token) {
  res <- httr2::request(config$token_url) |>
    httr2::req_method("POST") |>
    httr2::req_body_form(
      refresh_token = refresh_token,
      client_id = config$client_id,
      client_secret = config$client_secret,
      grant_type = "refresh_token",
      scope = "profile openid email offline_access"
    ) |>
    httr2::req_perform_promise()

  promises::then(
    res,
    onFulfilled = function(res) {
      resp_status <- httr2::resp_status(res)
      if (resp_status != 200) {
        stop(httr2::resp_body_string(res))
      }
      resp_body <- httr2::resp_body_json(res)
      list(
        at = access_token(config, resp_body$access_token),
        rt = resp_body$refresh_token
      )
    }
  )
}

#' @keywords internal
decode_token.entra_id_config <- function(config, token) {
  decoded <- config$jwks |>
    purrr::map(function(jwk) {
      tryCatch(
        jose::jwt_decode_sig(token, jwk),
        error = function(e) {
          NULL
        },
        warning = function(w) {
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

#' @keywords internal
get_client_id.entra_id_config <- function(config) {
  config$client_id
}

#' @export
internal_add_auth_layers.entra_id_config <- function(config, tower) {
  tower |>
    tower::add_post_route("/login", function(req) {
      form <- shiny::parseQueryString(req[["rook.input"]]$read_lines())
      token <- request_token(config, form[["code"]])
      return(
        promises::then(
          token,
          onFulfilled = function(token) {
            shiny::httpResponse(
              status = 302,
              headers = list(
                Location = config$app_url,
                "Set-Cookie" = build_cookie("access_token", get_bearer(token$at)),
                "Set-Cookie" = build_cookie("refresh_token", token$rt)
              )
            )
          },
          onRejected = function(e) {
            shiny::httpResponse(
              status = 302,
              headers = list(
                Location = get_login_url(config),
                "Set-Cookie" = build_cookie("access_token", ""),
                "Set-Cookie" = build_cookie("refresh_token", "")
              )
            )
          }
        )
      )
    }) |>
    tower::add_get_route("/logout", function(req) {
      return(
        shiny::httpResponse(
          status = 302,
          headers = list(
            Location = config$app_url,
            "Set-Cookie" = build_cookie("access_token", ""),
            "Set-Cookie" = build_cookie("refresh_token", "")
          )
        )
      )
    }) |>
    tower::add_http_layer(function(req) {
      # Get the HTTP cookies from the request
      cookies <- parse_cookies(req$HTTP_COOKIE)
      req$PARSED_COOKIES <- cookies

      # If the user requests the root path, we'll check if they have
      # an access token. If they don't, we'll redirect them to the
      # login page.
      req$TOKEN <- tryCatch(
        expr = access_token(config, remove_bearer(cookies$access_token)),
        error = function(e) {
          return(NULL)
        }
      )
      if (is.null(req$TOKEN) && shiny::isTruthy(cookies$refresh_token)) {
        # Ask for a new token using the refresh_token
        token <- request_token_refresh(config, cookies$refresh_token)
        return(
          promises::then(
            token,
            onFulfilled = function(token) {
              response <- req$NEXT(req)
              response$headers <- append(
                response$headers,
                list(
                  "Set-Cookie" = build_cookie("access_token", get_bearer(token$at)),
                  "Set-Cookie" = build_cookie("refresh_token", token$rt)
                )
              )
              return(response)
            },
            onRejected = function(e) {
              shiny::httpResponse(
                status = 302,
                headers = list(
                  Location = get_login_url(config),
                  "Set-Cookie" = build_cookie("access_token", ""),
                  "Set-Cookie" = build_cookie("refresh_token", "")
                )
              )
            }
          )
        )
      }
      if (is.null(req$TOKEN)) {
        if (req$PATH_INFO == "/") {
          return(
            shiny::httpResponse(
              status = 302,
              headers = list(
                Location = get_login_url(config)
              )
            )
          )
        } else {
          return(
            shiny::httpResponse(
              status = 403,
              content_type = "text/plain",
              content = "Forbidden"
            )
          )
        }
      }
      req$NEXT(req)
    }) |>
    tower::add_server_layer(function(input, output, session) {
      cookies <- parse_cookies(session$request$HTTP_COOKIE)

      if (is.null(cookies$access_token)) {
        stop("No access token")
      }

      token <- access_token(config, remove_bearer(cookies$access_token))

      if (is_expired(token)) {
        stop("Token expired")
      }

      session$userData$token <- token
    })
}
