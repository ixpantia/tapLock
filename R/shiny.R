internal_add_auth_layers <- function(config, tower) {
  tower |>
    tower::add_get_route("/login", function(req) {
      query <- shiny::parseQueryString(req$QUERY_STRING)
      token <- request_token(config, query[["code"]])
      return(
        promises::then(
          token,
          onFulfilled = function(token) {
            shiny::httpResponse(
              status = 302,
              headers = list(
                Location = config$get_app_url(),
                "Set-Cookie" = build_cookie("access_token", add_bearer(token$access_token)),
                "Set-Cookie" = build_cookie("refresh_token", token$refresh_token)
              )
            )
          },
          onRejected = function(e) {
            shiny::httpResponse(
              status = 302,
              headers = list(
                Location = config$get_app_url(),
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
            Location = config$get_app_url(),
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
      req$TOKEN <- access_token(config, cookies$access_token)

      if (is_error(req$TOKEN) && shiny::isTruthy(cookies$refresh_token)) {
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
                  "Set-Cookie" = build_cookie("access_token", add_bearer(token$access_token)),
                  "Set-Cookie" = build_cookie("refresh_token", token$refresh_token)
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
      if (is_error(req$TOKEN)) {
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

      token_decode_result <- access_token(config, cookies$access_token)

      if (methods::is(token_decode_result, "error")) rlang::abort(token_decode_result$value)

      session$userData$token <- token_decode_result
    })

}

#' @title Add authentication middle ware to a 'tower' object
#' @description Attaches the necessary authentication layers
#'   to a 'tower' object. This will secure any layer added
#'   after.
#' @param tower A 'tower' object from the package 'tower'
#' @param config An 'openid_config' object
#' @return A modified 'tower' object with authentication layers
#' @export
add_auth_layers <- function(tower, config) {
  internal_add_auth_layers(config, tower)
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
  session$userData$token$fields
}
