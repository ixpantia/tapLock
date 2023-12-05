#' @export
entra_id_config <- R6::R6Class(
  classname = "entra_id_config",
  public = list(
    initialize = function(tenant_id, client_id, client_secret, redirect_uri) {
      base_url <- "https://login.microsoftonline.com"
      private$redirect_uri <- redirect_uri
      private$auth_url <- glue::glue("{base_url}/{tenant_id}/oauth2/v2.0/authorize")
      private$token_url <- glue::glue("{base_url}/{tenant_id}/oauth2/v2.0/token")
      private$jwks_url <- glue::glue("{base_url}/{tenant_id}/discovery/v2.0/keys")
      private$client_id <- client_id
      private$client_secret <- client_secret
      self$refresh_jwks()
    },
    shiny_server = function(server_func) {
      function(input, output, session) {
        cookies <- parse_cookies(session$request$HTTP_COOKIE)

        if (is.null(cookies$access_token)) {
          stop("No access token")
        }

        token <- access_token$new(remove_bearer(cookies$access_token), self)

        if (token$is_expired()) {
          stop("Token expired")
        }

        session$userData$token <- token

        server_func(input, output, session)
      }
    },
    shiny_app = function(ui, server) {
      app <- shinyApp(ui, rsso_server(self, server))
      return(rsso_shiny_app(self, app))
    },
    get_login_url = function() {
      url <- httr2::url_parse(private$auth_url)
      url$query <- list(
        client_id = private$client_id,
        redirect_uri = private$redirect_uri,
        response_mode = "form_post",
        response_type = "code",
        prompt = "login",
        scope = glue::glue("{private$client_id}/.default")
      )
      httr2::url_build(url)
    },
    get_logout_url = function() {
      stop("Not implemented")
    },
    request_token = function(authorization_code) {
      res <- httr2::request(private$token_url) |>
        httr2::req_method("POST") |>
        httr2::req_body_form(
          code = authorization_code,
          client_id = private$client_id,
          client_secret = private$client_secret,
          grant_type = "authorization_code",
          redirect_uri = private$redirect_uri
        ) |>
        httr2::req_perform()
      resp_status <- httr2::resp_status(res)
      if (resp_status != 200) {
        stop(httr2::resp_body_string(res))
      }
      resp_body <- httr2::resp_body_json(res)
      access_token$new(
        token = resp_body$access_token,
        refresh_token = resp_body$refresh_token,
        config = self
      )
    },
    refresh_jwks = function() {
      private$jwks <- httr2::request(private$jwks_url) |>
        httr2::req_method("GET") |>
        httr2::req_perform() |>
        httr2::resp_body_json() |>
        purrr::pluck("keys") |>
        purrr::map(jose::jwk_read)
    },
    decode_token = function(token) {
      decoded <- private$jwks |>
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
    },
    get_client_id = function() {
      private$client_id
    }
  ),
  private = list(
    redirect_uri = NULL,
    auth_url = NULL,
    jwks_url = NULL,
    token_url = NULL,
    client_id = NULL,
    client_secret = NULL,
    jwks = NULL
  )
)
