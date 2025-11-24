# Create a new keycloak_config object

Creates a new keycloak_config object

## Usage

``` r
new_keycloak_config(
  base_url,
  realm,
  client_id,
  client_secret,
  app_url,
  use_refresh_token = TRUE
)
```

## Arguments

- base_url:

  The base URL for the Keycloak instance

- realm:

  The realm for the app

- client_id:

  The client ID for the app

- client_secret:

  The client secret for the app

- app_url:

  The URL for the app

- use_refresh_token:

  Enable the use of refresh tokens

## Value

A keycloak_config object
