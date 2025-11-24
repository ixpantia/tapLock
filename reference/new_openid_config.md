# New openid configuration

Creates a new openid configuration object for the given provider. You
can use this function or the individual provider functions.

## Usage

``` r
new_openid_config(provider, app_url, ...)
```

## Arguments

- provider:

  The openid provider to use

- app_url:

  The URL of the application (used to build redirect, login, and logout
  URLs)

- ...:

  Additional arguments passed to the provider's configuration. This
  depends on the provider.

  The `"google"` provider accepts the following arguments:

  - `client_id`

  - `client_secret`

  The `"entra_id"` provider accepts the following arguments:

  - `client_id`

  - `client_secret`

  - `tenant_id`

## Value

An openid_config object
