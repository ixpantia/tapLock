# Add authentication middle ware to a 'tower' object

Attaches the necessary authentication layers to a 'tower' object. This
will secure any layer added after.

## Usage

``` r
add_auth_layers(tower, config)
```

## Arguments

- tower:

  A 'tower' object from the package 'tower'

- config:

  An 'openid_config' object

## Value

A modified 'tower' object with authentication layers
