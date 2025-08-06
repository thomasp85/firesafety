# cross_origin_embedder_policy field validates input

    Code
      sec_headers$cross_origin_embedder_policy <- "invalid-value"
    Condition
      Error:
      ! `value` must be one of "unsafe-none", "require-corp", or "credentialless", not "invalid-value".

# cross_origin_opener_policy field validates input

    Code
      sec_headers$cross_origin_opener_policy <- "invalid-value"
    Condition
      Error:
      ! `value` must be one of "unsafe-none", "same-origin-allow-popups", "same-origin", or "noopener-allow-popups", not "invalid-value".

# cross_origin_resource_policy field validates input

    Code
      sec_headers$cross_origin_resource_policy <- "invalid-value"
    Condition
      Error:
      ! `value` must be one of "same-site", "same-origin", or "cross-origin", not "invalid-value".

# strict_transport_security field validates input

    Code
      sec_headers$strict_transport_security <- invalid_sts_preload
    Condition
      Error:
      ! `preload` can only be set if `include_sub_domains == TRUE` and `max_age >= 31536000`

---

    Code
      sec_headers$strict_transport_security <- invalid_sts_preload2
    Condition
      Error:
      ! `preload` can only be set if `include_sub_domains == TRUE` and `max_age >= 31536000`

---

    Code
      sec_headers$strict_transport_security <- list(invalid = "value")
    Condition
      Error:
      ! `value` must be a list with elements `max_age`, `include_sub_domains`, and `preload` or `NULL`, not a list.

# boolean fields validate input correctly

    Code
      sec_headers$origin_agent_cluster <- "not-a-boolean"
    Condition
      Error:
      ! `value` must be `TRUE`, `FALSE`, or `NULL`, not the string "not-a-boolean".

