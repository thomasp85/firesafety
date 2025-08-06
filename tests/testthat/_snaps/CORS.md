# CORS initialization validates parameters

    Code
      CORS$new(origin = "*", allow_credentials = TRUE)
    Condition
      Error in `self$add_path()`:
      ! Credentials cannot be allowed if origin is "*"

---

    Code
      CORS$new(methods = c("get", "invalid"))
    Condition
      Error in `self$add_path()`:
      ! `methods` must be one of "get", "head", "post", "put", "delete", "connect", "options", "trace", "patch", or "all", not "invalid".

