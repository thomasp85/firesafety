# ResourceIsolation validates allowed_site parameter

    Code
      ResourceIsolation$new(allowed_site = "invalid")
    Condition
      Error in `self$add_path()`:
      ! `allowed_site` must be one of "cross-site", "same-site", or "same-origin", not "invalid".

# ResourceIsolation validates forbidden_navigation parameter

    Code
      ResourceIsolation$new(forbidden_navigation = "invalid")
    Condition
      Error in `self$add_path()`:
      ! `forbidden_navigation` must be one of "audio", "audioworklet", "document", "embed", "empty", "fencedframe", "font", "frame", "iframe", "image", "manifest", "object", "paintworklet", "report", "script", "serviceworker", "sharedworker", "style", "track", "video", "webidentity", "worker", or "xslt", not "invalid".

# add_path validates parameters

    Code
      ri$add_path(path = "/api/*", allowed_site = "invalid")
    Condition
      Error in `ri$add_path()`:
      ! `allowed_site` must be one of "cross-site", "same-site", or "same-origin", not "invalid".

---

    Code
      ri$add_path(path = "/api/*", allowed_site = "same-site", forbidden_navigation = "invalid")
    Condition
      Error in `ri$add_path()`:
      ! `forbidden_navigation` must be one of "audio", "audioworklet", "document", "embed", "empty", "fencedframe", "font", "frame", "iframe", "image", "manifest", "object", "paintworklet", "report", "script", "serviceworker", "sharedworker", "style", "track", "video", "webidentity", "worker", or "xslt", not "invalid".

