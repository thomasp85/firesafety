#' Plugin for setting up CORS in a fiery server
#'
#' @description
#' Cross-Origin Resource Sharing (CORS) is a mechanism for servers to indicate
#' from where it may be accessed and allows browsers to block requests that are
#' not permitted. For security reasons, browsers limits requests initiated from
#' JavaScript to only those for the same site. To allow requests from other
#' sites the server needs to send the right CORS headers with the response. Read
#' more about CORS at [MDN](https://developer.mozilla.org/docs/Web/HTTP/Guides/CORS)
#'
#' @details
#' CORS is opt-in. The security measure is already in place in browsers to limit
#' cross-origin requests, and CORS is a way to break out of this in a controlled
#' manner where you can indicate exactly who can make a request and what
#' requests can be made. In general it works like this:
#'
#' 1) A request is being initiated from a website, either through JavaScript or
#'    another venue, to a site different than the one it originates from.
#' 2) The browser identifies that the request is cross-origin and sends an
#'    `OPTIONS` request to the server with information about the request it
#'    intends to send (this is called a pre-flight request).
#' 3) The server responds with a 204 response giving the allowed types of
#'    requests that can be made for the resource.
#' 4) If the original request conforms to the response the browser will then
#'    send the actual request.
#' 5) The server responds to the actual request.
#' 6) The client gets the response, but the browser will limit what information
#'    in the response it can access based on the information provided by the
#'    server in the pre-flight response.
#'
#' As can be seen, a CORS request is slightly more complex than the standard
#' request-response you normally think about. However, the pre-flight request
#' can be cached by the browser and so, will not happen every time a ressource
#' is accessed. While a site may employ a CORS policy the same way across all
#' its endpoints it does not need to. It is fine to only turn on CORS for a
#' subset of paths. In general it is a good rule of thumb to set up
#' [resource isolation][ResourceIsolation] for the paths that do not have CORS
#' enabled.
#'
#' @usage NULL
#' @format NULL
#'
#' @section Initialization:
#' A new 'CORS'-object is initialized using the \code{new()} method on the
#' generator and pass in any settings deviating from the defaults
#'
#' \strong{Usage}
#' \tabular{l}{
#'  \code{cors <- CORS$new(...)}
#' }
#'
#' @section Fiery plugin:
#' A CORS object is a fiery plugin and can be used by passing it
#' to the `attach()` method of the fiery server object. Once attached all
#' requests will be passed through the plugin and the policy applied to it
#'
#' @export
#'
#' @examples
#' # Setup CORS for a sub path allowing access from www.trustworthy.com
#' # Tell the browser to cache the preflight for a day
#' cors <- CORS$new(
#'   path = "/shared_assets/*",
#'   origin = "https://www.trustworthy.com",
#'   methods = c("get", "head", "post"),
#'   max_age = 86400
#' )
#'
#' @examplesIf requireNamespace("fiery", quietly = TRUE)
#' # Use it in a fiery server
#' app <- fiery::Fire$new()
#'
#' app$attach(cors)
#'
CORS <- R6::R6Class(
  "CORS",
  public = list(
    #' @description Initialize a CORS object
    #' @param path The path that the policy should apply to. routr path syntax
    #' applies, meaning that wilcards and path parameters are allowed.
    #' @param origin The origin allowed for the path. Can be one of:
    #' * A boolean. If `TRUE` then all origins are permitted and the preflight
    #'   response will have the `Access-Control-Allow-Origin` header reflect
    #'   the origin of the request. If `FALSE` then all origins are denied
    #' * The string `"*"` which will allow all origins and set
    #'   `Access-Control-Allow-Origin` to `*`. This is different than setting it
    #'   to `TRUE` because `*` instructs browsers that any origin is allowed and
    #'   it may use this information when searching the cache
    #' * A character vector giving allowed origins. If the request origin
    #'   matches any of these then the `Access-Control-Allow-Origin` header in
    #'   the response will reflect the origin of the request
    #' * A function taking the request and returning `TRUE` if the origin is
    #'   permitted and `FALSE` if it is not. If permitted the
    #'   `Access-Control-Allow-Origin` header will reflect the request origin
    #' @param methods The HTTP methods allowed for the `path`
    #' @param allowed_headers A character vector of request headers allowed when
    #' making the request. If the request contains headers not permitted, then
    #' the response will be blocked by the browser. `NULL` will allow any header
    #' by reflecting the `Access-Control-Request-Headers` header value from the
    #' request into the `Access-Control-Allow-Headers` header in the response.
    #' @param exposed_headers A character vector of response headers that should
    #' be made available to the client upon a succesful request
    #' @param allow_credentials A boolean indicating whether credentials are
    #' allowed in the request. Credentials are cookies or HTTP authentication
    #' headers, which are normally stripped from `fetch()` requests by the
    #' browser. If this is `TRUE` then `origin` cannot be `*` according to the
    #' spec
    #' @param max_age The duration browsers are allowed to keep the preflight
    #' response in the cache
    #'
    initialize = function(
      path = "/*",
      origin = "*",
      methods = c("get", "head", "put", "patch", "post", "delete"),
      allowed_headers = NULL,
      exposed_headers = NULL,
      allow_credentials = FALSE,
      max_age = NULL
    ) {
      private$OPTIONS_ROUTE <- routr::Route$new()
      private$MAIN_ROUTE <- routr::Route$new()
      self$add_path(
        path = path,
        origin = origin,
        methods = methods,
        allowed_headers = allowed_headers,
        exposed_headers = exposed_headers,
        allow_credentials = allow_credentials,
        max_age = max_age
      )
    },
    #' @description Add CORS settings to a path
    #' @param path The path that the policy should apply to. routr path syntax
    #' applies, meaning that wilcards and path parameters are allowed.
    #' @param origin The origin allowed for the path. Can be one of:
    #' * A boolean. If `TRUE` then all origins are permitted and the preflight
    #'   response will have the `Access-Control-Allow-Origin` header reflect
    #'   the origin of the request. If `FALSE` then all origins are denied
    #' * The string `"*"` which will allow all origins and set
    #'   `Access-Control-Allow-Origin` to `*`. This is different than setting it
    #'   to `TRUE` because `*` instructs browsers that any origin is allowed and
    #'   it may use this information when searching the cache
    #' * A character vector giving allowed origins. If the request origin
    #'   matches any of these then the `Access-Control-Allow-Origin` header in
    #'   the response will reflect the origin of the request
    #' * A function taking the request and returning `TRUE` if the origin is
    #'   permitted and `FALSE` if it is not. If permitted the
    #'   `Access-Control-Allow-Origin` header will reflect the request origin
    #' @param methods The HTTP methods allowed for the `path`
    #' @param allowed_headers A character vector of request headers allowed when
    #' making the request. If the request contains headers not permitted, then
    #' the response will be blocked by the browser. `NULL` will allow any header
    #' by reflecting the `Access-Control-Request-Headers` header value from the
    #' request into the `Access-Control-Allow-Headers` header in the response.
    #' @param exposed_headers A character vector of response headers that should
    #' be made available to the client upon a succesful request
    #' @param allow_credentials A boolean indicating whether credentials are
    #' allowed in the request. Credentials are cookies or HTTP authentication
    #' headers, which are normally stripped from `fetch()` requests by the
    #' browser. If this is `TRUE` then `origin` cannot be `*` according to the
    #' spec
    #' @param max_age The duration browsers are allowed to keep the preflight
    #' response in the cache
    #'
    add_path = function(
      path = "/*",
      origin = "*",
      methods = c("get", "head", "put", "patch", "post", "delete"),
      allowed_headers = NULL,
      exposed_headers = NULL,
      allow_credentials = FALSE,
      max_age = NULL
    ) {
      check_string(path)
      origin_fun <- private$make_origin_fun(origin)
      methods <- tolower(methods)
      methods <- arg_match(
        methods,
        c(http_methods, "all"),
        multiple = TRUE
      )
      if ("all" %in% methods) {
        methods <- http_methods
      }
      method_string <- paste0(methods, collapse = ",")
      check_character(allowed_headers, allow_na = FALSE, allow_null = TRUE)
      if (!is.null(allowed_headers)) {
        allowed_headers <- paste0(allowed_headers, collapse = ",")
      }
      check_character(exposed_headers, allow_na = FALSE, allow_null = TRUE)
      if (!is.null(exposed_headers)) {
        exposed_headers <- paste0(exposed_headers, collapse = ",")
      }
      check_bool(allow_credentials)
      if (allow_credentials && isTRUE(origin == "*")) {
        cli::cli_abort("Credentials cannot be allowed if origin is {.val *}")
      }
      check_number_whole(max_age, allow_infinite = FALSE, allow_null = TRUE)

      private$OPTIONS_ROUTE$add_handler(
        "options",
        path,
        function(request, response, ...) {
          vary <- NULL
          origin <- origin_fun(request)
          response$set_header("access-control-allow-origin", origin)
          if (origin != "*") {
            vary <- c(vary, "origin")
          }
          if (allow_credentials) {
            response$set_header("access-control-allow-credentials", "true")
          }
          response$set_header("access-control-allow-methods", method_string)
          if (is.null(allowed_headers)) {
            vary <- c(vary, "access-control-request-headers")
            allowed_headers <- request$get_header(
              "access-control-request-headers"
            )
          }
          response$set_header("access-control-allow-headers", allowed_headers)
          if (!is.null(exposed_headers)) {
            response$set_header(
              "access-control-expose-headers",
              exposed_headers
            )
          }
          if (!is.null(max_age)) {
            response$set_header("access-control-max-age", max_age)
          }
          if (!is.null(vary)) {
            response$append_header("vary", vary)
          }
          response$status <- 204L
          response$body <- ""
          FALSE
        }
      )

      private$MAIN_ROUTE$add_handler(
        "all",
        path,
        function(request, response, ...) {
          origin <- origin_fun(request)
          response$set_header("access-control-allow-origin", origin)
          if (origin != "*") {
            response$append_header("vary", "origin")
          }
          if (allow_credentials) {
            response$set_header("access-control-allow-credentials", "true")
          }
          if (!is.null(exposed_headers)) {
            response$set_header(
              "access-control-expose-headers",
              exposed_headers
            )
          }
          # Shortcircuit if origin+method isn't allowed
          origin != "false" && request$method %in% methods
        }
      )
    },
    #' @description Method for use by `fiery` when attached as a plugin. Should
    #' not be called directly.
    #' @param app The fiery server object
    #' @param ... Ignored
    #'
    on_attach = function(app, ...) {
      if (is.null(app$plugins$header_routr)) {
        rs <- routr::RouteStack$new()
        rs$attach_to <- "header"
        app$attach(rs)
      }
      app$plugins$header_routr$add_route(
        private$OPTIONS_ROUTE,
        "cors_options",
        after = 0
      )
      if (is.null(app$plugins$request_routr)) {
        rs <- routr::RouteStack$new()
        rs$attach_to <- "request"
        app$attach(rs)
      }
      app$plugins$request_routr$add_route(
        private$MAIN_ROUTE,
        "cors_main",
        after = 0
      )
    }
  ),
  active = list(
    #' @field name The name of the plugin
    name = function() {
      "cors"
    }
  ),
  private = list(
    OPTIONS_ROUTE = NULL,
    MAIN_ROUTE = NULL,

    make_origin_fun = function(origin, call = caller_env()) {
      if (isFALSE(origin)) {
        function(request) {
          "false"
        }
      } else if (identical(origin, "*")) {
        function(request) {
          "*"
        }
      } else if (isTRUE(origin)) {
        function(request) {
          request$get_header("origin")
        }
      } else if (is_bare_character(origin)) {
        origin <- tolower(origin)
        function(request) {
          req_orig <- request$get_header("origin")
          if (tolower(req_orig) %in% origin) {
            req_orig
          } else {
            "false"
          }
        }
      } else if (is_function(origin)) {
        function(request) {
          if (isTRUE(origin(request))) {
            request$get_header("origin")
          } else {
            "false"
          }
        }
      } else {
        stop_input_type(
          origin,
          "a boolean, a character vector or a function",
          call = call
        )
      }
    }
  )
)
