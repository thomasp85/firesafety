#' Fetch metadata based resource isolation plugin
#'
#' @description
#' This plugin uses the information provided in the `Sec-Fetch-*` request
#' headers to block unwanted requests to your server coming from other sites.
#' Setting up a strict control with which requests are allowed is an important
#' part of preventing some cross-site leaks as well as cross-site request
#' forgery attacks.
#'
#' @details
#' Compared to the other security measures in firesafety, the reource isolation
#' plugin is a server-side blocker of requests. Both CORS and CORP sends back a
#' full response and it is then up to the browser to determine if the response
#' becomes available to the site. In contrast, this plugin will return a 403
#' response if the request fails to be accepted. This is not to say that
#' resource isolation is *better* than CORS, CORP or other measures. They all
#' target different situations (or the same situation from different angles) and
#' works best in unison. You can read more about this type of defence at
#' [MDN](https://developer.mozilla.org/docs/Web/Security/Attacks/XS-Leaks#fetch_metadata)
#' and [XS-Leaks Wiki](https://xsleaks.dev/docs/defenses/isolation-policies/resource-isolation/)
#'
#' ## How it works
#' Resource isolation takes advantage of the `Sec-Fetch-*` headers that browser
#' send along with requests. These headers informs the server about the nature
#' of the request. Where it comes from, what action initiated it, and how it
#' will be used. Based on this information the server may chose to allow a
#' request to proceed or deny it altogether. This plugin runs a request through
#' a range of tests and if it passes *any* of them it proceeds:
#'
#' 1) Does the request have the `Sec-Fetch-*` headers
#' 2) Is `allow_cors == TRUE` and is `Sec-Fetch-Mode` set to `cors`
#' 3) Is `Sec-Fetch-Site` set to `allowed_site` or a more restrictive value
#' 4) Is the request method `GET`, the `Sec-Fetch-Mode` `navigation`, and the
#'    `Sec-Fetch-Dest` not one of those given by `forbidden_navigation`
#'
#' You can have different permissions for different paths. The default during
#' initialization is to add it to `/*` so that all all paths will share the same
#' policy, but you can strengthen or loosen up specific paths as needed. A good
#' rule of thumb is to make the policy as restrictive as possible while allowing
#' your application to still work as intented. Further, if you have paths that
#' do not have a resource isolation policy in place these should have CORS
#' enabled.
#'
#' @usage NULL
#' @format NULL
#'
#' @section Initialization:
#' A new 'ResourceIsolation'-object is initialized using the \code{new()} method on the
#' generator and pass in any settings deviating from the defaults
#'
#' \strong{Usage}
#' \tabular{l}{
#'  \code{resource_isolation <- ResourceIsolation$new(...)}
#' }
#'
#' @section Fiery plugin:
#' A ResourceIsolation object is a fiery plugin and can be used by passing it
#' to the `attach()` method of the fiery server object. Once attached all
#' requests will be passed through the plugin and the policy applied to it
#'
#' @export
#'
#' @examplesIf requireNamespace("fiery", quietly = TRUE)
#' # Create resource isolation policy denying all navigation requests
#' resource_isolation <- ResourceIsolation$new(forbidden_navigation = "all")
#'
#' # Allow cross-site requests on a subpath
#' resource_isolation$add_path(
#'   path = "/all_is_welcome/*",
#'   allowed_site = "cross-site"
#' )
#'
#' # Use it in a fiery server
#' app <- fiery::Fire$new()
#'
#' app$attach(resource_isolation)
#'
ResourceIsolation <- R6::R6Class(
  "ResourceIsolation",
  public = list(
    #' @description Initialize a new ResourceIsolation object
    #' @param path The path that the policy should apply to. routr path syntax
    #' applies, meaning that wilcards and path parameters are allowed.
    #' @param allowed_site The allowance level to permit. Either `cross-site`,
    #' `same-site`, or `same-origin`.
    #' @param forbidden_navigation A vector of destinations not allowed for
    #' navigational requests. See the [`Sec-Fetch-Dest` documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Sec-Fetch-Dest)
    #' for a description of possible values. The special value `"all"` is also
    #' permitted which is the equivalent of passing all values.
    #' @param allow_cors Should `Sec-Fetch-Mode: cors` requests be allowed
    #'
    initialize = function(
      path = "/*",
      allowed_site = "same-site",
      forbidden_navigation = c("object", "embed"),
      allow_cors = TRUE
    ) {
      private$ROUTE <- routr::Route$new()
      self$add_path(path, allowed_site, forbidden_navigation, allow_cors)
    },
    #' @description Add a policy to a path
    #'@param path The path that the policy should apply to. routr path syntax
    #' applies, meaning that wilcards and path parameters are allowed.
    #' @param allowed_site The allowance level to permit. Either `cross-site`,
    #' `same-site`, or `same-origin`.
    #' @param forbidden_navigation A vector of destinations not allowed for
    #' navigational requests. See the [`Sec-Fetch-Dest` documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Sec-Fetch-Dest)
    #' for a description of possible values. The special value `"all"` is also
    #' permitted which is the equivalent of passing all values.
    #' @param allow_cors Should `Sec-Fetch-Mode: cors` requests be allowed
    #'
    add_path = function(
      path,
      allowed_site,
      forbidden_navigation = c("object", "embed"),
      allow_cors = TRUE
    ) {
      allowed_site <- tolower(allowed_site)
      allowed_site <- arg_match0(
        allowed_site,
        site_values
      )
      allowed_site <- match(allowed_site, site_values)
      allowed_site <- c(site_values[-seq_len(allowed_site - 1)], "none")

      forbidden_navigation <- tolower(forbidden_navigation %||% character())
      if (isTRUE(forbidden_navigation == "all")) {
        forbidden_navigation <- dest_values
      }
      forbidden_navigation <- arg_match(
        forbidden_navigation,
        dest_values,
        multiple = TRUE,
        error_arg = "forbidden_navigation"
      )

      check_bool(allow_cors)

      private$ROUTE$add_handler("all", path, function(request, response, ...) {
        if (
          !allow_request(
            request,
            allowed_site,
            forbidden_navigation,
            allow_cors
          )
        ) {
          response$status_with_text(403L)
          FALSE
        } else {
          TRUE
        }
      })
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
      app$plugins$header_routr$add_route(private$ROUTE, "resource_isolation", after = 0)
    }
  ),
  active = list(
    #' @field name The name of the plugin
    name = function() {
      "resource_isolation"
    }
  ),
  private = list(
    ROUTE = NULL
  )
)

allow_request <- function(request, site, dest, cors) {
  if (!request$has_header("sec-fetch-site")) {
    return(TRUE)
  }
  if (cors && request$get_header("sec-fetch-mode") == "cors") {
    return(TRUE)
  }
  if (tolower(request$get_header("sec-fetch-site")) %in% site) {
    return(TRUE)
  }
  if (
    request$method == "get" &&
      tolower(request$get_header("sec-fetch-mode")) %in%
        c("navigate", "nested-navigate") &&
      !tolower(request$get_header("sec-fetch-dest")) %in% dest
  ) {
    return(TRUE)
  }
  FALSE
}

dest_values <- c(
  "audio",
  "audioworklet",
  "document",
  "embed",
  "empty",
  "fencedframe",
  "font",
  "frame",
  "iframe",
  "image",
  "manifest",
  "object",
  "paintworklet",
  "report",
  "script",
  "serviceworker",
  "sharedworker",
  "style",
  "track",
  "video",
  "webidentity",
  "worker",
  "xslt"
)
site_values <- c("cross-site", "same-site", "same_origin")
