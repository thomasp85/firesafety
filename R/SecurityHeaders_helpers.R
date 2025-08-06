#' Construct settings for the `Strict-Transport-Security` header
#'
#' This helper function exists mainly to document the possible values and
#' prevent misspelled directives. It returns a bare list. See
#' [MDN](https://developer.mozilla.org/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security)
#' for more information on the header
#'
#' @param max_age The maximum age the settings should be kept in the browser
#' cache, in seconds. Recommended value is 63072000 (2 years)
#' @param include_sub_domains Logical. Should subdomains be included in the
#' policy
#' @param preload Allow the settings to be cached and preloaded by a third-party,
#' e.g. Google or Mozilla. Can only be set if `include_sub_domains` is `TRUE`
#' and `max_age` is at least 31536000 (1 year)
#'
#' @return A bare list with the input arguments
#'
#' @export
#'
#' @examples
#' # Default settings
#' sts(
#'   max_age = 63072000,
#'   include_sub_domains = TRUE
#' )
#'
sts <- function(max_age, include_sub_domains = NULL, preload = NULL) {
  list(
    max_age = max_age,
    include_sub_domains = include_sub_domains,
    preload = preload
  )
}

#' Construct settings for the `Content-Security-Policy` header
#'
#' This helper function exists mainly to document the possible values and
#' prevent misspelled directives. It returns a bare list. See
#' [the header reference](https://developer.mozilla.org/docs/Web/HTTP/Reference/Headers/Content-Security-Policy)
#' and [the CSP section of the MDN security guide](https://developer.mozilla.org/docs/Web/Security/Practical_implementation_guides/CSP)
#' for more information on the header
#'
#' @param default_src Fallback for all other `*_src` values
#' @param script_src Fallback for `script_src_*` values
#' @param script_src_elem Valid sources for `<script>` elements
#' @param script_src_attr Valid sources for inline event handlers
#' @param style_src Fallback for `style_src_*` values
#' @param style_src_elem Valid sources for `<style>` elements
#' @param style_src_attr Valid sources for inline styling of elements
#' @param img_src Valid sources for images and favicons
#' @param font_src Valid sources for fonts loaded with `@font-face`
#' @param media_src Valid sources for `<audio>`, `<video>`, and `<track>` elements
#' @param object_src Valid sources for `<object>` and `<embed>` elements
#' @param child_src Fallback for `frame_src` and `worker_src`
#' @param frame_src Valid sources for `<frame>` and `<iframe>` elements
#' @param worker_src Valid sources for `Worker`, `SharedWorker`, and
#' `ServiceWorker` scripts
#' @param connect_src Valid sources for URLs loaded from within scripts
#' @param fenced_frame_src Valid sources for `<fencedframe>` elements
#' @param manifest_src Valid sources for application manifest files
#' @param prefetch_src Valid sources to be prefetched and prerendered
#' @param base_uri Valid sources that can be put in a `<base>` element
#' @param sandbox Logical. Enable sandboxing of the requested document/ressource
#' @param form_action Valid URLs to be targeted by form submissions
#' @param frame_ancestors Valid parents that may embed this document in an
#' `<frame>`, `<iframe>`, `<object>`, or `<embed>` element.
#' @param report_to A URL to report violations to. Setting this will also add
#' a `report-uri` directive along with a `Reporting-Endpoints` header for
#' maximum compitability.
#' @param require_trusted_types_for Logical. Enforces [Trusted Types](https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API)
#' @param trusted_types Specifies an allow list of [Trusted Types](https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API)
#' @param upgrade_insecure_requests Logical. Automatically treat all HTTP urls in the
#' document as if they were HTTPS
#'
#' @return A bare list with the input arguments
#'
#' @export
#'
#' @examples
#' # Default setting
#' csp(
#'   default_src = "self",
#'   script_src = "self",
#'   script_src_attr = "none",
#'   style_src = c("self", "https:", "unsafe-inline"),
#'   img_src = c("self", "data:"),
#'   font_src = c("self", "https:", "data:"),
#'   object_src = "none",
#'   base_uri = "self",
#'   form_action = "self",
#'   frame_ancestors = "self",
#'   upgrade_insecure_requests = TRUE
#' )
#'
csp <- function(
  default_src = NULL,
  script_src = NULL,
  script_src_elem = NULL,
  script_src_attr = NULL,
  style_src = NULL,
  style_src_elem = NULL,
  style_src_attr = NULL,
  img_src = NULL,
  font_src = NULL,
  media_src = NULL,
  object_src = NULL,
  child_src = NULL,
  frame_src = NULL,
  worker_src = NULL,
  connect_src = NULL,
  fenced_frame_src = NULL,
  manifest_src = NULL,
  prefetch_src = NULL,
  base_uri = NULL,
  sandbox = FALSE,
  form_action = NULL,
  frame_ancestors = NULL,
  report_to = NULL,
  require_trusted_types_for = FALSE,
  trusted_types = NULL,
  upgrade_insecure_requests = FALSE
) {
  list(
    child_src = child_src,
    connect_src = connect_src,
    default_src = default_src,
    fenced_frame_src = fenced_frame_src,
    font_src = font_src,
    frame_src = frame_src,
    img_src = img_src,
    manifest_src = manifest_src,
    media_src = media_src,
    object_src = object_src,
    prefetch_src = prefetch_src,
    script_src = script_src,
    script_src_elem = script_src_elem,
    script_src_attr = script_src_attr,
    style_src = style_src,
    style_src_elem = style_src_elem,
    style_src_attr = style_src_attr,
    worker_src = worker_src,
    base_uri = base_uri,
    sandbox = if (isTRUE(sandbox)) "" else NULL,
    form_action = form_action,
    frame_ancestors = frame_ancestors,
    report_to = report_to,
    require_trusted_types_for = if (isTRUE(require_trusted_types_for)) "" else NULL,
    trusted_types = trusted_types,
    upgrade_insecure_requests = if (isTRUE(upgrade_insecure_requests)) "" else NULL
  )
}

csp_directives <- list(
  "child_src",
  "connect_src",
  "default_src",
  "fenced_frame_src",
  "font_src",
  "frame_src",
  "img_src",
  "manifest_src",
  "media_src",
  "object_src",
  "prefetch_src",
  "script_src",
  "script_src_elem",
  "script_src_attr",
  "style_src",
  "style_src_elem",
  "style_src_attr",
  "worker_src",
  "base_uri",
  "sandbox",
  "form_action",
  "frame_ancestors",
  "report_to",
  "require_trusted_types_for",
  "trusted_types",
  "upgrade_insecure_requests"
)
csp_values <- list(
  "none" = list(
    applies_to = c(),
    ignores = c()
  ),
  "nonce-.*" = list(
    applies_to = c(
      "default_src",
      "script_src",
      "script_src_elem",
      "script_src_attr",
      "style_src",
      "style_src_elem",
      "style_src_attr"
    ),
    ignores = c("unsafe-inline")
  ),
  "sha256-.*" = list(
    applies_to = c(
      "default_src",
      "script_src",
      "script_src_elem",
      "script_src_attr",
      "style_src",
      "style_src_elem",
      "style_src_attr"
    ),
    ignores = c("unsafe-inline")
  ),
  "sha384-.*" = list(
    applies_to = c(
      "default_src",
      "script_src",
      "script_src_elem",
      "script_src_attr",
      "style_src",
      "style_src_elem",
      "style_src_attr"
    ),
    ignores = c("unsafe-inline")
  ),
  "sha512-.*" = list(
    applies_to = c(
      "default_src",
      "script_src",
      "script_src_elem",
      "script_src_attr",
      "style_src",
      "style_src_elem",
      "style_src_attr"
    ),
    ignores = c("unsafe-inline")
  ),
  "self" = list(
    applies_to = c(),
    ignores = c()
  ),
  "unsafe-eval" = list(
    applies_to = c(
      "default_src",
      "script_src",
      "script_src_elem",
      "script_src_attr"
    ),
    ignores = c()
  ),
  "wasm-unsafe-eval" = list(
    applies_to = c(
      "default_src",
      "script_src",
      "script_src_elem",
      "script_src_attr"
    ),
    ignores = c()
  ),
  "unsafe-inline" = list(
    applies_to = c(
      "default_src",
      "script_src",
      "script_src_elem",
      "script_src_attr",
      "style_src",
      "style_src_elem",
      "style_src_attr"
    ),
    ignores = c()
  ),
  "unsafe-hashes" = list(
    applies_to = c(
      "default_src",
      "script_src",
      "script_src_elem",
      "script_src_attr",
      "style_src",
      "style_src_elem",
      "style_src_attr"
    ),
    ignores = c()
  ),
  "inline-speculation-rules" = list(
    applies_to = c(
      "default_src",
      "script_src",
      "script_src_elem",
      "script_src_attr"
    ),
    ignores = c()
  ),
  "strict-dynamic" = list(
    applies_to = c(
      "default_src",
      "script_src",
      "script_src_elem",
      "script_src_attr"
    ),
    ignores = c("self", "unsafe-inline", NA)
  ),
  "report-sample" = list(
    applies_to = c(),
    ignores = c()
  )
)
csp_value_regex <- paste0("^'?", names(csp_values), "'?$")

validate_csp <- function(csp, call = caller_env()) {
  if (is.null(csp)) {
    return()
  }
  if (
    !(is_bare_list(csp) &&
      is_named(csp) &&
      all(
        names(csp) %in% csp_directives
      ))
  ) {
    stop_input_type(
      csp,
      cli::format_inline(
        "a list with elements {.and {.arg {csp_directives}}}"
      ),
      allow_null = TRUE,
      arg = "value",
      call = call
    )
  }
  csp <- csp[lengths(csp) != 0]
  for (directive in names(csp)) {
    check_character(
      csp[[directive]],
      allow_na = FALSE,
      arg = paste0("value$", directive),
      call = call
    )
    val_match <- vapply(
      csp[[directive]],
      function(val) {
        which(vapply(csp_value_regex, grepl, logical(1), x = val))[1]
      },
      integer(1)
    )
    csp[[directive]][!is.na(val_match)] <- gsub(
      "^'?|'?$",
      "'",
      csp[[directive]][!is.na(val_match)],
      perl = TRUE
    )
    remove <- integer()
    for (i in seq_along(val_match)) {
      if (i %in% remove) {
        next
      }
      val <- val_match[i]
      if (is.na(val)) {
        next
      }
      if (
        length(csp_values[[val]]$applies_to) != 0 &&
          !directive %in% csp_values[[val]]$applies_to
      ) {
        cli::cli_warn(
          "{.val {csp[[directive]][i]}} is not applicable to the {.field {directive}} directive. Ignoring"
        )
        remove <- c(remove, i)
      } else if (length(csp_values[[val]]$ignores) != 0) {
        ignore_ind <- match(csp_values[[val]]$ignores, names(csp_values))
        superseeded <- which(val_match %in% ignore_ind)
        if (length(superseeded) != 0) {
          cli::cli_warn(
            "{.val {csp[[directive]][superseeded]}} are superseeded by {csp[[directive]][i]} in {.field {directive}}. Ignoring"
          )
          remove <- c(remove, superseeded)
        }
      }
    }
    if (length(remove) != 0) {
      csp[[directive]] <- csp[[directive]][-unique(remove)]
    }
  }
  csp
}
