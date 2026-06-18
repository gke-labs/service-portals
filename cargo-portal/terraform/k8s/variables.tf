variable "enable_oauth2" {
  type        = bool
  default     = false
  description = "Enable Google OIDC OAuth2 authentication in Kellnr."
}

variable "kellnr_oauth2_client_id" {
  type        = string
  default     = "dummy-client-id"
  description = "Google OAuth2 Client ID (required if enable_oauth2 is true)."
}

variable "kellnr_oauth2_client_secret" {
  type        = string
  default     = "dummy-client-secret"
  description = "Google OAuth2 Client Secret (required if enable_oauth2 is true)."
}

variable "kellnr_oauth2_issuer" {
  type        = string
  default     = "https://accounts.google.com"
  description = "The OIDC issuer URL."
}
