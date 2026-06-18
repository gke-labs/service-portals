variable "concurrency" {
  type        = number
  default     = 90
  description = "Number of concurrent workers per stress pod."
}

variable "duration" {
  type        = number
  default     = 45
  description = "Duration of the stress test run in seconds."
}

variable "parallelism" {
  type        = number
  default     = 16
  description = "Number of stress generator pods to run concurrently."
}

variable "completions" {
  type        = number
  default     = 16
  description = "Total number of successful pod completions for the Job."
}

variable "registry_path" {
  type        = string
  default     = "/api/v1/cratesio"
  description = "The target registry path to test (e.g. /api/v1/crates for private registry, or /api/v1/cratesio for crates.io proxy fallback)."
}

variable "node_selector" {
  type        = map(string)
  default     = {
    "cloud.google.com/machine-family" = "n2"
  }
  description = "Additional node selectors for load generator pods (e.g. {'cloud.google.com/machine-family' = 'n2'})."
}
