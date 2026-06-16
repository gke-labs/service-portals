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
