variable "aws_region" {
  description = "AWS region for Lambda, EventBridge, and S3 resources."
  type        = string
  default     = "us-east-1"
}

variable "state_bucket_name" {
  description = "Optional name for the S3 bucket that stores Terraform state files. If empty, Terraform creates a new bucket."
  type        = string
  default     = ""
}

variable "state_prefix" {
  description = "S3 prefix path where Heliopause scans for Terraform state files."
  type        = string
  default     = "heliopause/statefiles/"
}

variable "core_state_file" {
  description = "Name of the core Heliopause state file that must be present for self-preservation."
  type        = string
  default     = "heliopause.tfstate"
}

variable "lambda_function_name" {
  description = "Name for the AWS Lambda function."
  type        = string
  default     = "heliopause-cleanup"
}

variable "lambda_role_name" {
  description = "Name for the AWS Lambda IAM execution role."
  type        = string
  default     = "heliopause-lambda-role"
}

variable "lambda_timeout" {
  description = "Maximum execution time for the Lambda function in seconds."
  type        = number
  default     = 300
}

variable "lambda_memory_size" {
  description = "Memory size for the Lambda function in MB."
  type        = number
  default     = 512
}

variable "schedule_expression" {
  description = "EventBridge schedule expression for triggering the cleanup Lambda."
  type        = string
  default     = "cron(0 0 * * ? *)"
}

variable "dry_run" {
  description = "Whether the Lambda should run in dry-run mode by default."
  type        = bool
  default     = true
}

variable "notification_email" {
  description = "Optional email address to subscribe to the SNS topic for notifications."
  type        = string
  default     = null
}

variable "purge_data_stores" {
  description = "Toggles purging of RDS, ElastiCache, and AMP resources."
  type        = bool
  default     = true
}

variable "purge_storage_buckets" {
  description = "Toggles purging of S3 buckets (contents emptied first)."
  type        = bool
  default     = true
}

variable "purge_custom_iam" {
  description = "Toggles purging of IAM roles and users not whitelisted in state files."
  type        = bool
  default     = true
}

