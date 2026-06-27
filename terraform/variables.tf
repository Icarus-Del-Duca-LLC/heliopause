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

variable "purge_ec2_instances" {
  description = "Toggles purging of EC2 instances."
  type        = bool
  default     = true
}

variable "purge_nat_gateways" {
  description = "Toggles purging of NAT Gateways."
  type        = bool
  default     = true
}

variable "purge_ebs_volumes" {
  description = "Toggles purging of detached EBS volumes."
  type        = bool
  default     = true
}

variable "purge_rds_instances" {
  description = "Toggles purging of RDS instances."
  type        = bool
  default     = true
}

variable "purge_load_balancers" {
  description = "Toggles purging of Elastic Load Balancers."
  type        = bool
  default     = true
}

variable "purge_security_groups" {
  description = "Toggles purging of custom security groups."
  type        = bool
  default     = true
}

variable "purge_auto_scaling_groups" {
  description = "Toggles purging of Auto Scaling Groups."
  type        = bool
  default     = true
}

variable "purge_ecs_clusters" {
  description = "Toggles purging of ECS clusters."
  type        = bool
  default     = true
}

variable "purge_elasticache_clusters" {
  description = "Toggles purging of ElastiCache clusters."
  type        = bool
  default     = true
}

variable "purge_prometheus_workspaces" {
  description = "Toggles purging of AMP (Prometheus) workspaces."
  type        = bool
  default     = true
}

variable "purge_s3_buckets" {
  description = "Toggles purging of untracked S3 buckets (off by default)."
  type        = bool
  default     = false
}

variable "purge_iam_roles" {
  description = "Toggles purging of untracked custom IAM roles (off by default)."
  type        = bool
  default     = false
}

variable "purge_iam_users" {
  description = "Toggles purging of untracked custom IAM users."
  type        = bool
  default     = true
}

variable "purge_vpcs" {
  description = "Toggles purging of non-default VPCs (off by default)."
  type        = bool
  default     = false
}

variable "extra_immune_iam_arns" {
  description = "List of IAM User or Role ARNs immune from purging."
  type        = list(string)
  default     = []
}

variable "warning_offset_hours" {
  description = "Number of hours before the purge to trigger the warning."
  type        = number
  default     = 2
}


