output "state_bucket_name" {
  description = "Name of the S3 bucket used to store Terraform state files."
  value       = aws_s3_bucket.state_bucket.bucket
}

output "lambda_function_name" {
  description = "Name of the deployed Heliopause Lambda function."
  value       = aws_lambda_function.heliopause.function_name
}

output "lambda_function_arn" {
  description = "ARN of the deployed Heliopause Lambda function."
  value       = aws_lambda_function.heliopause.arn
}

output "eventbridge_rule_name" {
  description = "Name of the EventBridge schedule rule triggering the cleanup Lambda."
  value       = aws_cloudwatch_event_rule.purge_schedule.name
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for Heliopause notifications."
  value       = aws_sns_topic.notifications.arn
}
