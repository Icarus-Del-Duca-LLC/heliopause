terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "state_bucket" {
  bucket = var.state_bucket_name != "" ? var.state_bucket_name : "heliopause-state-${random_id.bucket_suffix.hex}"

  versioning {
    enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  lifecycle_rule {
    id      = "expire-old-state-files"
    enabled = true

    prefix = var.state_prefix

    expiration {
      days = 365
    }
  }
}

resource "aws_s3_bucket_public_access_block" "state_bucket_block" {
  bucket = aws_s3_bucket.state_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda_execution" {
  name               = "heliopause-lambda-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

data "aws_iam_policy_document" "lambda_policy" {
  statement {
    sid       = "S3StateAccess"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.state_bucket.arn]
  }

  statement {
    sid = "S3StateObjectAccess"
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion"
    ]
    resources = ["${aws_s3_bucket.state_bucket.arn}/*"]
  }

  statement {
    sid = "CloudWatchLogging"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["arn:aws:logs:*:*:*"]
  }

  statement {
    sid = "ReadOnlyAwsInventory"
    actions = [
      "ec2:Describe*",
      "rds:Describe*",
      "elasticloadbalancing:Describe*",
      "ecs:Describe*",
      "cloudwatch:Describe*",
      "ssm:GetParameter"
    ]
    resources = ["*"]
  }

  statement {
    sid = "ResourceTermination"
    actions = [
      "ec2:TerminateInstances",
      "ec2:DeleteVolume",
      "ec2:DeleteNatGateway",
      "ec2:DeleteSubnet",
      "ec2:DeleteRoute",
      "ec2:DeleteRouteTable",
      "ec2:DeleteVpc",
      "rds:DeleteDBInstance",
      "elasticloadbalancing:DeleteLoadBalancer"
    ]
    resources = ["*"]
  }

  statement {
    sid = "SNSPublish"
    actions = [
      "sns:Publish"
    ]
    resources = [aws_sns_topic.notifications.arn]
  }
}

resource "aws_iam_role_policy" "lambda_policy" {
  name   = "heliopause-lambda-policy"
  role   = aws_iam_role.lambda_execution.id
  policy = data.aws_iam_policy_document.lambda_policy.json
}

resource "aws_sns_topic" "notifications" {
  name = "heliopause-notifications"
}

data "archive_file" "lambda_package" {
  type        = "zip"
  source_file = "${path.module}/../lambda/handler.py"
  output_path = "${path.module}/heliopause_lambda.zip"
}

resource "aws_lambda_function" "heliopause" {
  filename         = data.archive_file.lambda_package.output_path
  function_name    = var.lambda_function_name
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  role             = aws_iam_role.lambda_execution.arn
  source_code_hash = data.archive_file.lambda_package.output_base64sha256
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_size

  environment {
    variables = {
      STATE_BUCKET_NAME = aws_s3_bucket.state_bucket.id
      STATE_PREFIX      = var.state_prefix
      CORE_STATE_FILE   = var.core_state_file
      DRY_RUN           = tostring(var.dry_run)
      SNS_TOPIC_ARN     = aws_sns_topic.notifications.arn
    }
  }
}

resource "aws_cloudwatch_event_rule" "purge_schedule" {
  name                = "heliopause-purge-schedule"
  schedule_expression = var.schedule_expression
  description         = "Scheduled trigger for the Heliopause cleanup Lambda."
}

resource "aws_cloudwatch_event_target" "purge_lambda" {
  rule      = aws_cloudwatch_event_rule.purge_schedule.name
  target_id = "HeliopauseLambda"
  arn       = aws_lambda_function.heliopause.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.heliopause.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.purge_schedule.arn
}
