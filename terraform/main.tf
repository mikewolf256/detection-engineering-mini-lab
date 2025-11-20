###############################################################################
# Detection Engineering Mini Lab - Terraform Baseline
# Demonstrates IaC for consistent AWS logging and detection prerequisites.
###############################################################################

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

###############################################################################
# Variables
###############################################################################

variable "region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "trail_bucket_name" {
  description = "Name for the CloudTrail S3 bucket"
  type        = string
  default     = "de-mini-lab-cloudtrail-logs"
}

variable "siem_lambda_arn" {
  description = "ARN of the placeholder Lambda that forwards findings to SIEM"
  type        = string
  default     = "arn:aws:lambda:us-east-1:111122223333:function:siem_forwarder"
}

###############################################################################
# S3 bucket for CloudTrail logs (versioned + encrypted + lifecycle)
###############################################################################

resource "aws_s3_bucket" "cloudtrail" {
  bucket        = var.trail_bucket_name
  force_destroy = true

  tags = {
    Project = "DetectionEngineeringMiniLab"
  }
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    id     = "MoveToGlacierAfter30Days"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "GLACIER"
    }
  }
}

###############################################################################
# CloudWatch Logs and IAM Role for CloudTrail
###############################################################################

resource "aws_cloudwatch_log_group" "trail" {
  name              = "/aws/cloudtrail/org_trail"
  retention_in_days = 90
}

resource "aws_iam_role" "cloudtrail" {
  name = "OrgTrailCloudWatchRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
      }
    ]
  })
}

resource "aws_iam_role_policy" "cloudtrail" {
  name = "CloudTrail-To-CloudWatch"
  role = aws_iam_role.cloudtrail.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow",
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"],
        Resource = "${aws_cloudwatch_log_group.trail.arn}:*"
      }
    ]
  })
}

###############################################################################
# Organization-wide CloudTrail
###############################################################################

resource "aws_cloudtrail" "org_trail" {
  name                          = "org_trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_organization_trail         = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.trail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail.arn

  depends_on = [aws_iam_role_policy.cloudtrail]
}

###############################################################################
# Enable GuardDuty
###############################################################################

resource "aws_guardduty_detector" "this" {
  enable = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

###############################################################################
# EventBridge rule for high-severity GuardDuty findings
###############################################################################

resource "aws_cloudwatch_event_rule" "guardduty_high" {
  name        = "guardduty-high-severity"
  description = "Route GuardDuty high-severity findings to SIEM forwarder"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail_type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric: [">=", 7] }]
    }
  })
}

resource "aws_cloudwatch_event_target" "siem" {
  rule      = aws_cloudwatch_event_rule.guardduty_high.name
  target_id = "siem-forwarder"
  arn       = var.siem_lambda_arn
}

###############################################################################
# Outputs
###############################################################################

output "cloudtrail_bucket" {
  value = aws_s3_bucket.cloudtrail.bucket
}

output "guardduty_detector_id" {
  value = aws_guardduty_detector.this.id
}

output "event_rule_name" {
  value = aws_cloudwatch_event_rule.guardduty_high.name
}
