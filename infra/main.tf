terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

variable "trusted_role_arn" {
  description = "ARN of the IAM role allowed to assume the scanner role."
  type        = string
}

resource "aws_iam_role" "scanner" {
  name = "cloudsentinel-scanner"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = var.trusted_role_arn }
    }]
  })
}

resource "aws_iam_role_policy" "scanner" {
  name = "cloudsentinel-read-config"
  role = aws_iam_role.scanner.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:ListAllMyBuckets",
          "ec2:DescribeSecurityGroups",
          "iam:GetAccountSummary",
          "cloudtrail:DescribeTrails",
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetBucketPublicAccessBlock",
          "s3:GetBucketPolicyStatus",
          "s3:GetBucketVersioning",
        ]
        Resource = "arn:aws:s3:::*"
      },
      {
        Effect   = "Allow"
        Action   = "cloudtrail:GetTrailStatus"
        Resource = "arn:aws:cloudtrail:*:*:trail/*"
      },
    ]
  })
}
