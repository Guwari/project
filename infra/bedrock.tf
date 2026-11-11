variable "bedrock_trusted_role_arn" {
  description = "ARN of the IAM role allowed to assume the Bedrock analysis role."
  type        = string
}

variable "bedrock_model_arn" {
  description = "ARN of one regional Bedrock foundation model."
  type        = string

  validation {
    condition = can(regex(
      "^arn:aws:bedrock:[a-z0-9-]+::foundation-model/[a-zA-Z0-9.:-]+$",
      var.bedrock_model_arn
    ))
    error_message = "Provide a regional foundation model ARN with no wildcards."
  }
}

resource "aws_iam_role" "bedrock_analysis" {
  name = "cloudsentinel-bedrock-analysis"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = var.bedrock_trusted_role_arn }
    }]
  })
}

resource "aws_iam_role_policy" "bedrock_analysis" {
  name = "cloudsentinel-invoke-one-model"
  role = aws_iam_role.bedrock_analysis.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "bedrock:InvokeModel"
      Resource = var.bedrock_model_arn
    }]
  })
}
