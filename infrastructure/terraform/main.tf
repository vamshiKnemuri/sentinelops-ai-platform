data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  availability_zones = slice(data.aws_availability_zones.available.names, 0, 2)
  name               = "${var.project_name}-${var.environment}"
}

module "network" {
  source = "./modules/network"

  name               = local.name
  vpc_cidr           = var.vpc_cidr
  availability_zones = local.availability_zones
  cluster_name       = local.name
}

module "eks" {
  source = "./modules/eks"

  name                = local.name
  kubernetes_version  = var.kubernetes_version
  private_subnet_ids  = module.network.private_subnet_ids
  public_access_cidrs = var.cluster_public_access_cidrs
  node_instance_types = var.node_instance_types
  node_desired_size   = var.node_desired_size
}

resource "aws_kms_key" "data" {
  description             = "SentinelOps incident, queue, and runbook encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 7
}

resource "aws_kms_alias" "data" {
  name          = "alias/${local.name}-data"
  target_key_id = aws_kms_key.data.key_id
}

resource "aws_s3_bucket" "runbooks" {
  bucket        = "${local.name}-runbooks-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "runbooks" {
  bucket = aws_s3_bucket.runbooks.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "runbooks" {
  bucket = aws_s3_bucket.runbooks.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.data.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "runbooks" {
  bucket = aws_s3_bucket.runbooks.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "runbooks" {
  bucket = aws_s3_bucket.runbooks.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.runbooks.arn, "${aws_s3_bucket.runbooks.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_s3_object" "runbooks" {
  for_each = fileset("${path.root}/../../knowledge/runbooks", "*.md")

  bucket                 = aws_s3_bucket.runbooks.id
  key                    = "runbooks/${each.value}"
  source                 = "${path.root}/../../knowledge/runbooks/${each.value}"
  source_hash            = filesha256("${path.root}/../../knowledge/runbooks/${each.value}")
  server_side_encryption = "aws:kms"
  kms_key_id             = aws_kms_key.data.arn
  metadata = {
    sha256 = filesha256("${path.root}/../../knowledge/runbooks/${each.value}")
  }
}

resource "aws_dynamodb_table" "incidents" {
  name         = "${local.name}-incidents"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  ttl {
    attribute_name = "ttl_epoch"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.data.arn
  }
}

resource "aws_sqs_queue" "dead_letter" {
  name                              = "${local.name}-incidents-dlq"
  kms_master_key_id                 = aws_kms_key.data.arn
  kms_data_key_reuse_period_seconds = 300
  message_retention_seconds         = 1209600
}

resource "aws_sqs_queue" "incidents" {
  name                              = "${local.name}-incidents"
  kms_master_key_id                 = aws_kms_key.data.arn
  kms_data_key_reuse_period_seconds = 300
  visibility_timeout_seconds        = 120
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dead_letter.arn
    maxReceiveCount     = 3
  })
}

resource "aws_ecr_repository" "api" {
  name                 = "${local.name}-api"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = true

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.data.arn
  }

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_iam_role" "agent" {
  name = "${local.name}-agent"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "pods.eks.amazonaws.com" }
      Action    = ["sts:AssumeRole", "sts:TagSession"]
    }]
  })
}

resource "aws_iam_role_policy" "agent" {
  name = "${local.name}-agent"
  role = aws_iam_role.agent.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "InvokeConfiguredBedrockModel"
        Effect   = "Allow"
        Action   = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
        Resource = "arn:${data.aws_partition.current.partition}:bedrock:${var.aws_region}::foundation-model/${var.bedrock_model_id}"
      },
      {
        Sid      = "ReadRunbooks"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = [aws_s3_bucket.runbooks.arn, "${aws_s3_bucket.runbooks.arn}/*"]
      },
      {
        Sid      = "IncidentState"
        Effect   = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query",
          "dynamodb:TransactWriteItems"
        ]
        Resource = aws_dynamodb_table.incidents.arn
      },
      {
        Sid      = "IncidentQueue"
        Effect   = "Allow"
        Action   = ["sqs:DeleteMessage", "sqs:GetQueueAttributes", "sqs:ReceiveMessage"]
        Resource = aws_sqs_queue.incidents.arn
      },
      {
        Sid      = "DecryptProjectData"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.data.arn
      }
    ]
  })
}

resource "aws_eks_pod_identity_association" "agent" {
  cluster_name    = module.eks.cluster_name
  namespace       = "sentinelops"
  service_account = "sentinelops"
  role_arn        = aws_iam_role.agent.arn
}
