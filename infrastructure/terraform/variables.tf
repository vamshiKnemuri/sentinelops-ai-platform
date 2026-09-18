variable "aws_region" {
  type        = string
  description = "AWS region for the short-lived demo."
  default     = "us-east-1"
}

variable "project_name" {
  type        = string
  description = "Short project name used in resource names."
  default     = "sentinelops"
}

variable "environment" {
  type    = string
  default = "demo"
}

variable "github_repository" {
  type        = string
  description = "GitHub repository in owner/name form."
}

variable "vpc_cidr" {
  type    = string
  default = "10.30.0.0/16"
}

variable "kubernetes_version" {
  type    = string
  default = "1.36"
}

variable "cluster_public_access_cidrs" {
  type        = list(string)
  description = "Restricted CIDRs permitted to reach the demo EKS API."
  default     = ["127.0.0.1/32"]

  validation {
    condition = (
      length(var.cluster_public_access_cidrs) > 0 &&
      alltrue([for cidr in var.cluster_public_access_cidrs : can(cidrnetmask(cidr))]) &&
      !contains(var.cluster_public_access_cidrs, "0.0.0.0/0")
    )
    error_message = "Provide restricted valid CIDRs; 0.0.0.0/0 is forbidden."
  }
}

variable "node_instance_types" {
  type    = list(string)
  default = ["t3.medium"]
}

variable "node_desired_size" {
  type    = number
  default = 2
}

variable "bedrock_model_id" {
  type        = string
  description = "Bedrock model invoked through the Converse API."
  default     = "amazon.nova-lite-v1:0"
}
