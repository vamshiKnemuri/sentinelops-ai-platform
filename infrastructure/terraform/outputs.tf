output "cluster_name" {
  value = module.eks.cluster_name
}

output "ecr_repository_url" {
  value = aws_ecr_repository.api.repository_url
}

output "runbooks_bucket" {
  value = aws_s3_bucket.runbooks.id
}

output "incidents_table" {
  value = aws_dynamodb_table.incidents.name
}

output "incident_queue_url" {
  value = aws_sqs_queue.incidents.url
}

output "agent_role_arn" {
  value = aws_iam_role.agent.arn
}
