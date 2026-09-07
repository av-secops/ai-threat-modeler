variable "api_token" {
  type      = string
  sensitive = true
  default   = "holdout-secret-token"
}

resource "aws_s3_bucket" "documents" {
  bucket = "claims-documents"
  acl    = "public-read"
}

resource "aws_lambda_function" "processor" {
  function_name = "claim-processor"
  role          = aws_iam_role.processor.arn
  timeout       = 900
  environment {
    variables = {
      DOCUMENT_BUCKET = aws_s3_bucket.documents.id
      API_TOKEN       = "embedded-secret"
    }
  }
}

resource "aws_iam_role" "processor" {
  name = "claim-processor"
  assume_role_policy = jsonencode({
    Statement = [{ Effect = "Allow", Principal = "*", Action = "sts:AssumeRole" }]
  })
}

resource "azurerm_storage_account" "archive" {
  name                     = "claimsarchive"
  resource_group_name      = "claims"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_0"
  shared_access_key_enabled = true
}

resource "google_sql_database_instance" "analytics" {
  name             = "claims-analytics"
  database_version = "POSTGRES_15"
  settings {
    ip_configuration {
      ipv4_enabled = true
      authorized_networks { value = "0.0.0.0/0" }
    }
  }
}
