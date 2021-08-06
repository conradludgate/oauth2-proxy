terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "3.52.0"
    }
  }
}

provider "aws" {
  region = "eu-west-2"
}

resource "aws_dynamodb_table" "users" {
  name     = "Users"
  hash_key = "username"

  attribute {
    name = "username"
    type = "S"
  }
}

resource "aws_dynamodb_table" "token" {
  name      = "Token"
  hash_key  = "username"
  range_key = "token_id"

  attribute {
    name = "token_id"
    type = "S"
  }

  attribute {
    name = "username"
    type = "S"
  }
}
