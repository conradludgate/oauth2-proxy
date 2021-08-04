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

resource "aws_dynamodb_table" "tokens" {
  name      = "Tokens"
  hash_key  = "token_id"
  range_key = "username"

  attribute {
    name = "token_id"
    type = "S"
  }

  attribute {
    name = "username"
    type = "S"
  }

  global_secondary_index {
    name               = "TokenUserIndex"
    hash_key           = "username"
    projection_type    = "INCLUDE"
    non_key_attributes = ["name"]
  }
}
