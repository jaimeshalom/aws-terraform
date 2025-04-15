terraform {
  backend "s3" {
    bucket = "tfstate-terraform-practice-afda234234asw34gfer35"
    key    = "terraform/terraform-practice.tfstate"
    region = "us-east-1"
  }
}

module "nginx_server_dev" {
  source = "./nginx_server_module"

  aws_profile   = var.aws_profile
  aws_region    = var.aws_region
  environment   = "dev"
  project_name  = var.project_name
  owner         = var.owner
  ami_id        = var.ami_id
  instance_type = "t3.micro"
  server_name   = var.server_name
}

module "nginx_server_stage" {
  source = "./nginx_server_module"

  aws_profile   = var.aws_profile
  aws_region    = var.aws_region
  environment   = "dev"
  project_name  = var.project_name
  owner         = var.owner
  ami_id        = var.ami_id
  instance_type = "t3.nano"
  server_name   = var.server_name
}

output "nginx_server_dev_public_ip" {
  description = "Public IP of the EC2 instance"
  value       = module.nginx_server_dev.aws_instance_public_ip
}

output "nginx_server_dev_public_dns" {
  description = "Public DNS of the EC2 instance"
  value       = module.nginx_server_dev.aws_instance_public_dns
}
output "nginx_server_stage_public_ip" {
  description = "Public IP of the EC2 instance"
  value       = module.nginx_server_stage.aws_instance_public_ip
}

output "nginx_server_stage_public_dns" {
  description = "Public DNS of the EC2 instance"
  value       = module.nginx_server_stage.aws_instance_public_dns
}
