terraform {
  backend "s3" {
    bucket  = "tfstate-terraform-practice-afda234234asw34gfer35"
    key     = "terraform/terraform-practice.tfstate"
    region  = "us-east-1"
    profile = "js"
  }
}

module "ecs_service_dev" {
  source = "./ecs_module"

  aws_profile   = var.aws_profile
  aws_region    = var.aws_region
  environment   = "dev"
  project_name  = var.project_name
  owner         = var.owner
}

module "ecs_service_stage" {
  source = "./ecs_module"

  aws_profile   = var.aws_profile
  aws_region    = var.aws_region
  environment   = "dev"
  project_name  = var.project_name
  owner         = var.owner
}

# output "ecs_service_dev_public_ip" {
#   description = "Public IP of the EC2 instance"
#   value       = module.ecs_service_dev.aws_instance_public_ip
# }

# output "ecs_service_dev_public_dns" {
#   description = "Public DNS of the EC2 instance"
#   value       = module.ecs_service_dev.aws_instance_public_dns
# }
# output "ecs_service_stage_public_ip" {
#   description = "Public IP of the EC2 instance"
#   value       = module.ecs_service_stage.aws_instance_public_ip
# }

# output "ecs_service_stage_public_dns" {
#   description = "Public DNS of the EC2 instance"
#   value       = module.ecs_service_stage.aws_instance_public_dns
# }
