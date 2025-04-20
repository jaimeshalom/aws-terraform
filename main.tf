terraform {
  backend "s3" {
    bucket = "tfstate-terraform-practice-afda234234asw34gfer35"
    key    = "terraform/terraform-practice.tfstate"
    region = "us-east-1"
    use_lockfile = true
  }
}

module "ecs_service" {
  source = "./ecs_module"

  aws_profile               = var.aws_profile
  aws_region                = var.aws_region
  environment               = var.environment
  project_name              = var.project_name
  owner                     = var.owner
  mongodb_uri               = var.mongodb_uri
  image_tag                 = var.image_tag
  git_version_tag           = var.git_version_tag
  ecs_service_desired_count = var.ecs_service_desired_count
  ecs_task_cpu              = var.ecs_task_cpu
  ecs_task_memory           = var.ecs_task_memory
  domain_name               = var.domain_name
  route53_zone_name         = var.route53_zone_name
}

# module "ecs_service_stage" {
#   source = "./ecs_module"

#   aws_profile  = var.aws_profile
#   aws_region   = var.aws_region
#   environment  = "dev"
#   project_name = var.project_name
#   owner        = var.owner
#   mongodb_uri  = var.mongodb_uri_stage
# }

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

output "alb_app_url" {
  description = "URL pública del Application Load Balancer"
  value       = module.ecs_service.alb_app_url
}

output "app_url" {
  description = "URL pública HTTPS de la aplicación"
  value       = module.ecs_service.app_url
}
