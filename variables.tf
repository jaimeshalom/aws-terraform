variable "aws_profile" {
  type        = string
  default     = ""
  description = "AWS Profile to use"
}

variable "aws_region" {
  type        = string
  default     = "us-east-1"
  description = "AWS Region to use"
}

variable "project_name" {
  description = "Nombre del proyecto"
  type        = string
  default     = "terraform-practice"
}

variable "owner" {
  description = "Responsable del recurso (equipo o individuo)"
  type        = string
  default     = "DevOps"
}

variable "ami_id" {
  description = "ID de la AMI a utilizar"
  type        = string
  default     = "ami-0440d3b780d96b29d"
}

variable "server_name" {
  description = "Nombre del servidor"
  type        = string
  default     = "nginx-server"
}
