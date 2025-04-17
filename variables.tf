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
  description = "Responsable del recurso (equipo o individuo), si no se especifica se extrae del usuario aws del llamador"
  type        = string
  default     = null
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

variable "image_tag" {
  type        = string
  description = "Etiqueta de la imagen Docker"
  default     = "latest"
}

variable "environment" {
  description = "Entorno de despliegue (dev, stage, prod)"
  type        = string
  default     = "dev"
}

variable "mongodb_uri" {
  description = "Cadena de conexión a MongoDB"
  type        = string
  default     = "mongodb://localhost:27017"
}

variable "mongodb_uri_dev" {
  description = "Cadena de conexión a MongoDB para desarrollo"
  type        = string
  default     = "mongodb://localhost:27017"
}

variable "mongodb_uri_stage" {
  description = "Cadena de conexión a MongoDB para pruebas"
  type        = string
  default     = "mongodb://localhost:27017"
}
