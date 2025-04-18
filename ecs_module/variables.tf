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

variable "environment" {
  description = "Entorno de despliegue (dev, stage, prod)"
  type        = string
  default     = "dev"
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

variable "mongodb_uri" {
  description = "Cadena de conexión a MongoDB"
  type        = string
  default     = "mongodb://localhost:27017"
}

variable "ecr_image_tag" {
  description = "Tag de la imagen de Docker"
  type        = string
  default     = "latest"
}

variable "git_version_tag" {
  description = "The semantic version tag from Git (e.g., v1.2.3)"
  type        = string
  default     = "unknown"
}

variable "ecs_task_memory" {
  description = "Cantidad de memoria (en MiB) para asignar a la tarea ECS."
  type        = number
  default     = 512 # O el valor que necesites
}

variable "ecs_task_cpu" {
  description = "Cantidad de CPU (en unidades de CPU) para asignar a la tarea ECS (256 = 0.25 vCPU)."
  type        = number
  default     = 256 # O el valor que necesites
}

variable "ecs_service_desired_count" {
  description = "Número deseado de instancias de la tarea a ejecutar."
  type        = number
  default     = 1
}

variable "domain_name" {
  description = "El nombre de dominio completo para la aplicación (ej. app.ejemplo.com)"
  type        = string
  # No poner un default aquí, debe pasarse como variable
}
