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

# variable "ami_id" {
#   description = "ID de la AMI a utilizar"
#   type        = string
#   default     = "ami-0440d3b780d96b29d"
# }

# variable "server_name" {
#   description = "Nombre del servidor"
#   type        = string
#   default     = "nginx-server"
# }

variable "image_tag" {
  type        = string
  description = "Etiqueta de la imagen Docker"
  default     = "latest"
}

variable "git_version_tag" {
  description = "The semantic version tag from Git (e.g., v1.2.3)"
  type        = string
  default     = "unknown"
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

# variable "mongodb_uri_dev" {
#   description = "Cadena de conexión a MongoDB para desarrollo"
#   type        = string
#   default     = "mongodb://localhost:27017"
# }

# variable "mongodb_uri_stage" {
#   description = "Cadena de conexión a MongoDB para pruebas"
#   type        = string
#   default     = "mongodb://localhost:27017"
# }

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

variable "route53_zone_name" {
  description = "El nombre de la zona hospedada pública en Route 53 (incluyendo el punto final, ej: 'midominio.com.')."
  type        = string
  # No añadas un 'default' si quieres que sea obligatorio proporcionar este valor.

  # Validación opcional pero muy recomendada para asegurar el formato correcto:
  validation {
    # Asegura que el nombre de la zona termine con un punto.
    condition     = endswith(var.route53_zone_name, ".")
    error_message = "El valor de route53_zone_name debe terminar con un punto (.). Ejemplo: 'midominio.com.'."
  }
}

variable "mongodb_root_password" {
  description = "Root password for the internal MongoDB instance. ¡Gestionar de forma segura!"
  type        = string
  sensitive   = true
  # No pongas un default aquí. Pásalo como variable de entorno (TF_VAR_mongodb_root_password)
  # o usa un archivo tfvars seguro.
}