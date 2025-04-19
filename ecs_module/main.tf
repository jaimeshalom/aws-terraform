terraform {

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  required_version = ">= 1.6"
}

provider "aws" {
  profile = var.aws_profile
  region  = var.aws_region
}

data "aws_availability_zones" "available" {}

data "aws_caller_identity" "current" {}

locals {
  name_prefix = "${var.project_name}-${var.environment}"

  caller_arn      = data.aws_caller_identity.current.arn
  caller_username = regex(".*/(.*)", local.caller_arn)[0]
  effective_owner = coalesce(var.owner, local.caller_username)

  common_tags = {
    Environment = var.environment
    Project     = var.project_name
    Owner       = local.effective_owner
    ManagedBy   = "Terraform"
  }

  # Selecciona las AZs a usar basado en var.subnet_count
  selected_availability_zones = var.subnet_count == null ? data.aws_availability_zones.available.names : slice(data.aws_availability_zones.available.names, 0, var.subnet_count)
}

# =========================================
# Project Network
# =========================================

resource "aws_vpc" "vpc" {
  cidr_block           = var.vpc_cidr_block
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-vpc"
  })
}

# Subredes PÚBLICAS en cada AZ seleccionada
resource "aws_subnet" "subnets" {
  count                   = length(local.selected_availability_zones) # Usa la longitud de las AZs seleccionadas
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = cidrsubnet(aws_vpc.vpc.cidr_block, 8, count.index)
  map_public_ip_on_launch = true
  availability_zone       = local.selected_availability_zones[count.index]

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-public-subnet-${count.index}"
  })
}

# Internet Gateway para permitir acceso a/desde internet
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-igw"
  })
}

# Tabla de Rutas para las subredes públicas
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.vpc.id

  # Ruta por defecto hacia el Internet Gateway
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-public-rt"
  })
}

# Asociar la tabla de rutas pública a TODAS las subredes creadas
resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.subnets)
  subnet_id      = aws_subnet.subnets[count.index].id
  route_table_id = aws_route_table.public.id
}

# --- SECCIÓN DE VPC ENDPOINTS ELIMINADA ---
# Al usar subredes públicas con un IGW y asignar IPs públicas a las tareas Fargate,
# las tareas pueden acceder a los servicios de AWS (ECR, Secrets Manager, CloudWatch Logs)
# a través de sus endpoints públicos estándar, eliminando la necesidad de VPC Endpoints
# y reduciendo significativamente los costos de red.


# =========================================
# IAM Roles and Policies
# =========================================

resource "aws_iam_role" "ecs_task_execution_role" {
  name = "${local.name_prefix}-ecs_task_execution_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Effect = "Allow"
        Sid    = ""
      },
    ]
  })

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-ecs_task_execution_role"
  })
}

# Política administrada estándar para la ejecución de tareas ECS
resource "aws_iam_role_policy_attachment" "ecs_task_execution_role_policy" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Política para leer el secreto de MongoDB desde Secrets Manager
resource "aws_iam_policy" "mongodb_uri_allow_read" {
  name        = "${local.name_prefix}-mongodb_uri_allow_read"
  description = "Permite al rol de ejecución de tareas ECS leer el secreto de MongoDB"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret" # Describe es útil para la resolución inicial
        ]
        Effect   = "Allow"
        Resource = aws_secretsmanager_secret.mongodb_uri.arn
      }
    ]
  })

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-mongodb_uri_allow_read"
  })
}

# Adjuntar la política de lectura del secreto al rol de ejecución
resource "aws_iam_role_policy_attachment" "attach_mongodb_uri_allow_read" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = aws_iam_policy.mongodb_uri_allow_read.arn
}


# Rol IAM para la propia tarea (permisos que necesita tu aplicación)
resource "aws_iam_role" "ecs_task_role" {
  name = "${local.name_prefix}-ecs_task_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Effect = "Allow"
        Sid    = ""
      },
    ]
  })

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-ecs_task_role"
  })
}

# NOTA: Aquí se debería adjuntar políticas al 'ecs_task_role' si la aplicación
# necesita interactuar con otros servicios AWS (ej. S3, SQS, DynamoDB, etc.)


# =========================================
# Application Load Balancer (ALB)
# =========================================
resource "aws_security_group" "alb_sg" {
  name        = "${local.name_prefix}-alb-sg"
  description = "Allow HTTP and HTTPS inbound from anywhere to ALB"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"] # Permite al ALB enviar tráfico a cualquier destino (tus tareas)
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-alb-sg"
  })
}

resource "aws_alb" "alb" {
  name               = "${local.name_prefix}-alb"
  load_balancer_type = "application"
  internal           = false
  subnets            = [for s in aws_subnet.subnets : s.id]
  security_groups    = [aws_security_group.alb_sg.id]

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-alb"
  })
}

resource "aws_lb_target_group" "tg" {
  name        = "${local.name_prefix}-tg"
  port        = 3000 # Puerto donde escucha tu contenedor ECS
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.vpc.id

  health_check {
    path     = "/"            # Ruta de health check de la app
    port     = "traffic-port" # Usa el puerto del contenedor (3000)
    protocol = "HTTP"
    matcher  = "200" # Puedes usar "200-299" si tu app devuelve otros códigos 2xx para OK
    interval = 30    # Intervalo entre chequeos
    timeout  = 5     # Tiempo de espera para respuesta
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-tg"
  })
}

resource "aws_lb_listener" "http_listener_redirect" {
  load_balancer_arn = aws_alb.alb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301" # Redirección permanente
    }
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-http-listener-redirect"
  })
}

resource "aws_lb_listener" "https_listener" {
  load_balancer_arn = aws_alb.alb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08" # Política de seguridad TLS recomendada
  # ¡IMPORTANTE! Usa el ARN del recurso de VALIDACIÓN, no del certificado directamente
  certificate_arn   = aws_acm_certificate_validation.cert_validation_wait.certificate_arn
  # Si se uso la variable opcional acm_certificate_arn:
  # certificate_arn = var.acm_certificate_arn != null ? var.acm_certificate_arn : aws_acm_certificate.cert[0].arn

  # La acción por defecto es enviar el tráfico al Target Group
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tg.arn
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-https-listener"
  })

  depends_on = [aws_lb_listener.http_listener_redirect]
}

# =========================================
# Elastic Container Registry (ECR)
# =========================================
resource "aws_ecr_repository" "ecr_repository" {
  name                 = "${local.name_prefix}-ecr_repository" # Asegúrarse de que coincida con tu variable env en GHA
  image_tag_mutability = "IMMUTABLE"                           # Buena práctica para evitar sobrescribir tags

  encryption_configuration {
    encryption_type = "AES256" # KMS es una opción si se necesita claves gestionadas por cliente
  }

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-ecr_repository"
  })
}

# =========================================
# Secrets Manager (MongoDB URI)
# =========================================
resource "aws_secretsmanager_secret" "mongodb_uri" {
  name                    = "${local.name_prefix}-mongodb_uri"
  description             = "Cadena de conexión a MongoDB para ${local.name_prefix}"
  recovery_window_in_days = 0 # Sin ventana de recuperación, eliminación inmediata (CUIDADO en producción)

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-mongodb_uri"
  })
}

resource "aws_secretsmanager_secret_version" "mongodb_uri_version" {
  secret_id     = aws_secretsmanager_secret.mongodb_uri.id
  secret_string = var.mongodb_uri # La variable que pasas desde GitHub Actions/terraform.tfvars
  # Evita que Terraform detecte cambios si el secreto se actualiza externamente
  # Esto es útil si no se usa un secreto de GitHub Actions
  # lifecycle {
  #   ignore_changes = [secret_string]
  # }
}

# =========================================
# ECS Cluster, Task Definition, Service
# =========================================

# CloudWatch Log Group para las tareas ECS
resource "aws_cloudwatch_log_group" "ecs_log_group" {
  name = "/ecs/${local.name_prefix}"

  retention_in_days = 14 # Ajustar según necesidad

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-ecs-log-group"
  })
}

# ECS Task Definition
resource "aws_ecs_task_definition" "task_definition" {
  family                   = "${local.name_prefix}-task_definition"
  network_mode             = "awsvpc"
  memory                   = var.ecs_task_memory
  cpu                      = var.ecs_task_cpu
  requires_compatibilities = ["FARGATE"]
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_role.arn # Rol para permisos de la app

  container_definitions = jsonencode([
    {
      name      = "${local.name_prefix}-container" # Nombre lógico del contenedor
      image     = "${aws_ecr_repository.ecr_repository.repository_url}:${var.image_tag}"
      essential = true
      portMappings = [
        {
          containerPort = 3000 # Puerto que expone tu app DENTRO del contenedor
          hostPort      = 3000 # Relevante para EC2, pero Fargate lo ignora
          protocol      = "tcp"
        }
      ]
      # Asegúrate que estos valores coincidan o sean menores que los definidos a nivel de tarea
      memory = var.ecs_task_memory # Se puede definir límites por contenedor también
      cpu    = var.ecs_task_cpu

      # Inyectar el secreto como variable de entorno
      secrets = [
        {
          name      = "MONGODB_URI" # Nombre de la variable de entorno en el contenedor
          valueFrom = aws_secretsmanager_secret.mongodb_uri.arn
        }
      ]

      # Configuración de logs
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.ecs_log_group.name # Referencia al grupo creado
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "ecs" # Prefijo para las secuencias de logs (ecs/<container-name>/<task-id>)
        }
      }
      # Considera añadir environment variables adicionales si tu app las necesita
      # environment = [
      #   { name = "NODE_ENV", value = var.environment },
      #   { name = "OTHER_VAR", value = "some_value" }
      # ]
    }
  ])

  tags = merge(local.common_tags, {
    Name       = "${local.name_prefix}-task_definition"
    GitVersion = var.git_version_tag # Etiqueta pasada desde GHA
  })
}

# ECS Cluster
resource "aws_ecs_cluster" "cluster" {
  name = "${local.name_prefix}-cluster"

  # Habilitar Container Insights para métricas detalladas (opcional, tiene costo)
  # setting {
  #   name  = "containerInsights"
  #   value = "enabled"
  # }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-cluster"
  })
}

# Security Group para las tareas ECS
resource "aws_security_group" "ecs_sg" {
  name        = "${local.name_prefix}-ecs-sg"
  description = "Allow traffic from ALB to ECS tasks"
  vpc_id      = aws_vpc.vpc.id

  # Permitir tráfico entrante SOLO desde el Security Group del ALB en el puerto 3000
  ingress {
    from_port       = 3000 # Puerto del contenedor
    to_port         = 3000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id] # ¡MUY IMPORTANTE! Solo el ALB puede entrar
  }
  # El tráfico saliente usará el IGW de las subredes públicas
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-ecs-sg"
  })
}

# ECS Service
resource "aws_ecs_service" "service" {
  name            = "${local.name_prefix}-service"
  cluster         = aws_ecs_cluster.cluster.id
  task_definition = aws_ecs_task_definition.task_definition.arn # Usa la última revisión
  desired_count   = var.ecs_service_desired_count               # Usa una variable, ej. 1 o 2 para HA

  launch_type = "FARGATE"

  # Configuración de red para Fargate
  network_configuration {
    # Las tareas necesitan este SG para comunicarse y ser alcanzadas por el ALB
    security_groups = [aws_security_group.ecs_sg.id]
    # Usa las subredes públicas creadas
    subnets = [for s in aws_subnet.subnets : s.id]
    # CRÍTICO: Asignar IP pública para que las tareas en subredes públicas
    # puedan usar el IGW para acceder a ECR, Secrets Manager, etc.
    assign_public_ip = true
  }

  # Conectar el servicio con el ALB
  load_balancer {
    target_group_arn = aws_lb_target_group.tg.arn
    container_name   = "${local.name_prefix}-container" # Debe coincidir con el 'name' en container_definitions
    container_port   = 3000                             # Debe coincidir con 'containerPort' en container_definitions
  }

  # Asegura que el servicio espere a que el ALB esté listo
  depends_on = [aws_lb_listener.https_listener]

  # Opciones de despliegue (rolling update es el predeterminado)
  # deployment_controller {
  #   type = "ECS" # vs CODE_DEPLOY
  # }

  # Considera configurar el Circuit Breaker para despliegues más seguros
  # deployment_circuit_breaker {
  #   enable   = true
  #   rollback = true
  # }

  # Esperar a que el despliegue se estabilice antes de marcar el 'apply' como completado
  wait_for_steady_state = true

  tags = merge(local.common_tags, {
    Name       = "${local.name_prefix}-service"
    GitVersion = var.git_version_tag # Etiqueta pasada desde GHA
  })
}

# =========================================
# Certificate Manager (ACM) & Route 53
# =========================================

# Descomenta y usa 'data' si el certificado YA EXISTE y está VALIDADO en ACM
# data "aws_acm_certificate" "cert" {
#   domain   = var.domain_name
#   statuses = ["ISSUED"] # Asegura que solo coja certificados válidos
#   most_recent = true     # Coge el más reciente si hay varios
# }

# Usa 'resource' para solicitar un NUEVO certificado
resource "aws_acm_certificate" "cert" {
  # count = var.acm_certificate_arn == null ? 1 : 0 # Descomenta si usas la variable opcional de arriba
  domain_name       = var.domain_name
  validation_method = "DNS" # O "EMAIL" si prefieres validación por email

  # Añade SANs (Subject Alternative Names) si necesitas cubrir subdominios como www
  # subject_alternative_names = ["www.${var.domain_name}"]

  tags = merge(local.common_tags, {
    Name = "${var.domain_name}-certificate"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# NOTA IMPORTANTE SOBRE LA VALIDACIÓN:
# Si usas validation_method = "DNS", después del 'terraform apply' inicial,
# tendrás que ir a la consola de ACM o usar la AWS CLI para obtener los registros
# CNAME que necesitas añadir a tu proveedor de DNS para validar el dominio.
# Terraform NO completará el 'apply' del listener HTTPS hasta que el certificado
# tenga el estado 'ISSUED'.
#
# Para automatizar la validación DNS con Terraform, necesitarías:
# 1. Que tu zona DNS esté gestionada en AWS Route 53.
# 2. Usar los recursos 'aws_route53_record' y 'aws_acm_certificate_validation'.
# Esto está fuera del alcance de esta modificación básica, pero es la forma recomendada
# para una automatización completa.

data "aws_route53_zone" "zone" {
  # Asegúrate de que el nombre coincida EXACTAMENTE con tu zona en Route 53
  # incluyendo el punto al final.
  name         = var.route53_zone_name
  private_zone = false
}

resource "aws_route53_record" "app_dns" {
  zone_id = data.aws_route53_zone.zone.zone_id # Usa el data source de tu zona
  name    = var.domain_name                    # Debe ser algo como 'api.midominio.com' en donde midominio.com corresponde a la route53_zone_name
  type    = "A"                                # Registro tipo A para IPv4

  alias {
    name                   = aws_alb.alb.dns_name               # DNS name del ALB
    zone_id                = aws_alb.alb.zone_id                # Zone ID del ALB
    evaluate_target_health = true                               # Recomendado: Route 53 comprueba la salud del ALB
  }
}

# Opcional: Si también quieres soportar IPv6 (requiere que el ALB tenga dualstack habilitado, que es el default)
resource "aws_route53_record" "app_dns_ipv6" {
  zone_id = data.aws_route53_zone.zone.zone_id
  name    = var.domain_name
  type    = "AAAA" # Registro tipo AAAA para IPv6

  alias {
    name                   = aws_alb.alb.dns_name
    zone_id                = aws_alb.alb.zone_id
    evaluate_target_health = true
  }
}

# Crea los registros DNS necesarios para la validación
resource "aws_route53_record" "cert_validation" {
  # Necesitamos un registro por cada dominio a validar (principal + SANs)
  # Usamos for_each sobre las opciones de validación que provee el certificado
  for_each = {
    for dvo in aws_acm_certificate.cert.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true # Permite sobrescribir registros CNAME preexistentes si es necesario
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60 # TTL bajo para validación rápida
  type            = each.value.type
  zone_id         = data.aws_route53_zone.zone.zone_id # ID de tu zona hospedada
}

# Este recurso ESPERA hasta que AWS confirme que la validación DNS tuvo éxito
resource "aws_acm_certificate_validation" "cert_validation_wait" {
  certificate_arn         = aws_acm_certificate.cert.arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]

  # Puedes ajustar el tiempo de espera si es necesario
  # timeouts {
  #   create = "15m"
  # }
}

# =========================================
# Outputs
# =========================================
output "alb_app_url" {
  description = "URL pública del Application Load Balancer"
  value       = aws_alb.alb.dns_name
}

output "app_url" {
  description = "URL pública HTTPS de la aplicación"
  value       = "https://${var.domain_name}"
}

output "ecr_repository_url" {
  description = "URL del repositorio ECR"
  value       = aws_ecr_repository.ecr_repository.repository_url
}

output "cloudwatch_log_group_name" {
  description = "Nombre del grupo de logs de CloudWatch para las tareas ECS"
  value       = aws_cloudwatch_log_group.ecs_log_group.name
}
