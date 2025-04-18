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
}

# =========================================
# Project Network
# =========================================

resource "aws_vpc" "vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-vpc"
  })
}

resource "aws_subnet" "subnets" {
  # count                 = 3 # Considera usar length(data.aws_availability_zones.available.names) si se quiere usar todas las AZs disponibles
  count                   = length(data.aws_availability_zones.available.names)
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = cidrsubnet(aws_vpc.vpc.cidr_block, 8, count.index)
  map_public_ip_on_launch = true # Las tareas Fargate necesitarán acceso a internet o VPC endpoints
  availability_zone       = element(data.aws_availability_zones.available.names, count.index)

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-public_subnet-${count.index}"
  })
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-igw"
  })
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-public_rt"
  })
}

resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.subnets)
  subnet_id      = aws_subnet.subnets[count.index].id
  route_table_id = aws_route_table.public.id
}

# --- VPC Endpoints ---
# Security Group para los Endpoints de Interfaz
resource "aws_security_group" "vpc_endpoint_sg" {
  name        = "${local.name_prefix}-vpc-endpoint-sg"
  description = "Allow TLS traffic to VPC endpoints from within the VPC"
  vpc_id      = aws_vpc.vpc.id

  # Permitir tráfico HTTPS ENTRANTE desde la VPC hacia el endpoint
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.vpc.cidr_block] # Permite desde cualquier IP dentro de la VPC
  }

  # Permitir TODO el tráfico SALIENTE desde los endpoints
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-vpc-endpoint-sg"
  })
}

# Endpoint de INTERFAZ para Secrets Manager
resource "aws_vpc_endpoint" "secrets_manager" {
  vpc_id              = aws_vpc.vpc.id
  service_name        = "com.amazonaws.${var.aws_region}.secretsmanager"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true

  subnet_ids = aws_subnet.subnets.*.id

  security_group_ids = [
    aws_security_group.vpc_endpoint_sg.id,
  ]

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-secretsmanager-vpce"
  })
}

# Endpoint de INTERFAZ para ECR API
resource "aws_vpc_endpoint" "ecr_api" {
  vpc_id              = aws_vpc.vpc.id
  service_name        = "com.amazonaws.${var.aws_region}.ecr.api"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true

  subnet_ids = aws_subnet.subnets.*.id

  security_group_ids = [
    aws_security_group.vpc_endpoint_sg.id,
  ]

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-ecr-api-vpce"
  })
}

# Endpoint de INTERFAZ para ECR Docker Registry
resource "aws_vpc_endpoint" "ecr_dkr" {
  vpc_id              = aws_vpc.vpc.id
  service_name        = "com.amazonaws.${var.aws_region}.ecr.dkr"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = false

  subnet_ids = aws_subnet.subnets.*.id

  security_group_ids = [
    aws_security_group.vpc_endpoint_sg.id,
  ]

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-ecr-dkr-vpce"
  })
}

# Endpoint de INTERFAZ para CloudWatch Logs
resource "aws_vpc_endpoint" "logs" {
  vpc_id              = aws_vpc.vpc.id
  service_name        = "com.amazonaws.${var.aws_region}.logs"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true

  subnet_ids = aws_subnet.subnets.*.id

  security_group_ids = [
    aws_security_group.vpc_endpoint_sg.id,
  ]

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-logs-vpce"
  })
}

# Endpoint de GATEWAY para S3 (Requerido por ECR)
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.vpc.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"

  # Asociar con las tablas de rutas de las subredes donde se ejecutarán las tareas
  route_table_ids = [aws_route_table.public.id]

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-s3-vpce"
  })
}


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
  name        = "${local.name_prefix}-alb_sg"
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
    Name = "${local.name_prefix}-alb_sg"
  })
}

resource "aws_alb" "alb" {
  name               = "${local.name_prefix}-alb"
  load_balancer_type = "application"
  internal           = false

  subnets = aws_subnet.subnets.*.id # El ALB necesita estar en subredes públicas para ser accesible desde internet

  security_groups = [aws_security_group.alb_sg.id]

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-alb"
  })
}

resource "aws_lb_target_group" "tg" {
  name        = "${local.name_prefix}-tg"
  port        = 3000 # Puerto donde escucha tu contenedor ECS
  protocol    = "HTTP"
  target_type = "ip" # Requerido para Fargate con awsvpc
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
    Name = "${local.name_prefix}-http_listener_redirect"
  })
}

resource "aws_lb_listener" "https_listener" {
  load_balancer_arn = aws_alb.alb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08" # Política de seguridad TLS recomendada
  certificate_arn   = aws_acm_certificate.cert.arn # Usa el ARN del certificado creado/referenciado
  # Si se uso la variable opcional acm_certificate_arn:
  # certificate_arn = var.acm_certificate_arn != null ? var.acm_certificate_arn : aws_acm_certificate.cert[0].arn

  # La acción por defecto es enviar el tráfico al Target Group
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tg.arn
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-https_listener"
  })

  # Asegura que el listener HTTP (que ahora depende del https para la redirección implícita)
  # y el certificado estén listos.
  # La dependencia del certificado es implícita por usar su ARN.
  depends_on = [aws_lb_listener.http_listener_redirect] # Asegura que el listener http exista
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

  retention_in_days = 14 # Ajusta según necesidad

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-ecs-log-group" # Etiqueta actualizada
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
      image     = "${aws_ecr_repository.ecr_repository.repository_url}:${var.ecr_image_tag}"
      essential = true
      portMappings = [
        {
          containerPort = 3000 # Puerto que expone tu app DENTRO del contenedor
          hostPort      = 3000 # Relevante para EC2, pero Fargate lo ignora
          protocol      = "tcp"
        }
      ]
      # Asegúrate que estos valores coincidan o sean menores que los definidos a nivel de tarea
      memory = var.ecs_task_memory # Puedes definir límites por contenedor también
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
  name        = "${local.name_prefix}-ecs_sg"
  description = "Allow traffic from ALB to ECS tasks"
  vpc_id      = aws_vpc.vpc.id

  # Permitir tráfico entrante SOLO desde el Security Group del ALB en el puerto 3000
  ingress {
    from_port       = 3000 # Puerto de tu contenedor
    to_port         = 3000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id] # ¡MUY IMPORTANTE! Solo el ALB puede entrar
  }
  # Permitir TODO el tráfico saliente (necesario para VPC Endpoints, ECR, Mongo (si es externo), etc.)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-ecs_sg"
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
    # Especifica las subredes donde se lanzarán las tareas
    subnets = aws_subnet.subnets.*.id
    # 'assign_public_ip = true' es necesario si usas subredes públicas y NO tienes NAT Gateway
    # pero SÍ tienes IGW y necesitas acceso saliente a internet (además de endpoints).
    # Si usas subredes privadas + NAT Gateway, esto sería 'false'.
    # Si SOLO usas VPC Endpoints para TODO, podría ser 'false'.
    assign_public_ip = true # Requerido para que Fargate descargue la imagen/hable con servicios si no hay NAT y los endpoints no cubren todo
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
# Certificate Manager (ACM)
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
    create_before_destroy = true # Útil para rotación de certificados si se gestiona con Terraform
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
