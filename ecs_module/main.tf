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

# Subredes PÚBLICAS en cada AZ disponible
resource "aws_subnet" "subnets" {
  # count                 = 3 # Considera usar length(data.aws_availability_zones.available.names) si se quiere usar todas las AZs disponibles
  count                   = length(data.aws_availability_zones.available.names)
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = cidrsubnet(aws_vpc.vpc.cidr_block, 8, count.index)
  map_public_ip_on_launch = true
  availability_zone       = element(data.aws_availability_zones.available.names, count.index)

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

# --- Política para leer el secreto de CREDENCIALES de MongoDB ---
resource "aws_iam_policy" "mongodb_credentials_allow_read" {
  name        = "${local.name_prefix}-mongodb_credentials_allow_read"
  description = "Permite leer el secreto de credenciales de MongoDB (para la tarea Mongo)"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
        Effect   = "Allow"
        Resource = aws_secretsmanager_secret.mongodb_credentials.arn #secreto
      }
    ]
  })
  tags = merge(local.common_tags, { Name = "${local.name_prefix}-mongodb_credentials_allow_read" })
}

# --- Adjuntar la política de lectura del secreto de CREDENCIALES al rol de ejecución ---
resource "aws_iam_role_policy_attachment" "attach_mongodb_credentials_allow_read" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = aws_iam_policy.mongodb_credentials_allow_read.arn
}

# ... (aws_iam_role.ecs_task_role se mantiene igual) ...
# Nota: Si tu aplicación necesita permisos específicos para interactuar con MongoDB
# (más allá de la conexión inicial), deberías añadirlos al 'ecs_task_role'.
# Normalmente, la autenticación se maneja a nivel de driver/conexión.

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
  subnets            = aws_subnet.subnets.*.id
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

# USAR PARA PROD
# resource "aws_secretsmanager_secret_version" "mongodb_uri_version" {
#   secret_id = aws_secretsmanager_secret.mongodb_uri.id
#   # ¡URI SIN CREDENCIALES! La aplicación las obtendrá por separado.
#   # Ajusta el nombre de la base de datos ('mydatabase') y otras opciones según necesites.
#   # Nota: No usamos SSL aquí para la conexión interna, puedes añadir ?ssl=true si configuras TLS en el contenedor Mongo.
#   secret_string = format(
#     "mongodb://%s.%s:%d/mydatabase?retryWrites=true&w=majority",
#     aws_service_discovery_service.mongodb_discovery_service.name, # "mongodb"
#     aws_service_discovery_private_dns_namespace.private_dns.name, # "service.local"
#     27017                                                          # Puerto
#   )

#   lifecycle {
#     ignore_changes = [secret_string]
#   }
#   depends_on = [aws_service_discovery_service.mongodb_discovery_service]
# }

# === ¡ALTERNATIVA SIMPLE PERO INSEGURA PARA DEV! ===
# NO USAR EN PRODUCCIÓN

# Necesitarías obtener el valor del secreto de credenciales usando un data source
# ¡ADVERTENCIA! Esto puede causar problemas de dependencia cíclica o exponer el secreto
# en planes si no se maneja con cuidado.
data "aws_secretsmanager_secret_version" "mongo_creds_value" {
  secret_id = aws_secretsmanager_secret.mongodb_credentials.id
  depends_on = [aws_secretsmanager_secret_version.mongodb_credentials_version]
}

resource "aws_secretsmanager_secret_version" "mongodb_uri_version_INSECURE" {
  secret_id = aws_secretsmanager_secret.mongodb_uri.id

  # Decodificar el JSON del secreto de credenciales
  # local_creds = jsondecode(data.aws_secretsmanager_secret_version.mongo_creds_value.secret_string)

  # ¡URI COMPLETA CON CREDENCIALES EN TEXTO PLANO EN ESTE SECRETO!
  secret_string = format(
    "mongodb://%s:%s@%s.%s:%d/mydatabase?retryWrites=true&w=majority",
    var.mongodb_root_username, # ¡Usando la variable directamente!
    var.mongodb_root_password, # ¡Usando la variable directamente! ¡PELIGRO!
    aws_service_discovery_service.mongodb_discovery_service.name,
    aws_service_discovery_private_dns_namespace.private_dns.name,
    27017
 )

  lifecycle {
    ignore_changes = [secret_string]
  }
  depends_on = [
    aws_service_discovery_service.mongodb_discovery_service,
    # data.aws_secretsmanager_secret_version.mongo_creds_value # Dependencia explícita
  ]
}
# --- FIN DE ALTERNATIVA INSEGURA ---

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
        # USAR PARA PROD
        # # El ARN de la URI (que ahora solo contendrá el host y opciones, sin credenciales)
        # {
        #   name      = "MONGODB_URI_TEMPLATE" # Nuevo nombre, ej. mongodb://mongodb.service.local:27017/mydb?ssl=false
        #   valueFrom = aws_secretsmanager_secret.mongodb_uri.arn
        # },
        # # El ARN del secreto con las credenciales
        # {
        #   name      = "MONGODB_CREDENTIALS_SECRET_ARN"
        #   valueFrom = aws_secretsmanager_secret.mongodb_credentials.arn
        # },
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
    subnets = aws_subnet.subnets.*.id
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
  depends_on = [
    aws_lb_listener.https_listener,
    aws_ecs_service.mongodb_service # Asegura que Mongo se intente crear/estabilizar primero
  ]

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
# Secrets Manager (MongoDB Credentials)
# =========================================
resource "aws_secretsmanager_secret" "mongodb_credentials" {
  name        = "${local.name_prefix}-mongodb-credentials"
  description = "Root credentials for the internal MongoDB instance on ECS for ${local.name_prefix}"
  recovery_window_in_days = 0 # Descomenta si NO quieres recuperación

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-mongodb-credentials"
  })
}

resource "aws_secretsmanager_secret_version" "mongodb_credentials_version" {
  secret_id = aws_secretsmanager_secret.mongodb_credentials.id
  # Almacena las credenciales como un JSON simple
  secret_string = jsonencode({
    username = var.mongodb_root_username
    password = var.mongodb_root_password # Pasado de forma segura
  })

  lifecycle {
    # Evita que Terraform detecte cambios si el secreto se actualiza externamente
    # (ej. si implementas rotación de contraseñas más adelante)
    ignore_changes = [secret_string]
  }
}

# =========================================
# Service Discovery (Cloud Map)
# =========================================
resource "aws_service_discovery_private_dns_namespace" "private_dns" {
  name        = var.service_discovery_namespace # ej. "service.local"
  description = "Private DNS namespace for microservices in ${local.name_prefix}"
  vpc         = aws_vpc.vpc.id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-private-dns"
  })
}

# =========================================
# MongoDB Security Group
# =========================================
resource "aws_security_group" "mongodb_sg" {
  name        = "${local.name_prefix}-mongodb-internal-sg"
  description = "Allow MongoDB inbound traffic ONLY from App ECS tasks"
  vpc_id      = aws_vpc.vpc.id

  # Permitir tráfico entrante SOLO desde el Security Group de las tareas de la APLICACIÓN
  # en el puerto por defecto de MongoDB (27017)
  ingress {
    description     = "Allow inbound from App ECS tasks"
    from_port       = 27017
    to_port         = 27017
    protocol        = "tcp"
    # ¡IMPORTANTE! Referencia cruzada al SG de tu aplicación existente
    security_groups = [aws_security_group.ecs_sg.id]
  }

  # Permite toda la salida (necesario para que Mongo se comunique internamente si es un clúster,
  # y para que el agente ECS funcione correctamente)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-mongodb-sg"
  })
}

# =========================================
# MongoDB on ECS (Task Definition & Service)
# =========================================

# --- Definición de Tarea para MongoDB ---
resource "aws_ecs_task_definition" "mongodb_task_definition" {
  family                   = "${local.name_prefix}-mongodb-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.mongodb_ecs_cpu
  memory                   = var.mongodb_ecs_memory
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn # Necesita acceso a Secrets Manager
  # task_role_arn            = aws_iam_role.ecs_task_role.arn # Opcional: si mongo necesitara otros permisos AWS

  # --- ¡IMPORTANTE! Persistencia ---
  # Para persistencia en Fargate, necesitarías definir un volumen aquí
  # y configurarlo en container_definitions. EFS es lo más común.
  # Ejemplo conceptual con EFS (requiere crear EFS File System y Access Point):
  # volume {
  #   name = "mongodb-data"
  #   efs_volume_configuration {
  #     file_system_id          = aws_efs_file_system.mongodb_efs.id
  #     transit_encryption      = "ENABLED"
  #     authorization_config {
  #        access_point_id = aws_efs_access_point.mongodb_ap.id
  #        iam = "ENABLED" # Requires task_role_arn with EFS permissions
  #     }
  #   }
  # }

  container_definitions = jsonencode([
    {
      name      = "${local.name_prefix}-mongodb-container"
      image     = "mongo:latest" # O una versión específica como "mongo:6.0"
      essential = true
      portMappings = [
        {
          containerPort = 27017
          protocol      = "tcp"
        }
      ]
      # CPU/Memory a nivel de contenedor (opcional si ya está en la tarea)
      # memory = var.mongodb_ecs_memory
      # cpu    = var.mongodb_ecs_cpu

      # Inyectar las credenciales root desde el NUEVO secreto
      secrets = [
        {
          name      = "MONGO_INITDB_ROOT_USERNAME" # Variable de entorno esperada por la imagen oficial de Mongo
          valueFrom = "${aws_secretsmanager_secret.mongodb_credentials.arn}:username::" # Extrae 'username' del JSON
        },
        {
          name      = "MONGO_INITDB_ROOT_PASSWORD" # Variable de entorno esperada por la imagen oficial de Mongo
          valueFrom = "${aws_secretsmanager_secret.mongodb_credentials.arn}:password::" # Extrae 'password' del JSON
        }
      ]

      # --- ¡IMPORTANTE! Montaje de Volumen para Persistencia ---
      # Si defines un volumen arriba, móntalo aquí:
      # mountPoints = [
      #   {
      #     sourceVolume  = "mongodb-data"
      #     containerPath = "/data/db" # Directorio estándar de datos de MongoDB
      #     readOnly      = false
      #   }
      # ]

      # Configuración de logs (igual que tu app, pero quizás un stream diferente)
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.ecs_log_group.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "mongodb" # Prefijo diferente para logs de mongo
        }
      }
      # Asegura que el contenedor no se inicie hasta que la red y los secretos estén listos
      # dependsOn = [] # Podrías añadir dependencias si es necesario
      # healthCheck = { ... } # Considera añadir un health check específico para Mongo
    }
  ])

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-mongodb-task_definition"
  })
}

# --- Servicio ECS para MongoDB ---
resource "aws_ecs_service" "mongodb_service" {
  name            = "${local.name_prefix}-mongodb-service"
  cluster         = aws_ecs_cluster.cluster.id
  task_definition = aws_ecs_task_definition.mongodb_task_definition.arn
  desired_count   = 1 # Solo una instancia para dev sin replicación
  launch_type     = "FARGATE"

  network_configuration {
    # Usa las mismas subredes que tu aplicación (idealmente deberían ser privadas)
    subnets = aws_subnet.subnets.*.id
    # Asigna el grupo de seguridad específico de MongoDB
    security_groups = [aws_security_group.mongodb_sg.id]

    # # MongoDB NO necesita IP pública
    # assign_public_ip = false

    # CAMBIO AQUÍ: Permitir IP pública para que pueda usar el IGW en la subred pública
    # Solución simple y temporal. Arreglo rápido, requiere mínimo cambio en el código
    # Expone la interfaz de red de la base de datos a internet (aunque el Security Group mongodb_sg
    # debería seguir restringiendo el acceso solo desde el SG de tu aplicación). No es la práctica
    # recomendada para bases de datos.
    assign_public_ip = true
  }

  # Registrar el servicio en Cloud Map para descubrimiento
  service_registries {
    registry_arn = aws_service_discovery_service.mongodb_discovery_service.arn
    # port = 27017 # No necesario para DNS discovery type A
  }

  # Opciones de despliegue (rolling update es el predeterminado)
  deployment_controller {
    type = "ECS"
  }

  # Podrías añadir Circuit Breaker aquí también
  # deployment_circuit_breaker { ... }

  # Esperar a que el servicio se estabilice
  wait_for_steady_state = true

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-mongodb-service"
  })

  # Asegúrate de que el namespace exista antes de crear el servicio
  depends_on = [aws_service_discovery_private_dns_namespace.private_dns]
}

# --- Recurso de Service Discovery específico para MongoDB ---
resource "aws_service_discovery_service" "mongodb_discovery_service" {
  name = "mongodb" # El servicio será descubrible como 'mongodb.service.local'

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.private_dns.id
    # Crea registros A que apuntan a las IPs de las tareas
    dns_records {
      ttl  = 10 # TTL bajo para cambios rápidos en dev
      type = "A"
    }
    routing_policy = "MULTIVALUE" # O "WEIGHTED" si tienes varias instancias
  }

  # Health check opcional gestionado por Cloud Map (alternativa al health check de ECS/ALB)
  # health_check_custom_config {
  #   failure_threshold = 1
  # }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-mongodb-discovery"
  })
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

output "mongodb_service_discovery_name" {
  description = "Internal DNS name for the MongoDB service within the VPC"
  value       = format("%s.%s", aws_service_discovery_service.mongodb_discovery_service.name, aws_service_discovery_private_dns_namespace.private_dns.name)
}

output "mongodb_credentials_secret_arn" {
  description = "ARN of the Secrets Manager secret holding MongoDB credentials"
  value       = aws_secretsmanager_secret.mongodb_credentials.arn
  sensitive   = true
}