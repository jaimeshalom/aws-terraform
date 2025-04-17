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

# project network

resource "aws_vpc" "vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-vpc"
  })
}

resource "aws_subnet" "subnets" {
  count                   = 3
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = cidrsubnet(aws_vpc.vpc.cidr_block, 8, count.index)
  map_public_ip_on_launch = true
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

# IAM

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

resource "aws_iam_role_policy_attachment" "ecs_task_execution_role_policy" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

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

// ALB
resource "aws_security_group" "alb_sg" {
  name        = "${local.name_prefix}-alb_sg"
  description = "Allow inbound access to the ECS tasks from the ALB"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-alb_sg"
  })
}

resource "aws_alb" "alb" {
  name               = "${local.name_prefix}-alb"
  load_balancer_type = "application"
  internal           = false

  subnets = aws_subnet.subnets.*.id

  security_groups = [aws_security_group.alb_sg.id]

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-alb"
  })
}

resource "aws_lb_target_group" "tg" {
  name        = "${local.name_prefix}-tg"
  port        = 3000
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.vpc.id

  health_check {
    path     = "/"
    port     = "traffic-port"
    protocol = "HTTP"
    matcher  = "200-299"
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-tg"
  })
}

resource "aws_lb_listener" "lb_listener" {
  load_balancer_arn = aws_alb.alb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tg.arn
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-lb_listener"
  })
}


// ECR
resource "aws_ecr_repository" "ecr_repository" {
  name                 = "${local.name_prefix}-ecr_repository"
  image_tag_mutability = "IMMUTABLE"

  encryption_configuration {
    encryption_type = "KMS"
  }

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-ecr_repository"
  })
}

// MongoDB Secret
resource "aws_secretsmanager_secret" "mongodb_uri" {
  name                    = "${local.name_prefix}-mongodb_uri"
  description             = "Cadena de conexión a MongoDB para ${local.name_prefix}"
  recovery_window_in_days = 0 # Eliminación inmediata sin período de recuperación


  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-mongodb_uri"
  })
}

resource "aws_secretsmanager_secret_version" "mongodb_uri_version" {
  secret_id     = aws_secretsmanager_secret.mongodb_uri.id
  secret_string = var.mongodb_uri
}

resource "aws_iam_policy" "mongodb_uri_allow_read" {
  name        = "${local.name_prefix}-mongodb_uri_allow_read"
  description = "Política para acceder a MongoDB"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",
          "secretsmanager:ListSecretVersionIds"
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

resource "aws_iam_policy_attachment" "attach_mongodb_uri_allow_read" {
  name       = "${local.name_prefix}-attach_mongodb_uri_allow_read"
  roles      = [aws_iam_role.ecs_task_execution_role.name]
  policy_arn = aws_iam_policy.mongodb_uri_allow_read.arn
}

// ECS Task Definition
resource "aws_cloudwatch_log_group" "ecs_log_group" {
  name = "/ecs/${local.name_prefix}"

  retention_in_days = 14

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-ecs_log_group"
  })
}

resource "aws_ecs_task_definition" "task_definition" {
  family                   = "${local.name_prefix}-task_definition"
  network_mode             = "awsvpc" # add the AWS VPN network mode as this is required for Fargate
  memory                   = 512      # Specify the memory the container requires
  cpu                      = 256      # Specify the CPU the container requires
  requires_compatibilities = ["FARGATE"]
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_role.arn

  container_definitions = jsonencode([
    {
      name      = "${local.name_prefix}-container"
      image     = "${aws_ecr_repository.ecr_repository.repository_url}:${var.ecr_image_tag}"
      essential = true
      portMappings = [
        {
          containerPort = 3000
          hostPort      = 3000
        }
      ],
      memory = 512,
      cpu    = 256

      secrets = [
        {
          name      = "MONGODB_URI"
          valueFrom = aws_secretsmanager_secret.mongodb_uri.arn
        }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.ecs_log_group.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "ecs"
        }
      }
    }
  ])

  tags = merge(local.common_tags, {
    Name       = "${local.name_prefix}-task_definition"
    GitVersion = var.git_version_tag
  })
}

// ECS Cluster
resource "aws_ecs_cluster" "cluster" {
  name = "${local.name_prefix}-cluster"

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-cluster"
  })
}

// ECS SG
resource "aws_security_group" "ecs_sg" {
  name        = "${local.name_prefix}-ecs_sg"
  description = "Allow inbound access to the ALB from the ECS tasks"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    # Only allowing traffic in from the load balancer security group
    security_groups = [aws_security_group.alb_sg.id]
  }
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

// ECS Service
resource "aws_ecs_service" "service" {
  name            = "${local.name_prefix}-service"
  cluster         = aws_ecs_cluster.cluster.id
  task_definition = aws_ecs_task_definition.task_definition.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    security_groups = [aws_security_group.ecs_sg.id]
    subnets         = aws_subnet.subnets.*.id
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.tg.arn
    container_name   = "${local.name_prefix}-container"
    container_port   = 3000
  }

  tags = merge(local.common_tags, {
    Name       = "${local.name_prefix}-service"
    GitVersion = var.git_version_tag
  })
}

#Log the load balancer app URL
output "app_url" {
  value = aws_alb.alb.dns_name
}
