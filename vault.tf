# Vault Storage Bucket
resource "aws_s3_bucket" "vault" {
  bucket_prefix = "vault-vgh-"
  acl           = "private"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }

  tags = var.common_tags
}

resource "aws_s3_bucket_policy" "vault" {
  bucket = aws_s3_bucket.vault.id
  policy = data.aws_iam_policy_document.vault_s3.json
}

data "aws_iam_policy_document" "vault_s3" {
  statement {
    sid       = "DenyUnEncryptedInflightOperations"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["arn:aws:s3:::${aws_s3_bucket.vault.id}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = [false]
    }
  }

  statement {
    sid       = "DenyUnEncryptedObjectUploads"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["arn:aws:s3:::${aws_s3_bucket.vault.id}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["true"]
    }
  }

  statement {
    sid       = "DenyIncorrectEncryptionHeader"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["arn:aws:s3:::${aws_s3_bucket.vault.id}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["AES256", "aws:kms"]
    }
  }
}

# Vault HA DynamoDB table
resource "aws_dynamodb_table" "vault" {
  name           = "vault"
  read_capacity  = 5
  write_capacity = 5
  hash_key       = "Path"
  range_key      = "Key"

  server_side_encryption {
    enabled = true
  }

  attribute {
    name = "Path"
    type = "S"
  }

  attribute {
    name = "Key"
    type = "S"
  }

  tags = merge(
    var.common_tags,
    {
      "Name" = "Vault"
    },
  )
}

# Vault Instance Security Group
resource "aws_security_group" "vault" {
  name        = "Vault"
  description = " Vault Security Group"
  vpc_id      = module.vpc.vpc_id

  tags = var.common_tags
}

resource "aws_security_group_rule" "vault_ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  security_group_id = aws_security_group.vault.id
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "vault_server" {
  type              = "ingress"
  from_port         = 8200
  to_port           = 8200
  protocol          = "tcp"
  security_group_id = aws_security_group.vault.id
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "vault_monitoring" {
  type              = "ingress"
  from_port         = 9100
  to_port           = 9100
  protocol          = "tcp"
  security_group_id = aws_security_group.vault.id
  cidr_blocks       = ["${var.monitoring_ip}/32"]
}

resource "aws_security_group_rule" "vault_self" {
  type                     = "ingress"
  from_port                = 0
  to_port                  = 0
  protocol                 = "-1"
  security_group_id        = aws_security_group.vault.id
  source_security_group_id = aws_security_group.vault.id
}

resource "aws_security_group_rule" "vault_egress" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  security_group_id = aws_security_group.vault.id
  cidr_blocks       = ["0.0.0.0/0"]
}

# Vault Instance Role
resource "aws_iam_instance_profile" "vault" {
  name = "vault"
  role = aws_iam_role.vault.name
}

resource "aws_iam_role" "vault" {
  name               = "vault"
  description        = "Vault"
  assume_role_policy = data.aws_iam_policy_document.vault_trust.json
}

data "aws_iam_policy_document" "vault_trust" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "vault" {
  name   = "vault"
  role   = aws_iam_role.vault.name
  policy = data.aws_iam_policy_document.vault_role.json
}

data "aws_iam_policy_document" "vault_role" {
  statement {
    sid       = "AllowAssumeRole"
    actions   = ["sts:AssumeRole"]
    resources = ["*"]
  }

  # Used by the AWS authentication backend
  statement {
    sid = "AllowIAMAuth"

    actions = [
      "ec2:DescribeInstances",
      "iam:GetInstanceProfile",
      "iam:GetUser",
      "iam:GetRole",
      "sts:GetCallerIdentity",
    ]

    resources = ["*"]
  }

  statement {
    sid = "AllowLogging"

    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams",
    ]

    resources = ["arn:aws:logs:*:*:*"]
  }

  statement {
    sid       = "AllowS3ListAllBuckets"
    actions   = ["s3:ListAllMyBuckets"]
    resources = ["*"]
  }

  statement {
    sid     = "AllowS3AccessToAssetsBucket"
    actions = ["*"]

    resources = [
      "arn:aws:s3:::${aws_s3_bucket.vault.id}",
      "arn:aws:s3:::${aws_s3_bucket.vault.id}/*",
    ]
  }

  statement {
    sid = "AllowKMSUse"

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]

    resources = ["arn:aws:kms:*:*:alias/aws/s3"]
  }
}

resource "aws_iam_role_policy_attachment" "vault_dynamodb" {
  role       = aws_iam_role.vault.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess"
}

# SSH
resource "aws_key_pair" "vgh" {
  key_name   = "vgh"
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAEAQCuW/klOclhy5P4ipa24ISqChtLrDsNOO/mSkmavq5ypE8LR9ZP2Y9o52LYZ+Cp3QTYO46qIt4ubTEnWHjaCoY82P2zyFn7S4X16NvKLnjRCV4T5U0O2MM8ZlQbQqZPvuzsNI64yMUWOlVKXGohWFctCxafQWzcFebctARf50armUPF9A7hKm0qYa6aEWl1/dtMs8JVP3+bhZ0AlhkbLNiOSvT63I9Yakc11bedmtY07nSVOa1bWgHuGogdbexqLeaKLj6xCQKKM1iM7uaxXZyJGXTXrFV+VomnWZ3WKRaGRU9ctf+ki3nJJpEphTQsir6Dvg/qXL6fOW1pU2vd5XgV60FVd6kvFzy5yMzZfRMrwgG4241BGtOrnNGJEqo/9HGSNv9xX7Mm0mqX57rdIagZPwGaOk930dI0osYuyv09o0tqzwtJByEQ8rzhHHVu1L1l7SrhcfGq2ocjyyuZ33AY4aIY3JaretsfyahhleHCXwJUSJS3NDob8sqg/h5OBEnWLEcWBUm5+L1EeK332LM9tBwxrqFu5h6FwUuUeg3GtmREbgAKfA8ZvUwN4bl/nGzxrwjBjC+Y1ceaU30IrcbxEl6KdmO2vxivtGUlzkjAZ7yg7VpPEGOFpOqfjpGF5QeWcFXD2fnF5pg+YwCQcKoC6fdyhndkKQDOA87uVkFhi3z/QFO/PJ4rNxx5N69cdtSwB4mwJIb5KtAsyciYZpsmV/YrZhNT/7pHuPl3gERUIDpw6roo7/Lkeb19WAOc+9fDEDyFvHJIzO6+J5Kt5YdG2eXMRcGsxSRAUhl3Hfbtfok3qNh86wp39xd1mjzRoslXSGTfARzNb/CjpLA7Bs7vcEHCVYqEOm4Po2irWQeZZPJqaf37TjThS9WesZQLxYsi1KvOJYQiIJeOK2JbccRlRTl0DmcKQbwhMPNdf87LzcsQpDzKE3iESMImmgmGu+zcx/lUwjs7zjAuC/nTbPXPfs5KzniCxJuHMjC08IoP4c+FnWXRwA8WjggqKWBom9gY8FfxnI35Ic/aZj4z2LSzBDISGxk50QwS44Z1RX5x/W28HmIk54BFl527/R0Z1UYodHK1/tLjIdPAAOiRHaTBzR/6jKqnvH5WTvzxOH1jclMtm0TLpTon+VgDwkPG1TRx5icTbyz1YtlEq3pfPRnE2endKJub52Tpiym9qbPVNDs0vK5JwExufUAplwtVUw35C+OVKUhIMYTHibpZZJnBKCuQCBZhQ/qGN13vuPHqhIVKkrsgdVabOj8QrPpbpQaoYDiaWCpLLKMDgt0VyOtpWJKksjUlzDF+nU7B37alXxc2wEVLHOqDvSze5RPdAiIrQUyWDf1GVtPcF9aABH1F vlad@ghn.me"
}

# AMI
data "aws_ami" "vault" {
  most_recent = true
  owners      = ["self"]
  name_regex  = "^Vault_.*"

  filter {
    name   = "tag:Group"
    values = ["vgh"]
  }

  filter {
    name   = "tag:Project"
    values = ["vgh"]
  }
}

# DNS
resource "aws_eip" "vault" {
  vpc        = true
  instance   = aws_instance.vault.id
  depends_on = [module.vpc]

  tags = merge(
    var.common_tags,
    {
      "Name" = "Vault"
    },
  )
}

data "null_data_source" "vault" {
  inputs = {
    public_dns = "ec2-${replace(join("", aws_eip.vault.*.public_ip), ".", "-")}.${data.aws_region.current.name == "us-east-1" ? "compute-1" : "${data.aws_region.current.name}.compute"}.amazonaws.com"
  }
}

resource "cloudflare_record" "vault" {
  zone_id = var.cloudflare_zone_id
  name    = "vault"
  value   = data.null_data_source.vault.outputs["public_dns"]
  type    = "CNAME"
}

# Vault Instance
resource "aws_instance" "vault" {
  instance_type               = "t3.micro"
  ami                         = data.aws_ami.vault.id
  subnet_id                   = element(module.vpc.public_subnets, 0)
  vpc_security_group_ids      = [aws_security_group.vault.id]
  iam_instance_profile        = aws_iam_instance_profile.vault.name
  key_name                    = aws_key_pair.vgh.key_name
  associate_public_ip_address = true

  user_data = <<DATA
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Send the log output from this script to user-data.log, syslog, and the console
# From: https://alestic.com/2010/12/ec2-user-data-output/
exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1

echo 'Update System'
export DEBIAN_FRONTEND=noninteractive
while ! apt-get -y update; do sleep 1; done
sudo apt-get -q -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' --allow-remove-essential upgrade

echo 'Set hostname'
sudo hostnamectl set-hostname vault.ghn.me

echo 'Download LetsEncrypt certificates'
sudo aws s3 sync --delete --sse aws:kms s3://${aws_s3_bucket.vault.id}/acme/ca /root/.acme.sh/ca || true
sudo aws s3 sync --delete --sse aws:kms s3://${aws_s3_bucket.vault.id}/acme/vault.ghn.me /root/.acme.sh/vault.ghn.me || true

echo 'Generate/Renew LetsEncrypt certificates'
export CF_Email="${var.cloudflare_email}"
export CF_Key="${var.cloudflare_api_key}"
sudo -E su -c '/root/.acme.sh/acme.sh --issue --dns dns_cf -d vault.ghn.me || true'
sudo -E su -c '/root/.acme.sh/acme.sh --install-cert -d vault.ghn.me --cert-file /opt/vault/tls/vault.ghn.me.crt --key-file /opt/vault/tls/vault.ghn.me.key --fullchain-file /opt/vault/tls/vault.ghn.me.fullchain.crt'

echo 'Upload LetsEncrypt certificates'
sudo aws s3 sync --sse aws:kms /root/.acme.sh/ca s3://${aws_s3_bucket.vault.id}/acme/ca
sudo aws s3 sync --sse aws:kms /root/.acme.sh/vault.ghn.me s3://${aws_s3_bucket.vault.id}/acme/vault.ghn.me

echo 'Configure Vault Server'
cat <<EOF | sudo tee /opt/vault/config/default.hcl
listener "tcp" {
  address         = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  tls_cert_file   = "/opt/vault/tls/vault.ghn.me.fullchain.crt"
  tls_key_file    = "/opt/vault/tls/vault.ghn.me.key"
}

storage "dynamodb" {
  ha_enabled = "true"
  region     = "${data.aws_region.current.name}"
  table      = "${aws_dynamodb_table.vault.id}"
}

ui = true

api_addr     = "https://vault.ghn.me:8200"
cluster_addr = "https://vault.ghn.me:8201"
EOF

echo 'Set Vault Server permissions'
sudo chown -R vault:vault /opt/vault/tls /opt/vault/config

echo 'Start Vault Server'
/opt/vault/bin/run-vault --skip-vault-config --tls-cert-file /opt/vault/tls/vault.ghn.me_fullchain.crt --tls-key-file /opt/vault/tls/vault.ghn.me.key

echo "FINISHED @ $(date "+%m-%d-%Y %T")" | sudo tee /var/lib/cloud/instance/deployed
DATA


  tags = merge(
    var.common_tags,
    {
      "Name" = "Vault"
    },
  )
}
