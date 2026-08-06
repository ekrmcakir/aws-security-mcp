# AWS Security Analyzer (MCP Server)

An automated Cloud Security Posture Management (CSPM) tool built on the Model Context Protocol (MCP). This server acts as a local security scanner for AWS environments, designed to detect over-privileged IAM roles and S3 Public Access Block misconfigurations using the Principle of Least Privilege.

## 🚀 Features

- **IAM Role Enumeration:** Lists IAM roles and ARNs with pagination support.
- **Policy Analysis:** Scans both managed and inline IAM policies for `AdministratorAccess` and wildcard (`*`) action/resource risks.
- **S3 Public Access Block Scanner:** Audits S3 buckets for missing or partial Public Access Block (PAB) settings.

## 🛠️ Prerequisites

- Python 3.10+
- Node.js (optional, for MCP Inspector testing)
- AWS credentials configured (`aws configure`, environment variables, or an IAM role)

## ⚙️ Installation

1. Clone the repository:

```bash
git clone https://github.com/ekremcakir/aws-security-mcp.git
cd aws-security-mcp
```

2. Create and activate a virtual environment:

```bash
python3 -m venv .venv
```

macOS / Linux:

```bash
source .venv/bin/activate
```

Windows:

```powershell
.venv\Scripts\activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

## 🔍 Usage

### MCP Inspector (local testing)

```bash
npx @modelcontextprotocol/inspector .venv/bin/python server.py
```

Open the localhost URL in your browser, go to **Tools**, and run:

- `list_iam_roles`
- `analyze_iam_policy`
- `analyze_s3_security`

### Cursor / Claude Desktop

Add this to your MCP config (adjust paths to your machine):

```json
{
  "mcpServers": {
    "aws-security": {
      "command": "/absolute/path/to/aws-security-mcp/.venv/bin/python",
      "args": ["/absolute/path/to/aws-security-mcp/server.py"]
    }
  }
}
```

Windows example:

```json
{
  "mcpServers": {
    "aws-security": {
      "command": "C:\\path\\to\\aws-security-mcp\\.venv\\Scripts\\python.exe",
      "args": ["C:\\path\\to\\aws-security-mcp\\server.py"]
    }
  }
}
```

## 🔐 Required AWS IAM Permissions

The IAM user or role running this server needs at least:

| Service | Actions |
|---------|---------|
| IAM | `iam:ListRoles`, `iam:ListAttachedRolePolicies`, `iam:ListRolePolicies`, `iam:GetRolePolicy`, `iam:GetPolicy`, `iam:GetPolicyVersion` |
| S3 | `s3:ListAllMyBuckets`, `s3:GetPublicAccessBlock` |

Example read-only policy snippet:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListRoles",
        "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies",
        "iam:GetRolePolicy",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "s3:ListAllMyBuckets",
        "s3:GetPublicAccessBlock"
      ],
      "Resource": "*"
    }
  ]
}
```

## ⚠️ Limitations

- **S3 scope:** Checks Public Access Block settings only. Does not analyze bucket policies, ACLs, or actual public object exposure.
- **IAM scope:** Does not evaluate permission boundaries, trust policies, or cross-account access patterns.
- **Pagination:** `list_iam_roles` respects `max_items`; large accounts may need multiple calls with higher limits.
- **Credentials:** Uses the default Boto3 credential chain (environment, shared config, instance profile).

## 🛡️ Architecture & DevSecOps Context

This project demonstrates cloud security automation with standard AWS SDKs (Boto3) and the MCP standard, bridging infrastructure auditing and AI-driven workflow integrations.

## 📄 License

MIT — see [LICENSE](LICENSE).
