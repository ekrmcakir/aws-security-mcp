from fastmcp import FastMCP
import boto3
import json
from botocore.exceptions import ClientError

# Initialize FastMCP Server for AWS Security Analysis
mcp = FastMCP("AWS-Security-Analyzer")


def _normalize_statements(document: dict) -> list[dict]:
    """
    Normalize IAM policy Statement field.
    AWS returns Statement as either a single dict or a list — we always work with a list.
    """
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        return [statements]
    return statements


def _scan_policy_document(document: dict, policy_name: str, alerts: list[str]) -> None:
    """
    Scan a policy document (managed or inline) for common privilege-escalation risks.
    We flag AdministratorAccess and wildcard (*) actions/resources.
    """
    # Critical check: full admin access attached to the role
    if policy_name == "AdministratorAccess":
        alerts.append("CRITICAL: Role has full AdministratorAccess attached!")

    for statement in _normalize_statements(document):
        # We only care about Allow statements — Deny rules reduce risk
        if statement.get("Effect") != "Allow":
            continue

        actions = statement.get("Action", [])
        resources = statement.get("Resource", [])

        # AWS allows Action/Resource as a string or a list — normalize to list
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        # Flag wildcard actions (e.g. "*" or ["s3:*", "*"])
        if "*" in actions:
            alerts.append(
                f"HIGH RISK in {policy_name}: Action wildcard '*' found (can perform any action)."
            )

        # Flag wildcard resources (e.g. "*" or ["arn:aws:s3:::*", "*"])
        if "*" in resources:
            alerts.append(
                f"WARNING in {policy_name}: Resource wildcard '*' found (can access any resource)."
            )


# --- TOOL 1: List IAM Roles ---
@mcp.tool()
def list_iam_roles(max_items: int = 10) -> str:
    """
    Lists IAM roles in the AWS account.
    Returns role names and ARNs for security analysis.
    Supports pagination up to max_items.
    """
    try:
        iam_client = boto3.client("iam")
        roles: list[dict] = []
        marker = None

        # Paginate through IAM roles until we hit max_items or run out of pages
        while len(roles) < max_items:
            kwargs: dict = {"MaxItems": min(max_items - len(roles), 100)}
            if marker:
                kwargs["Marker"] = marker

            response = iam_client.list_roles(**kwargs)
            for role in response.get("Roles", []):
                roles.append({"RoleName": role["RoleName"], "Arn": role["Arn"]})
                if len(roles) >= max_items:
                    break

            if not response.get("IsTruncated") or len(roles) >= max_items:
                break
            marker = response.get("Marker")

        return json.dumps({"status": "success", "roles": roles}, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": f"AWS Connection Error: {str(e)}"})


# --- TOOL 2: Analyze IAM Policy ---
@mcp.tool()
def analyze_iam_policy(role_name: str) -> str:
    """
    Analyzes managed and inline IAM policies attached to a role.
    Flags AdministratorAccess and wildcard (*) action/resource permissions.
    """
    try:
        iam_client = boto3.client("iam")

        analysis_result = {
            "role_name": role_name,
            "managed_policies": [],
            "inline_policies": [],
            "security_alerts": [],
        }

        # Step 1: Scan AWS-managed / customer-managed policies attached to the role
        attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
        for policy in attached_policies.get("AttachedPolicies", []):
            policy_arn = policy["PolicyArn"]
            policy_name = policy["PolicyName"]
            analysis_result["managed_policies"].append(policy_name)

            # Fetch the active policy version document from IAM
            policy_info = iam_client.get_policy(PolicyArn=policy_arn)
            version_id = policy_info["Policy"]["DefaultVersionId"]
            policy_version = iam_client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=version_id,
            )
            document = policy_version["PolicyVersion"]["Document"]
            _scan_policy_document(document, policy_name, analysis_result["security_alerts"])

        # Step 2: Scan inline policies embedded directly on the role
        inline_policies = iam_client.list_role_policies(RoleName=role_name)
        for policy_name in inline_policies.get("PolicyNames", []):
            analysis_result["inline_policies"].append(policy_name)
            inline_policy = iam_client.get_role_policy(
                RoleName=role_name,
                PolicyName=policy_name,
            )
            _scan_policy_document(
                inline_policy["PolicyDocument"],
                policy_name,
                analysis_result["security_alerts"],
            )

        return json.dumps({"status": "success", "analysis": analysis_result}, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Policy Analysis Error: {str(e)}"})


# --- TOOL 3: S3 Bucket Security Scanner ---
@mcp.tool()
def analyze_s3_security(max_buckets: int = 10) -> str:
    """
    Scans S3 buckets for Public Access Block (PAB) misconfigurations.
    Flags buckets with missing or partial PAB settings.
    Does not inspect bucket policies or ACLs.
    """
    try:
        s3_client = boto3.client("s3")
        response = s3_client.list_buckets()

        # Limit the number of buckets to scan per request
        buckets = response.get("Buckets", [])[:max_buckets]
        analysis_result = {
            "scanned_buckets": [],
            "security_alerts": [],
        }

        for bucket in buckets:
            bucket_name = bucket["Name"]
            analysis_result["scanned_buckets"].append(bucket_name)

            try:
                # Check whether Public Access Block is fully enabled (all 4 settings = True)
                pab_response = s3_client.get_public_access_block(Bucket=bucket_name)
                pab_config = pab_response.get("PublicAccessBlockConfiguration", {})

                # If any of the 4 block settings are False, it's a risk
                if not all(pab_config.values()):
                    analysis_result["security_alerts"].append(
                        f"WARNING: S3 Bucket '{bucket_name}' has partial Public Access Block settings."
                    )
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code")
                if error_code == "NoSuchPublicAccessBlockConfiguration":
                    # No PAB at all — bucket may be publicly reachable depending on policy/ACL
                    analysis_result["security_alerts"].append(
                        f"HIGH RISK: S3 Bucket '{bucket_name}' has NO Public Access Block configuration."
                    )
                else:
                    # Likely missing s3:GetPublicAccessBlock permission for this bucket
                    analysis_result["security_alerts"].append(
                        f"INFO: Could not verify '{bucket_name}' due to permissions ({error_code})."
                    )

        return json.dumps({"status": "success", "analysis": analysis_result}, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": f"S3 Analysis Error: {str(e)}"})


if __name__ == "__main__":
    mcp.run()
