import json
import logging
import os
from typing import Any, Dict, List, Set

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

class LazyClient:
    """A lazy loader for boto3 clients to prevent import-time side-effects."""
    def __init__(self, service_name: str):
        self._service_name = service_name
        self._client = None

    def _get_client(self) -> Any:
        if self._client is None:
            self._client = boto3.client(self._service_name)
        return self._client

    def __getattr__(self, name: str) -> Any:
        return getattr(self._get_client(), name)


s3_client = LazyClient("s3")
ec2_client = LazyClient("ec2")
rds_client = LazyClient("rds")
elb_client = LazyClient("elbv2")
sns_client = LazyClient("sns")
autoscaling_client = LazyClient("autoscaling")
ecs_client = LazyClient("ecs")
elasticache_client = LazyClient("elasticache")
amp_client = LazyClient("amp")
iam_client = LazyClient("iam")
sts_client = LazyClient("sts")


TYPE_MAPPING = {
    "ec2_instances": "ec2",
    "nat_gateways": "nat",
    "ebs_volumes": "ebs",
    "rds_instances": "rds",
    "load_balancers": "elb",
    "security_groups": "sg",
    "auto_scaling_groups": "asg",
    "ecs_clusters": "ecs",
    "elasticache_clusters": "elasticache",
    "prometheus_workspaces": "prometheus",
    "s3_buckets": "s3",
    "iam_roles": "iam_role",
    "iam_users": "iam_user",
    "vpcs": "vpc"
}


def format_sns_body(state: str, resource_plan: Dict[str, List[Dict[str, Any]]], result: Dict[str, Any] = None) -> str:
    """Format the SNS message body based on the state.
    
    States:
      - 'warning': Pre-Purge Warning
      - 'dry_run': Dry-Run Audit
      - 'purge': Live Purge Complete
    """
    body_lines = []
    
    if state == "warning":
        body_lines.append("The following unmanaged resources are scheduled to be purged in the upcoming execution window:")
        body_lines.append("")
        for r_type, resources in resource_plan.items():
            if resources:
                type_prefix = TYPE_MAPPING.get(r_type, r_type)
                body_lines.append(f"{type_prefix}:")
                for r in resources:
                    r_id = r.get("id") or r.get("arn") or str(r)
                    body_lines.append(f"  - {r_id}")
                    
    elif state == "dry_run":
        body_lines.append("Dry-run audit completed. The following resources would have been deleted:")
        body_lines.append("")
        for r_type, resources in resource_plan.items():
            if resources:
                type_prefix = TYPE_MAPPING.get(r_type, r_type)
                body_lines.append(f"{type_prefix}:")
                for r in resources:
                    r_id = r.get("id") or r.get("arn") or str(r)
                    body_lines.append(f"  - {r_id}")
                    
    elif state == "purge":
        body_lines.append("Purge completed.")
        body_lines.append("")
        
        if result:
            deleted = result.get("deleted", {})
            failures = result.get("failures", {})
            
            body_lines.append("Deleted resources:")
            has_deleted = False
            for r_type, ids in deleted.items():
                if ids:
                    has_deleted = True
                    type_prefix = TYPE_MAPPING.get(r_type, r_type)
                    body_lines.append(f"{type_prefix}:")
                    for r_id in ids:
                        body_lines.append(f"  - {r_id}")
            if not has_deleted:
                body_lines.append("  (None)")
                
            body_lines.append("")
            body_lines.append("Failed to delete:")
            has_failures = False
            for r_type, fails in failures.items():
                if fails:
                    has_failures = True
                    type_prefix = TYPE_MAPPING.get(r_type, r_type)
                    body_lines.append(f"{type_prefix}:")
                    for f in fails:
                        if isinstance(f, dict):
                            f_id = f.get("id") or f.get("arn") or str(f)
                            f_err = f.get("error", "Unknown error")
                            body_lines.append(f"  - {f_id}: {f_err}")
                        else:
                            body_lines.append(f"  - {f}")
            if not has_failures:
                body_lines.append("  (None)")
                
    return "\n".join(body_lines)


def send_sns_warning_payload(
    topic_arn: str, 
    state_bucket: str, 
    resource_plan: Dict[str, List[Dict[str, Any]]]
) -> None:
    """Compile warning message and publish to SNS, offloading to S3 if it exceeds 240 KB."""
    header = "The following unmanaged resources will be permanently purged at 00:00 UTC:"
    
    warning_offset_hours = os.environ.get("WARNING_OFFSET_HOURS", "2")
    hours_suffix = "HOUR" if warning_offset_hours == "1" else "HOURS"
    
    footer = (
        "──────────────────────────────────────────────────────────────────────\n"
        f"💡 HOW TO PROTECT THESE RESOURCES FROM THE PURGE (EXECUTION IN {warning_offset_hours} {hours_suffix})\n"
        "──────────────────────────────────────────────────────────────────────\n"
        "If any of the resources listed above need to survive tonight's purge, \n"
        "you must apply one of the following remediation steps before 00:00 UTC:\n"
        "\n"
        "Option A: The State Shield (Recommended)\n"
        "Ensure the resource is managed via Terraform and that its state file \n"
        "is synced to our central Heliopause S3 immunity bucket prefix.\n"
        "\n"
        "Option B: The Real-Time Tag Override\n"
        "Manually apply the following tag directly to the resource in the AWS Console:\n"
        "Key:   Heliopause: Shield\n"
        "Value: true\n"
        "\n"
        "Option C: Global Variable Lock (Emergency Mute)\n"
        "Update your Heliopause environment configuration variable 'DRY_RUN' \n"
        "to 'true' to completely freeze active destruction across the account."
    )
    
    list_items = []
    for r_type, resources in resource_plan.items():
        if resources:
            type_prefix = TYPE_MAPPING.get(r_type, r_type)
            for r in resources:
                r_id = r.get("id") or r.get("arn") or str(r)
                list_items.append(f"- {type_prefix}: {r_id}")
                
    list_content = "\n".join(list_items)
    full_message = f"{header}\n{list_content}\n\n{footer}"
    
    if len(full_message.encode('utf-8')) > 240 * 1024:
        key = "heliopause/pending_resource_purge_list.txt"
        logger.info("Warning payload exceeds 240 KB. Writing drift list to S3: s3://%s/%s", state_bucket, key)
        try:
            s3_client.put_object(
                Bucket=state_bucket,
                Key=key,
                Body=list_content.encode("utf-8"),
                ContentType="text/plain"
            )
        except Exception as exc:
            logger.error("Failed to write pending purge list to S3: %s", exc)
            fallback_msg = f"{header}\n[Error: List exceeded limit and S3 offload failed]\n\n{footer}"
            publish_to_sns(topic_arn, "[Heliopause] [WARNING] Pending Purge", fallback_msg)
            return

        replacement_text = (
            "The list of pending resources was too large to fit in this notification and has been offloaded to S3.\n"
            f"Bucket: {state_bucket}\n"
            f"Key: {key}\n"
            "\n"
            "To retrieve the full list of resources, run the following AWS CLI command:\n"
            f"aws s3 cp s3://{state_bucket}/{key} ."
        )
        full_message = f"{header}\n{replacement_text}\n\n{footer}"
        
    publish_to_sns(topic_arn, "[Heliopause] [WARNING] Pending Purge", full_message)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Entry point for the Heliopause cleanup Lambda."""
    state_bucket = os.environ["STATE_BUCKET_NAME"]
    state_prefix = os.environ.get("STATE_PREFIX", "heliopause/statefiles/")
    core_state_file = os.environ.get("CORE_STATE_FILE", "heliopause.tfstate")
    dry_run = os.environ.get("DRY_RUN", "true").lower() == "true"
    sns_topic_arn = os.environ.get("SNS_TOPIC_ARN")

    # Feature toggles
    purge_ec2_instances = os.environ.get("PURGE_EC2_INSTANCES", "true").lower() == "true"
    purge_nat_gateways = os.environ.get("PURGE_NAT_GATEWAYS", "true").lower() == "true"
    purge_ebs_volumes = os.environ.get("PURGE_EBS_VOLUMES", "true").lower() == "true"
    purge_rds_instances = os.environ.get("PURGE_RDS_INSTANCES", "true").lower() == "true"
    purge_load_balancers = os.environ.get("PURGE_LOAD_BALANCERS", "true").lower() == "true"
    purge_security_groups = os.environ.get("PURGE_SECURITY_GROUPS", "true").lower() == "true"
    purge_auto_scaling_groups = os.environ.get("PURGE_AUTO_SCALING_GROUPS", "true").lower() == "true"
    purge_ecs_clusters = os.environ.get("PURGE_ECS_CLUSTERS", "true").lower() == "true"
    purge_elasticache_clusters = os.environ.get("PURGE_ELASTICACHE_CLUSTERS", "true").lower() == "true"
    purge_prometheus_workspaces = os.environ.get("PURGE_PROMETHEUS_WORKSPACES", "true").lower() == "true"
    purge_s3_buckets = os.environ.get("PURGE_S3_BUCKETS", "false").lower() == "true"
    purge_iam_roles = os.environ.get("PURGE_IAM_ROLES", "false").lower() == "true"
    purge_iam_users = os.environ.get("PURGE_IAM_USERS", "true").lower() == "true"
    purge_vpcs = os.environ.get("PURGE_VPCS", "false").lower() == "true"

    action = event.get("action", "purge")
    logger.info("Heliopause starting: action=%s, dry_run=%s, bucket=%s, prefix=%s, core_file=%s", 
                action, dry_run, state_bucket, state_prefix, core_state_file)

    # 1. Global Safeguard: If action == "warn" and DRY_RUN is true, abort execution immediately.
    if action == "warn" and dry_run:
        msg = "Pre-purge warning suppressed: DRY_RUN is enabled."
        logger.info(msg)
        return {
            "dry_run": True,
            "action": "warn",
            "message": msg
        }

    # Check for core state file presence
    core_state_key = f"{state_prefix}{core_state_file}"
    if not state_file_exists(state_bucket, core_state_key):
        error_msg = f"Core state file '{core_state_key}' is missing."
        if dry_run:
            logger.warning("%s Proceeding with dry-run evaluation.", error_msg)
        else:
            full_error = f"{error_msg} Aborting deletion to prevent self-destruction."
            logger.error(full_error)
            if sns_topic_arn:
                publish_to_sns(sns_topic_arn, "Heliopause Alert", full_error)
            raise RuntimeError(full_error)

    state_files = list_state_files(state_bucket, state_prefix)
    immunity_ids = build_immunity_list(state_bucket, state_files)

    logger.info("Immunity list contains %d resource IDs", len(immunity_ids))

    resource_plan = scan_for_purge_candidates(
        immunity_ids,
        purge_ec2_instances=purge_ec2_instances,
        purge_nat_gateways=purge_nat_gateways,
        purge_ebs_volumes=purge_ebs_volumes,
        purge_rds_instances=purge_rds_instances,
        purge_load_balancers=purge_load_balancers,
        purge_security_groups=purge_security_groups,
        purge_auto_scaling_groups=purge_auto_scaling_groups,
        purge_ecs_clusters=purge_ecs_clusters,
        purge_elasticache_clusters=purge_elasticache_clusters,
        purge_prometheus_workspaces=purge_prometheus_workspaces,
        purge_s3_buckets=purge_s3_buckets,
        purge_iam_roles=purge_iam_roles,
        purge_iam_users=purge_iam_users,
        purge_vpcs=purge_vpcs
    )

    # For 'warn' action, we must strictly NOT execute any deletion blocks, so evaluate with dry_run=True.
    eval_dry_run = True if action == "warn" else dry_run
    result = evaluate_purge_plan(resource_plan, eval_dry_run, context=context, immunity_ids=immunity_ids)

    # Publish decoupled notifications to SNS based on the routing matrix
    if sns_topic_arn:
        if action == "warn":
            # State A (Pre-Purge Warning)
            send_sns_warning_payload(sns_topic_arn, state_bucket, resource_plan)
        elif dry_run:
            # State B (Dry-Run Audit)
            subject = "[Heliopause] [DRY_RUN_COMPLETED]"
            body = format_sns_body("dry_run", resource_plan)
            publish_to_sns(sns_topic_arn, subject, body)
        else:
            # State C (Live Purge Complete)
            subject = "[Heliopause] [PURGE_COMPLETED]"
            body = format_sns_body("purge", resource_plan, result)
            publish_to_sns(sns_topic_arn, subject, body)

    # Clean up the pending purge list from S3 if it exists during actual purge execution
    if action == "purge":
        try:
            s3_client.delete_object(Bucket=state_bucket, Key="heliopause/pending_resource_purge_list.txt")
            logger.info("Removed pending resource purge list from S3.")
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("404", "NoSuchKey"):
                logger.warning("Could not delete pending resource purge list from S3: %s", exc)
        except Exception as exc:
            logger.warning("Could not delete pending resource purge list from S3: %s", exc)

    logger.info("Heliopause complete: %s", json.dumps(result, default=str))
    return result


def state_file_exists(bucket_name: str, key: str) -> bool:
    """Check if a specific state file exists in S3."""
    try:
        s3_client.head_object(Bucket=bucket_name, Key=key)
        return True
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "404":
            return False
        raise


def publish_to_sns(topic_arn: str, subject: str, message: str) -> None:
    """Publish a message to the SNS topic."""
    try:
        sns_client.publish(
            TopicArn=topic_arn,
            Subject=subject,
            Message=message
        )
        logger.info("Published to SNS: %s", subject)
    except ClientError as exc:
        logger.error("Failed to publish to SNS: %s", exc)


def list_state_files(bucket_name: str, prefix: str) -> List[str]:
    """List all .tfstate files under the configured S3 prefix."""
    keys: List[str] = []
    paginator = s3_client.get_paginator("list_objects_v2")

    for page in paginator.paginate(Bucket=bucket_name, Prefix=prefix):
        for obj in page.get("Contents", []):
            key = obj.get("Key")
            if key and key.endswith(".tfstate"):
                keys.append(key)

    logger.debug("Found %d state files", len(keys))
    return keys


def build_immunity_list(bucket_name: str, state_files: List[str]) -> Set[str]:
    """Parse each Terraform state file and collect all managed resource IDs."""
    immunity: Set[str] = set()

    for key in state_files:
        state_data = load_state_file(bucket_name, key)
        immunity.update(extract_resource_ids(state_data))

    return immunity


def load_state_file(bucket_name: str, key: str) -> Dict[str, Any]:
    """Load a single Terraform state file from S3."""
    try:
        response = s3_client.get_object(Bucket=bucket_name, Key=key)
        payload = response["Body"].read().decode("utf-8")
        return json.loads(payload)
    except Exception as exc:
        logger.error("Unable to load state file %s from %s: %s", key, bucket_name, exc)
        raise RuntimeError(f"Failed to load state file {key} from bucket {bucket_name}: {exc}") from exc


def extract_resource_ids(state_data: Dict[str, Any]) -> Set[str]:
    """Extract resource IDs from Terraform state data."""
    ids: Set[str] = set()
    for module in state_data.get("resources", []):
        for instance in module.get("instances", []):
            attributes = instance.get("attributes", {})
            resource_id = attributes.get("id")
            if resource_id:
                ids.add(resource_id)

    return ids


def scan_for_purge_candidates(
    immunity_ids: Set[str],
    purge_ec2_instances: bool,
    purge_nat_gateways: bool,
    purge_ebs_volumes: bool,
    purge_rds_instances: bool,
    purge_load_balancers: bool,
    purge_security_groups: bool,
    purge_auto_scaling_groups: bool,
    purge_ecs_clusters: bool,
    purge_elasticache_clusters: bool,
    purge_prometheus_workspaces: bool,
    purge_s3_buckets: bool,
    purge_iam_roles: bool,
    purge_iam_users: bool,
    purge_vpcs: bool
) -> Dict[str, List[Dict[str, Any]]]:
    """Scan AWS resources and identify candidates not present in the immunity list."""
    candidates: Dict[str, List[Dict[str, Any]]] = {
        "ec2_instances": [],
        "nat_gateways": [],
        "ebs_volumes": [],
        "rds_instances": [],
        "load_balancers": [],
        "security_groups": [],
        "auto_scaling_groups": [],
        "ecs_clusters": [],
        "elasticache_clusters": [],
        "prometheus_workspaces": [],
        "s3_buckets": [],
        "iam_roles": [],
        "iam_users": [],
        "vpcs": [],
    }

    if purge_ec2_instances:
        candidates["ec2_instances"] = scan_ec2_instances(immunity_ids)
    if purge_nat_gateways:
        candidates["nat_gateways"] = scan_nat_gateways(immunity_ids)
    if purge_ebs_volumes:
        candidates["ebs_volumes"] = scan_ebs_volumes(immunity_ids)
    if purge_rds_instances:
        candidates["rds_instances"] = scan_rds_instances(immunity_ids)
    if purge_load_balancers:
        candidates["load_balancers"] = scan_load_balancers(immunity_ids)
    if purge_security_groups:
        candidates["security_groups"] = scan_security_groups(immunity_ids)
    if purge_auto_scaling_groups:
        candidates["auto_scaling_groups"] = scan_auto_scaling_groups(immunity_ids)
    if purge_ecs_clusters:
        candidates["ecs_clusters"] = scan_ecs_clusters(immunity_ids)
    if purge_elasticache_clusters:
        candidates["elasticache_clusters"] = scan_elasticache_clusters(immunity_ids)
    if purge_prometheus_workspaces:
        candidates["prometheus_workspaces"] = scan_prometheus_workspaces(immunity_ids)
    if purge_s3_buckets:
        candidates["s3_buckets"] = scan_s3_buckets(immunity_ids)
    if purge_iam_roles:
        candidates["iam_roles"] = scan_iam_roles(immunity_ids)
    if purge_iam_users:
        candidates["iam_users"] = scan_iam_users(immunity_ids)
    if purge_vpcs:
        candidates["vpcs"] = scan_vpcs(immunity_ids)

    return candidates


def scan_ec2_instances(immunity_ids: Set[str]) -> List[Dict[str, Any]]:
    instances: List[Dict[str, Any]] = []
    paginator = ec2_client.get_paginator("describe_instances")
    for page in paginator.paginate():
        for reservation in page.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                if instance.get("InstanceId") not in immunity_ids:
                    instances.append({
                        "id": instance.get("InstanceId"),
                        "type": instance.get("InstanceType"),
                        "state": instance.get("State", {}).get("Name"),
                    })
    return instances


def scan_nat_gateways(immunity_ids: Set[str]) -> List[Dict[str, Any]]:
    gateways: List[Dict[str, Any]] = []
    response = ec2_client.describe_nat_gateways()
    for gateway in response.get("NatGateways", []):
        if gateway.get("NatGatewayId") not in immunity_ids:
            gateways.append({
                "id": gateway.get("NatGatewayId"),
                "state": gateway.get("State"),
            })
    return gateways


def scan_ebs_volumes(immunity_ids: Set[str]) -> List[Dict[str, Any]]:
    volumes: List[Dict[str, Any]] = []
    paginator = ec2_client.get_paginator("describe_volumes")
    for page in paginator.paginate():
        for volume in page.get("Volumes", []):
            if volume.get("VolumeId") not in immunity_ids and not volume.get("Attachments"):
                volumes.append({
                    "id": volume.get("VolumeId"),
                    "size": volume.get("Size"),
                    "state": volume.get("State"),
                })
    return volumes


def scan_rds_instances(immunity_ids: Set[str]) -> List[Dict[str, Any]]:
    instances: List[Dict[str, Any]] = []
    response = rds_client.describe_db_instances()
    for instance in response.get("DBInstances", []):
        if instance.get("DbiResourceId") not in immunity_ids and instance.get("DBInstanceIdentifier") not in immunity_ids:
            instances.append({
                "id": instance.get("DBInstanceIdentifier"),
                "status": instance.get("DBInstanceStatus"),
            })
    return instances


def scan_load_balancers(immunity_ids: Set[str]) -> List[Dict[str, Any]]:
    balancers: List[Dict[str, Any]] = []
    response = elb_client.describe_load_balancers()
    for lb in response.get("LoadBalancers", []):
        if lb.get("LoadBalancerArn") not in immunity_ids and lb.get("LoadBalancerName") not in immunity_ids:
            balancers.append({
                "arn": lb.get("LoadBalancerArn"),
                "name": lb.get("LoadBalancerName"),
                "type": lb.get("Type"),
            })
    return balancers


def scan_security_groups(immunity_ids: Set[str]) -> List[Dict[str, Any]]:
    groups: List[Dict[str, Any]] = []
    response = ec2_client.describe_security_groups()
    for sg in response.get("SecurityGroups", []):
        sg_id = sg.get("GroupId")
        sg_name = sg.get("GroupName")
        if sg_name == "default":
            continue
        if sg_id not in immunity_ids and sg_name not in immunity_ids:
            groups.append({
                "id": sg_id,
                "name": sg_name,
                "vpc_id": sg.get("VpcId")
            })
    return groups


def scan_auto_scaling_groups(immunity_ids: Set[str]) -> List[Dict[str, Any]]:
    groups: List[Dict[str, Any]] = []
    paginator = autoscaling_client.get_paginator("describe_auto_scaling_groups")
    for page in paginator.paginate():
        for asg in page.get("AutoScalingGroups", []):
            asg_name = asg.get("AutoScalingGroupName")
            asg_arn = asg.get("AutoScalingGroupARN")
            if asg_name not in immunity_ids and asg_arn not in immunity_ids:
                groups.append({
                    "id": asg_name,
                    "arn": asg_arn,
                    "status": asg.get("Status")
                })
    return groups


def scan_ecs_clusters(immunity_ids: Set[str]) -> List[Dict[str, Any]]:
    clusters: List[Dict[str, Any]] = []
    response = ecs_client.list_clusters()
    cluster_arns = response.get("clusterArns", [])
    if cluster_arns:
        desc_response = ecs_client.describe_clusters(clusters=cluster_arns)
        for cluster in desc_response.get("clusters", []):
            cluster_name = cluster.get("clusterName")
            cluster_arn = cluster.get("clusterArn")
            if cluster_name not in immunity_ids and cluster_arn not in immunity_ids:
                clusters.append({
                    "id": cluster_name,
                    "arn": cluster_arn,
                    "status": cluster.get("status")
                })
    return clusters


def scan_elasticache_clusters(immunity_ids: Set[str]) -> List[Dict[str, Any]]:
    """Scan for ElastiCache clusters and replication groups not in the immunity list."""
    clusters: List[Dict[str, Any]] = []
    
    # 1. Individual Cache Clusters
    try:
        paginator = elasticache_client.get_paginator("describe_cache_clusters")
        for page in paginator.paginate():
            for cluster in page.get("CacheClusters", []):
                cluster_id = cluster.get("CacheClusterId")
                # Skip if it is part of a replication group (replication groups are deleted as a whole)
                if cluster.get("ReplicationGroupId"):
                    continue
                if cluster_id not in immunity_ids:
                    clusters.append({
                        "id": cluster_id,
                        "engine": cluster.get("Engine"),
                        "status": cluster.get("CacheClusterStatus"),
                        "is_replication_group": False
                    })
    except ClientError as exc:
        logger.error("Failed to describe ElastiCache clusters: %s", exc)

    # 2. Replication Groups
    try:
        paginator = elasticache_client.get_paginator("describe_replication_groups")
        for page in paginator.paginate():
            for rg in page.get("ReplicationGroups", []):
                rg_id = rg.get("ReplicationGroupId")
                if rg_id not in immunity_ids:
                    clusters.append({
                        "id": rg_id,
                        "status": rg.get("Status"),
                        "is_replication_group": True
                    })
    except ClientError as exc:
        logger.error("Failed to describe ElastiCache replication groups: %s", exc)

    return clusters


def scan_prometheus_workspaces(immunity_ids: Set[str]) -> List[Dict[str, Any]]:
    """Scan for Amazon Managed Prometheus (AMP) workspaces not in the immunity list."""
    workspaces: List[Dict[str, Any]] = []
    try:
        next_token = None
        while True:
            kwargs = {}
            if next_token:
                kwargs["nextToken"] = next_token
            response = amp_client.list_workspaces(**kwargs)
            for ws in response.get("workspaces", []):
                ws_id = ws.get("workspaceId")
                ws_arn = ws.get("arn")
                if ws_id not in immunity_ids and ws_arn not in immunity_ids:
                    workspaces.append({
                        "id": ws_id,
                        "arn": ws_arn,
                        "status": ws.get("status", {}).get("statusCode")
                    })
            next_token = response.get("nextToken")
            if not next_token:
                break
    except ClientError as exc:
        logger.error("Failed to list AMP workspaces: %s", exc)
    return workspaces


def scan_s3_buckets(immunity_ids: Set[str]) -> List[Dict[str, Any]]:
    """Scan for S3 buckets not in the immunity list, excluding the Heliopause state bucket."""
    buckets: List[Dict[str, Any]] = []
    state_bucket = os.environ.get("STATE_BUCKET_NAME")
    try:
        response = s3_client.list_buckets()
        for bucket in response.get("Buckets", []):
            name = bucket.get("Name")
            if name == state_bucket:
                continue
            if name not in immunity_ids:
                buckets.append({
                    "id": name,
                    "creation_date": bucket.get("CreationDate")
                })
    except ClientError as exc:
        logger.error("Failed to list S3 buckets: %s", exc)
    return buckets


def get_current_role_name() -> str:
    """Retrieve the current Lambda execution role name using STS caller identity."""
    try:
        arn = sts_client.get_caller_identity()["Arn"]
        if "assumed-role" in arn:
            parts = arn.split("/")
            if len(parts) >= 2:
                return parts[1]
        else:
            return arn.split("/")[-1]
    except Exception as exc:
        logger.warning("Could not determine current role name: %s", exc)
    return ""


def get_extra_immune_iam_arns() -> Set[str]:
    """Retrieve extra immune IAM ARNs from the environment variable."""
    extra_immune_arns_str = os.environ.get("EXTRA_IMMUNE_IAM_ARNS", "[]")
    try:
        extra_immune = json.loads(extra_immune_arns_str)
        if isinstance(extra_immune, list):
            return {arn.strip() for arn in extra_immune if isinstance(arn, str) and arn.strip()}
    except Exception:
        pass
    # Fallback to comma-separated list
    return {arn.strip() for arn in extra_immune_arns_str.split(",") if arn.strip()}


def scan_iam_roles(immunity_ids: Set[str]) -> List[Dict[str, Any]]:
    """Scan for custom IAM roles not in the immunity list, ignoring service roles and ourselves."""
    roles: List[Dict[str, Any]] = []
    current_role = get_current_role_name()
    extra_immune = get_extra_immune_iam_arns()
    try:
        paginator = iam_client.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                role_name = role.get("RoleName")
                role_arn = role.get("Arn")
                path = role.get("Path", "")
                if path.startswith("/aws-service-role/"):
                    continue
                if role_name == current_role or role_arn == current_role:
                    continue
                if role_name.startswith("AWSServiceRole"):
                    continue
                if (role_name not in immunity_ids and 
                    role_arn not in immunity_ids and 
                    role_arn not in extra_immune):
                    roles.append({
                        "id": role_name,
                        "arn": role_arn,
                        "path": path
                    })
    except ClientError as exc:
        logger.error("Failed to list IAM roles: %s", exc)
    return roles


def scan_iam_users(immunity_ids: Set[str]) -> List[Dict[str, Any]]:
    """Scan for IAM users not in the immunity list."""
    users: List[Dict[str, Any]] = []
    extra_immune = get_extra_immune_iam_arns()
    try:
        paginator = iam_client.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                user_name = user.get("UserName")
                user_arn = user.get("Arn")
                if (user_name not in immunity_ids and 
                    user_arn not in immunity_ids and 
                    user_arn not in extra_immune):
                    users.append({
                        "id": user_name,
                        "arn": user_arn
                    })
    except ClientError as exc:
        logger.error("Failed to list IAM users: %s", exc)
    return users



def scan_vpcs(immunity_ids: Set[str]) -> List[Dict[str, Any]]:
    """Scan for non-default VPCs not in the immunity list."""
    vpcs: List[Dict[str, Any]] = []
    try:
        response = ec2_client.describe_vpcs()
        for vpc in response.get("Vpcs", []):
            vpc_id = vpc.get("VpcId")
            if vpc.get("IsDefault", False):
                continue
            if vpc_id not in immunity_ids:
                vpcs.append({
                    "id": vpc_id,
                    "cidr_block": vpc.get("CidrBlock")
                })
    except ClientError as exc:
        logger.error("Failed to describe VPCs: %s", exc)
    return vpcs


def delete_s3_bucket_contents(bucket_name: str) -> None:
    """Recursively delete all object versions, delete markers, and abort multipart uploads."""
    try:
        paginator = s3_client.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket_name):
            objects_to_delete = []
            
            for version in page.get("Versions", []):
                objects_to_delete.append({
                    "Key": version["Key"],
                    "VersionId": version["VersionId"]
                })
                
            for marker in page.get("DeleteMarkers", []):
                objects_to_delete.append({
                    "Key": marker["Key"],
                    "VersionId": marker["VersionId"]
                })
                
            if objects_to_delete:
                s3_client.delete_objects(
                    Bucket=bucket_name,
                    Delete={"Objects": objects_to_delete, "Quiet": True}
                )
    except ClientError as exc:
        logger.error("Error deleting object versions from S3 bucket %s: %s", bucket_name, exc)
        
    try:
        paginator = s3_client.get_paginator("list_multipart_uploads")
        for page in paginator.paginate(Bucket=bucket_name):
            for upload in page.get("Uploads", []):
                s3_client.abort_multipart_upload(
                    Bucket=bucket_name,
                    Key=upload["Key"],
                    UploadId=upload["UploadId"]
                )
    except ClientError as exc:
        logger.error("Error aborting multipart uploads for S3 bucket %s: %s", bucket_name, exc)


def delete_iam_role(role_name: str) -> None:
    """Detach policies, delete inline policies, remove from instance profiles, and delete the role."""
    current_role = get_current_role_name()
    if role_name == current_role:
        logger.warning("Bypassing self-destruction of execution role: %s", role_name)
        return

    # 1. Detach managed policies
    try:
        paginator = iam_client.get_paginator("list_attached_role_policies")
        for page in paginator.paginate(RoleName=role_name):
            for policy in page.get("AttachedPolicies", []):
                policy_arn = policy["PolicyArn"]
                logger.info("Detaching policy %s from role %s", policy_arn, role_name)
                iam_client.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    except ClientError as exc:
        logger.error("Error detaching policies from role %s: %s", role_name, exc)

    # 2. Delete inline policies
    try:
        paginator = iam_client.get_paginator("list_role_policies")
        for page in paginator.paginate(RoleName=role_name):
            for policy_name in page.get("PolicyNames", []):
                logger.info("Deleting inline policy %s from role %s", policy_name, role_name)
                iam_client.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        logger.error("Error deleting inline policies from role %s: %s", role_name, exc)

    # 3. Remove from instance profiles
    try:
        response = iam_client.list_instance_profiles_for_role(RoleName=role_name)
        for profile in response.get("InstanceProfiles", []):
            profile_name = profile["InstanceProfileName"]
            logger.info("Removing role %s from instance profile %s", role_name, profile_name)
            iam_client.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    except ClientError as exc:
        logger.error("Error removing role %s from instance profiles: %s", role_name, exc)

    # 4. Delete the role
    logger.info("Deleting IAM role: %s", role_name)
    iam_client.delete_role(RoleName=role_name)


def delete_iam_user(user_name: str) -> None:
    """Strip all policies, login profiles, access keys, certificates, SSH keys, MFA, and delete the user."""
    # 1. Detach managed policies
    try:
        paginator = iam_client.get_paginator("list_attached_user_policies")
        for page in paginator.paginate(UserName=user_name):
            for policy in page.get("AttachedPolicies", []):
                policy_arn = policy["PolicyArn"]
                logger.info("Detaching policy %s from user %s", policy_arn, user_name)
                iam_client.detach_user_policy(UserName=user_name, PolicyArn=policy_arn)
    except ClientError as exc:
        logger.error("Error detaching policies from user %s: %s", user_name, exc)

    # 2. Delete inline policies
    try:
        paginator = iam_client.get_paginator("list_user_policies")
        for page in paginator.paginate(UserName=user_name):
            for policy_name in page.get("PolicyNames", []):
                logger.info("Deleting inline policy %s from user %s", policy_name, user_name)
                iam_client.delete_user_policy(UserName=user_name, PolicyName=policy_name)
    except ClientError as exc:
        logger.error("Error deleting inline policies from user %s: %s", user_name, exc)

    # 3. Delete access keys
    try:
        paginator = iam_client.get_paginator("list_access_keys")
        for page in paginator.paginate(UserName=user_name):
            for key in page.get("AccessKeyMetadata", []):
                key_id = key["AccessKeyId"]
                logger.info("Deleting access key %s for user %s", key_id, user_name)
                iam_client.delete_access_key(UserName=user_name, AccessKeyId=key_id)
    except ClientError as exc:
        logger.error("Error deleting access keys for user %s: %s", user_name, exc)

    # 4. Delete login profile
    try:
        iam_client.delete_login_profile(UserName=user_name)
        logger.info("Deleted login profile for user %s", user_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            logger.error("Error deleting login profile for user %s: %s", user_name, exc)

    # 5. Delete signing certificates
    try:
        response = iam_client.list_signing_certificates(UserName=user_name)
        for cert in response.get("Certificates", []):
            cert_id = cert["CertificateId"]
            logger.info("Deleting signing certificate %s for user %s", cert_id, user_name)
            iam_client.delete_signing_certificate(UserName=user_name, CertificateId=cert_id)
    except ClientError as exc:
        logger.error("Error deleting signing certificates for user %s: %s", user_name, exc)

    # 6. Delete SSH public keys
    try:
        response = iam_client.list_ssh_public_keys(UserName=user_name)
        for key in response.get("SSHPublicKeys", []):
            key_id = key["SSHPublicKeyId"]
            logger.info("Deleting SSH public key %s for user %s", key_id, user_name)
            iam_client.delete_ssh_public_key(UserName=user_name, SSHPublicKeyId=key_id)
    except ClientError as exc:
        logger.error("Error deleting SSH public keys for user %s: %s", user_name, exc)

    # 7. Delete service-specific credentials
    try:
        response = iam_client.list_service_specific_credentials(UserName=user_name)
        for cred in response.get("ServiceSpecificCredentials", []):
            cred_id = cred["ServiceSpecificCredentialId"]
            logger.info("Deleting service-specific credential %s for user %s", cred_id, user_name)
            iam_client.delete_service_specific_credentials(UserName=user_name, ServiceSpecificCredentialId=cred_id)
    except ClientError as exc:
        logger.error("Error deleting service-specific credentials for user %s: %s", user_name, exc)

    # 8. Deactivate and delete MFA devices
    try:
        response = iam_client.list_mfa_devices(UserName=user_name)
        for mfa in response.get("MFADevices", []):
            serial = mfa["SerialNumber"]
            logger.info("Deactivating MFA device %s for user %s", serial, user_name)
            iam_client.deactivate_mfa_device(UserName=user_name, SerialNumber=serial)
            if serial.startswith("arn:aws:iam::"):
                try:
                    iam_client.delete_virtual_mfa_device(SerialNumber=serial)
                    logger.info("Deleted virtual MFA device %s", serial)
                except ClientError as mfa_exc:
                    logger.error("Error deleting virtual MFA device %s: %s", serial, mfa_exc)
    except ClientError as exc:
        logger.error("Error handling MFA devices for user %s: %s", user_name, exc)

    # 9. Delete user
    logger.info("Deleting IAM user: %s", user_name)
    iam_client.delete_user(UserName=user_name)


def delete_vpc_resources(vpc_id: str, immunity_ids: Set[str]) -> None:
    """Tear down all dependent VPC resources sequentially before deleting the VPC itself."""
    logger.info("Tearing down resources in VPC: %s", vpc_id)

    # 1. VPC Endpoints
    try:
        endpoints_resp = ec2_client.describe_vpc_endpoints(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
        for ep in endpoints_resp.get("VpcEndpoints", []):
            ep_id = ep["VpcEndpointId"]
            if ep_id not in immunity_ids:
                logger.info("Deleting VPC Endpoint: %s", ep_id)
                ec2_client.delete_vpc_endpoints(VpcEndpointIds=[ep_id])
    except Exception as exc:
        logger.error("Failed to delete VPC Endpoints in VPC %s: %s", vpc_id, exc)

    # 2. VPC Peering Connections
    try:
        peerings_resp = ec2_client.describe_vpc_peering_connections()
        for pc in peerings_resp.get("VpcPeeringConnections", []):
            pc_id = pc["VpcPeeringConnectionId"]
            req_vpc = pc.get("RequesterVpcInfo", {}).get("VpcId")
            acp_vpc = pc.get("AccepterVpcInfo", {}).get("VpcId")
            if (req_vpc == vpc_id or acp_vpc == vpc_id) and pc_id not in immunity_ids:
                logger.info("Deleting VPC Peering Connection: %s", pc_id)
                ec2_client.delete_vpc_peering_connection(VpcPeeringConnectionId=pc_id)
    except Exception as exc:
        logger.error("Failed to delete VPC Peering Connections in VPC %s: %s", vpc_id, exc)

    # 3. Network Interfaces (ENIs)
    try:
        enis_resp = ec2_client.describe_network_interfaces(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
        for eni in enis_resp.get("NetworkInterfaces", []):
            eni_id = eni["NetworkInterfaceId"]
            if eni_id not in immunity_ids:
                attachment = eni.get("Attachment", {})
                if attachment:
                    attachment_id = attachment.get("AttachmentId")
                    logger.info("Detaching ENI %s", eni_id)
                    try:
                        ec2_client.detach_network_interface(AttachmentId=attachment_id, Force=True)
                    except Exception as det_exc:
                        logger.warning("Failed to detach ENI %s: %s", eni_id, det_exc)
                logger.info("Deleting ENI: %s", eni_id)
                try:
                    ec2_client.delete_network_interface(NetworkInterfaceId=eni_id)
                except Exception as del_exc:
                    logger.warning("Failed to delete ENI %s: %s (will retry or ignore)", eni_id, del_exc)
    except Exception as exc:
        logger.error("Failed to handle ENIs in VPC %s: %s", vpc_id, exc)

    # 4. Internet Gateways
    try:
        igws_resp = ec2_client.describe_internet_gateways(Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}])
        for igw in igws_resp.get("InternetGateways", []):
            igw_id = igw["InternetGatewayId"]
            if igw_id not in immunity_ids:
                logger.info("Detaching Internet Gateway %s from VPC %s", igw_id, vpc_id)
                try:
                    ec2_client.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
                except Exception as det_exc:
                    logger.warning("Failed to detach IGW %s: %s", igw_id, det_exc)
                logger.info("Deleting Internet Gateway: %s", igw_id)
                try:
                    ec2_client.delete_internet_gateway(InternetGatewayId=igw_id)
                except Exception as del_exc:
                    logger.warning("Failed to delete IGW %s: %s", igw_id, del_exc)
    except Exception as exc:
        logger.error("Failed to handle Internet Gateways in VPC %s: %s", vpc_id, exc)

    # 5. Route Tables
    try:
        rts_resp = ec2_client.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
        for rt in rts_resp.get("RouteTables", []):
            rt_id = rt["RouteTableId"]
            is_main = any(assoc.get("Main", False) for assoc in rt.get("Associations", []))
            if is_main:
                continue
            if rt_id not in immunity_ids:
                for assoc in rt.get("Associations", []):
                    assoc_id = assoc.get("RouteTableAssociationId")
                    if assoc_id:
                        logger.info("Disassociating route table association %s", assoc_id)
                        try:
                            ec2_client.disassociate_route_table(AssociationId=assoc_id)
                        except Exception as dis_exc:
                            logger.warning("Failed to disassociate route table %s: %s", rt_id, dis_exc)
                logger.info("Deleting Route Table: %s", rt_id)
                try:
                    ec2_client.delete_route_table(RouteTableId=rt_id)
                except Exception as del_exc:
                    logger.warning("Failed to delete Route Table %s: %s", rt_id, del_exc)
    except Exception as exc:
        logger.error("Failed to handle Route Tables in VPC %s: %s", vpc_id, exc)

    # 6. Security Groups
    try:
        sgs_resp = ec2_client.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
        # First revoke rules to break circular dependencies
        for sg in sgs_resp.get("SecurityGroups", []):
            sg_id = sg["GroupId"]
            if sg.get("GroupName") == "default":
                continue
            if sg_id not in immunity_ids:
                if sg.get("IpPermissions"):
                    try:
                        ec2_client.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=sg["IpPermissions"])
                    except Exception as rev_exc:
                        logger.warning("Failed to revoke ingress rules for SG %s: %s", sg_id, rev_exc)
                if sg.get("IpPermissionsEgress"):
                    try:
                        ec2_client.revoke_security_group_egress(GroupId=sg_id, IpPermissions=sg["IpPermissionsEgress"])
                    except Exception as rev_exc:
                        logger.warning("Failed to revoke egress rules for SG %s: %s", sg_id, rev_exc)

        # Then delete security groups
        for sg in sgs_resp.get("SecurityGroups", []):
            sg_id = sg["GroupId"]
            if sg.get("GroupName") == "default":
                continue
            if sg_id not in immunity_ids:
                logger.info("Deleting Security Group: %s", sg_id)
                try:
                    ec2_client.delete_security_group(GroupId=sg_id)
                except Exception as del_exc:
                    logger.warning("Failed to delete Security Group %s: %s", sg_id, del_exc)
    except Exception as exc:
        logger.error("Failed to handle Security Groups in VPC %s: %s", vpc_id, exc)

    # 7. Subnets
    try:
        subnets_resp = ec2_client.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
        for subnet in subnets_resp.get("Subnets", []):
            subnet_id = subnet["SubnetId"]
            if subnet_id not in immunity_ids:
                logger.info("Deleting Subnet: %s", subnet_id)
                try:
                    ec2_client.delete_subnet(SubnetId=subnet_id)
                except Exception as del_exc:
                    logger.warning("Failed to delete Subnet %s: %s", subnet_id, del_exc)
    except Exception as exc:
        logger.error("Failed to handle Subnets in VPC %s: %s", vpc_id, exc)

    # 8. Finally, delete VPC
    logger.info("Deleting VPC: %s", vpc_id)
    try:
        ec2_client.delete_vpc(VpcId=vpc_id)
    except Exception as exc:
        logger.error("Failed to delete VPC %s: %s", vpc_id, exc)


def evaluate_purge_plan(
    resource_plan: Dict[str, List[Dict[str, Any]]],
    dry_run: bool,
    context: Any = None,
    immunity_ids: Set[str] = None
) -> Dict[str, Any]:
    """Build the final purge plan and execute deletion if dry-run is disabled."""
    if immunity_ids is None:
        immunity_ids = set()

    result = {
        "dry_run": dry_run,
        "summary": {k: len(v) for k, v in resource_plan.items()},
        "resources": resource_plan,
        "deleted": {k: [] for k in resource_plan.keys()},
        "failures": {k: [] for k in resource_plan.keys()},
        "message": "Dry-run enabled. No resources were deleted."
    }

    purge_ec2_instances = os.environ.get("PURGE_EC2_INSTANCES", "true").lower() == "true"
    purge_nat_gateways = os.environ.get("PURGE_NAT_GATEWAYS", "true").lower() == "true"
    purge_ebs_volumes = os.environ.get("PURGE_EBS_VOLUMES", "true").lower() == "true"
    purge_rds_instances = os.environ.get("PURGE_RDS_INSTANCES", "true").lower() == "true"
    purge_load_balancers = os.environ.get("PURGE_LOAD_BALANCERS", "true").lower() == "true"
    purge_security_groups = os.environ.get("PURGE_SECURITY_GROUPS", "true").lower() == "true"
    purge_auto_scaling_groups = os.environ.get("PURGE_AUTO_SCALING_GROUPS", "true").lower() == "true"
    purge_ecs_clusters = os.environ.get("PURGE_ECS_CLUSTERS", "true").lower() == "true"
    purge_elasticache_clusters = os.environ.get("PURGE_ELASTICACHE_CLUSTERS", "true").lower() == "true"
    purge_prometheus_workspaces = os.environ.get("PURGE_PROMETHEUS_WORKSPACES", "true").lower() == "true"
    purge_s3_buckets = os.environ.get("PURGE_S3_BUCKETS", "false").lower() == "true"
    purge_iam_roles = os.environ.get("PURGE_IAM_ROLES", "false").lower() == "true"
    purge_iam_users = os.environ.get("PURGE_IAM_USERS", "true").lower() == "true"
    purge_vpcs = os.environ.get("PURGE_VPCS", "false").lower() == "true"

    if not dry_run:
        logger.info("Dry-run is disabled. Executing resource purge...")

        # 1. ECS Clusters
        if purge_ecs_clusters:
            for cluster in resource_plan.get("ecs_clusters", []):
                cluster_name = cluster["id"]
                try:
                    logger.info("Deleting ECS Cluster: %s", cluster_name)
                    ecs_client.delete_cluster(cluster=cluster_name)
                    result["deleted"]["ecs_clusters"].append(cluster_name)
                except Exception as exc:
                    logger.error("Failed to delete ECS Cluster %s: %s", cluster_name, exc)
                    result["failures"]["ecs_clusters"].append({"id": cluster_name, "error": str(exc)})

        # 2. Auto Scaling Groups
        if purge_auto_scaling_groups:
            for asg in resource_plan.get("auto_scaling_groups", []):
                asg_name = asg["id"]
                try:
                    logger.info("Deleting Auto Scaling Group: %s", asg_name)
                    autoscaling_client.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
                    result["deleted"]["auto_scaling_groups"].append(asg_name)
                except Exception as exc:
                    logger.error("Failed to delete Auto Scaling Group %s: %s", asg_name, exc)
                    result["failures"]["auto_scaling_groups"].append({"id": asg_name, "error": str(exc)})

        # 3. EC2 Instances
        if purge_ec2_instances:
            for instance in resource_plan.get("ec2_instances", []):
                instance_id = instance["id"]
                try:
                    logger.info("Terminating EC2 instance: %s", instance_id)
                    ec2_client.terminate_instances(InstanceIds=[instance_id])
                    result["deleted"]["ec2_instances"].append(instance_id)
                except Exception as exc:
                    logger.error("Failed to terminate EC2 instance %s: %s", instance_id, exc)
                    result["failures"]["ec2_instances"].append({"id": instance_id, "error": str(exc)})

        # 4. RDS Instances
        if purge_rds_instances:
            for db in resource_plan.get("rds_instances", []):
                db_id = db["id"]
                try:
                    logger.info("Deleting RDS DB instance: %s", db_id)
                    rds_client.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True)
                    result["deleted"]["rds_instances"].append(db_id)
                except Exception as exc:
                    logger.error("Failed to delete RDS instance %s: %s", db_id, exc)
                    result["failures"]["rds_instances"].append({"id": db_id, "error": str(exc)})

        # 5. ElastiCache Clusters
        if purge_elasticache_clusters:
            for ec in resource_plan.get("elasticache_clusters", []):
                ec_id = ec["id"]
                try:
                    if ec.get("is_replication_group"):
                        logger.info("Deleting ElastiCache Replication Group: %s", ec_id)
                        elasticache_client.delete_replication_group(ReplicationGroupId=ec_id, RetainPrimaryCluster=False)
                    else:
                        logger.info("Deleting ElastiCache Cache Cluster: %s", ec_id)
                        elasticache_client.delete_cache_cluster(CacheClusterId=ec_id)
                    result["deleted"]["elasticache_clusters"].append(ec_id)
                except Exception as exc:
                    logger.error("Failed to delete ElastiCache resource %s: %s", ec_id, exc)
                    result["failures"]["elasticache_clusters"].append({"id": ec_id, "error": str(exc)})

        # 6. AMP Workspaces
        if purge_prometheus_workspaces:
            for ws in resource_plan.get("prometheus_workspaces", []):
                ws_id = ws["id"]
                try:
                    logger.info("Deleting AMP Workspace: %s", ws_id)
                    amp_client.delete_workspace(workspaceId=ws_id)
                    result["deleted"]["prometheus_workspaces"].append(ws_id)
                except Exception as exc:
                    logger.error("Failed to delete AMP workspace %s: %s", ws_id, exc)
                    result["failures"]["prometheus_workspaces"].append({"id": ws_id, "error": str(exc)})

        # 7. Load Balancers
        if purge_load_balancers:
            for lb in resource_plan.get("load_balancers", []):
                lb_arn = lb["arn"]
                try:
                    logger.info("Deleting Load Balancer: %s", lb_arn)
                    elb_client.delete_load_balancer(LoadBalancerArn=lb_arn)
                    result["deleted"]["load_balancers"].append(lb_arn)
                except Exception as exc:
                    logger.error("Failed to delete Load Balancer %s: %s", lb_arn, exc)
                    result["failures"]["load_balancers"].append({"arn": lb_arn, "error": str(exc)})

        # 8. NAT Gateways
        if purge_nat_gateways:
            for gateway in resource_plan.get("nat_gateways", []):
                gw_id = gateway["id"]
                try:
                    logger.info("Deleting NAT Gateway: %s", gw_id)
                    ec2_client.delete_nat_gateway(NatGatewayId=gw_id)
                    result["deleted"]["nat_gateways"].append(gw_id)
                except Exception as exc:
                    logger.error("Failed to delete NAT Gateway %s: %s", gw_id, exc)
                    result["failures"]["nat_gateways"].append({"id": gw_id, "error": str(exc)})

        # 9. EBS Volumes
        if purge_ebs_volumes:
            for volume in resource_plan.get("ebs_volumes", []):
                vol_id = volume["id"]
                try:
                    logger.info("Deleting EBS volume: %s", vol_id)
                    ec2_client.delete_volume(VolumeId=vol_id)
                    result["deleted"]["ebs_volumes"].append(vol_id)
                except Exception as exc:
                    logger.error("Failed to delete EBS volume %s: %s", vol_id, exc)
                    result["failures"]["ebs_volumes"].append({"id": vol_id, "error": str(exc)})

        # 10. S3 Buckets
        if purge_s3_buckets:
            for bucket in resource_plan.get("s3_buckets", []):
                bucket_name = bucket["id"]
                if bucket_name == os.environ.get("STATE_BUCKET_NAME"):
                    logger.warning("Bypassing self-destruction of state bucket: %s", bucket_name)
                    continue
                try:
                    logger.info("Emptying S3 bucket: %s", bucket_name)
                    delete_s3_bucket_contents(bucket_name)
                    logger.info("Deleting S3 bucket: %s", bucket_name)
                    s3_client.delete_bucket(Bucket=bucket_name)
                    result["deleted"]["s3_buckets"].append(bucket_name)
                except Exception as exc:
                    logger.error("Failed to delete S3 bucket %s: %s", bucket_name, exc)
                    result["failures"]["s3_buckets"].append({"id": bucket_name, "error": str(exc)})

        # 11. IAM Users
        if purge_iam_users:
            for user in resource_plan.get("iam_users", []):
                user_name = user["id"]
                try:
                    logger.info("Deleting IAM User: %s", user_name)
                    delete_iam_user(user_name)
                    result["deleted"]["iam_users"].append(user_name)
                except Exception as exc:
                    logger.error("Failed to delete IAM User %s: %s", user_name, exc)
                    result["failures"]["iam_users"].append({"id": user_name, "error": str(exc)})

        # 12. IAM Roles
        if purge_iam_roles:
            for role in resource_plan.get("iam_roles", []):
                role_name = role["id"]
                try:
                    logger.info("Deleting IAM Role: %s", role_name)
                    delete_iam_role(role_name)
                    result["deleted"]["iam_roles"].append(role_name)
                except Exception as exc:
                    logger.error("Failed to delete IAM Role %s: %s", role_name, exc)
                    result["failures"]["iam_roles"].append({"id": role_name, "error": str(exc)})

        # 13. VPCs
        if purge_vpcs:
            for vpc in resource_plan.get("vpcs", []):
                vpc_id = vpc["id"]
                try:
                    logger.info("Deleting VPC: %s", vpc_id)
                    delete_vpc_resources(vpc_id, immunity_ids)
                    result["deleted"]["vpcs"].append(vpc_id)
                except Exception as exc:
                    logger.error("Failed to delete VPC %s: %s", vpc_id, exc)
                    result["failures"]["vpcs"].append({"id": vpc_id, "error": str(exc)})

        # 14. Security Groups (remaining non-default)
        if purge_security_groups:
            for sg in resource_plan.get("security_groups", []):
                sg_id = sg["id"]
                try:
                    logger.info("Deleting Security Group: %s", sg_id)
                    ec2_client.delete_security_group(GroupId=sg_id)
                    result["deleted"]["security_groups"].append(sg_id)
                except Exception as exc:
                    logger.error("Failed to delete Security Group %s: %s", sg_id, exc)
                    result["failures"]["security_groups"].append({"id": sg_id, "error": str(exc)})

        total_success = sum(len(v) for v in result["deleted"].values())
        total_fail = sum(len(v) for v in result["failures"].values())
        result["message"] = f"Purge executed: {total_success} resources successfully deleted, {total_fail} failures."

    return result

