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


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Entry point for the Heliopause cleanup Lambda."""
    state_bucket = os.environ["STATE_BUCKET_NAME"]
    state_prefix = os.environ.get("STATE_PREFIX", "heliopause/statefiles/")
    core_state_file = os.environ.get("CORE_STATE_FILE", "heliopause.tfstate")
    dry_run = os.environ.get("DRY_RUN", "true").lower() == "true"
    sns_topic_arn = os.environ.get("SNS_TOPIC_ARN")

    logger.info("Heliopause starting: dry_run=%s, bucket=%s, prefix=%s, core_file=%s", dry_run, state_bucket, state_prefix, core_state_file)

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

    resource_plan = scan_for_purge_candidates(immunity_ids)
    result = evaluate_purge_plan(resource_plan, dry_run)

    # Publish summary to SNS
    if sns_topic_arn:
        total_deleted = sum(result["summary"].values()) if not dry_run else 0
        if dry_run:
            message = f"Dry-run completed. {sum(result['summary'].values())} AWS resources would be deleted. See CloudWatch logs for details."
        else:
            message = f"{total_deleted} AWS resources deleted in this run. See CloudWatch logs for details."
        publish_to_sns(sns_topic_arn, "Heliopause Summary", message)

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


def scan_for_purge_candidates(immunity_ids: Set[str]) -> Dict[str, List[Dict[str, Any]]]:
    """Scan AWS resources and identify candidates not present in the immunity list."""
    candidates: Dict[str, List[Dict[str, Any]]] = {
        "ec2_instances": [],
        "nat_gateways": [],
        "ebs_volumes": [],
        "rds_instances": [],
        "load_balancers": [],
    }

    candidates["ec2_instances"] = scan_ec2_instances(immunity_ids)
    candidates["nat_gateways"] = scan_nat_gateways(immunity_ids)
    candidates["ebs_volumes"] = scan_ebs_volumes(immunity_ids)
    candidates["rds_instances"] = scan_rds_instances(immunity_ids)
    candidates["load_balancers"] = scan_load_balancers(immunity_ids)

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


def evaluate_purge_plan(resource_plan: Dict[str, List[Dict[str, Any]]], dry_run: bool) -> Dict[str, Any]:
    """Build the final purge plan. This function is a safe stub for future destruction logic."""
    result = {
        "dry_run": dry_run,
        "summary": {k: len(v) for k, v in resource_plan.items()},
        "resources": resource_plan,
        "message": "No destructive actions were executed. Implement purge logic in evaluate_purge_plan().",
    }

    if not dry_run:
        result["message"] = "Dry-run disabled. Purge operations are not yet implemented in this framework."

    return result
