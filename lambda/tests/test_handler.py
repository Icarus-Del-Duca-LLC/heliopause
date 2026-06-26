import json
import os
import pytest
from unittest.mock import MagicMock, patch, call
from handler import (
    lambda_handler,
    list_state_files,
    build_immunity_list,
    load_state_file,
    extract_resource_ids,
    scan_for_purge_candidates,
    scan_ec2_instances,
    scan_nat_gateways,
    scan_ebs_volumes,
    scan_rds_instances,
    scan_load_balancers,
    evaluate_purge_plan,
    state_file_exists,
    publish_to_sns,
)


@pytest.fixture
def mock_env():
    """Mock environment variables."""
    return {
        "STATE_BUCKET_NAME": "test-bucket",
        "STATE_PREFIX": "test-prefix/",
        "CORE_STATE_FILE": "heliopause.tfstate",
        "DRY_RUN": "true",
        "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123456789012:test-topic",
    }


@patch.dict(os.environ, {"STATE_BUCKET_NAME": "test-bucket", "STATE_PREFIX": "test-prefix/", "CORE_STATE_FILE": "heliopause.tfstate", "DRY_RUN": "true", "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123456789012:test-topic"})
@patch("handler.state_file_exists")
@patch("handler.list_state_files")
@patch("handler.build_immunity_list")
@patch("handler.scan_for_purge_candidates")
@patch("handler.evaluate_purge_plan")
@patch("handler.publish_to_sns")
def test_lambda_handler_success(mock_publish, mock_evaluate, mock_scan, mock_build, mock_list, mock_exists):
    """Test successful lambda_handler execution."""
    mock_exists.return_value = True
    mock_list.return_value = ["test-prefix/heliopause.tfstate"]
    mock_build.return_value = {"id1", "id2"}
    mock_scan.return_value = {"ec2_instances": []}
    mock_evaluate.return_value = {"dry_run": True, "summary": {"ec2_instances": 0}}

    event = {}
    context = MagicMock()

    result = lambda_handler(event, context)

    assert result["dry_run"] is True
    mock_exists.assert_called_once_with("test-bucket", "test-prefix/heliopause.tfstate")
    mock_publish.assert_called_once()


@patch.dict(os.environ, {"STATE_BUCKET_NAME": "test-bucket", "STATE_PREFIX": "test-prefix/", "CORE_STATE_FILE": "heliopause.tfstate", "DRY_RUN": "false", "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123456789012:test-topic"})
@patch("handler.state_file_exists")
@patch("handler.publish_to_sns")
def test_lambda_handler_core_file_missing(mock_publish, mock_exists):
    """Test lambda_handler aborts when core state file is missing and dry-run is disabled."""
    mock_exists.return_value = False

    event = {}
    context = MagicMock()

    with pytest.raises(RuntimeError, match="Core state file 'test-prefix/heliopause.tfstate' is missing"):
        lambda_handler(event, context)

    mock_publish.assert_called_once()


@patch.dict(os.environ, {"STATE_BUCKET_NAME": "test-bucket", "STATE_PREFIX": "test-prefix/", "CORE_STATE_FILE": "heliopause.tfstate", "DRY_RUN": "true", "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123456789012:test-topic"})
@patch("handler.state_file_exists")
@patch("handler.list_state_files")
@patch("handler.build_immunity_list")
@patch("handler.scan_for_purge_candidates")
@patch("handler.evaluate_purge_plan")
@patch("handler.publish_to_sns")
def test_lambda_handler_core_file_missing_dry_run(mock_publish, mock_evaluate, mock_scan, mock_build, mock_list, mock_exists):
    """Test lambda_handler proceeds when core state file is missing but dry-run is enabled."""
    mock_exists.return_value = False
    mock_list.return_value = []
    mock_build.return_value = set()
    mock_scan.return_value = {"ec2_instances": []}
    mock_evaluate.return_value = {"dry_run": True, "summary": {"ec2_instances": 0}}

    event = {}
    context = MagicMock()

    result = lambda_handler(event, context)

    assert result["dry_run"] is True
    mock_publish.assert_called_once()


@patch("handler.s3_client")
def test_list_state_files(mock_s3):
    """Test listing state files."""
    mock_paginator = MagicMock()
    mock_s3.get_paginator.return_value = mock_paginator
    mock_paginator.paginate.return_value = [
        {"Contents": [{"Key": "test-prefix/file1.tfstate"}, {"Key": "test-prefix/file2.txt"}]}
    ]

    result = list_state_files("test-bucket", "test-prefix/")

    assert result == ["test-prefix/file1.tfstate"]
    mock_s3.get_paginator.assert_called_once_with("list_objects_v2")


@patch("handler.s3_client")
def test_build_immunity_list(mock_s3):
    """Test building immunity list from state files."""
    mock_s3.get_object.return_value = {
        "Body": MagicMock(read=MagicMock(return_value=json.dumps({
            "resources": [{"instances": [{"attributes": {"id": "test-id"}}]}]
        }).encode("utf-8")))
    }

    result = build_immunity_list("test-bucket", ["test-prefix/file.tfstate"])

    assert "test-id" in result


def test_extract_resource_ids():
    """Test extracting resource IDs from state data."""
    state_data = {
        "resources": [
            {"instances": [{"attributes": {"id": "id1"}}, {"attributes": {"id": "id2"}}]}
        ]
    }

    result = extract_resource_ids(state_data)

    assert result == {"id1", "id2"}


@patch("handler.ec2_client")
def test_scan_ec2_instances(mock_ec2):
    """Test scanning EC2 instances."""
    mock_paginator = MagicMock()
    mock_ec2.get_paginator.return_value = mock_paginator
    mock_paginator.paginate.return_value = [
        {"Reservations": [{"Instances": [{"InstanceId": "i-123", "InstanceType": "t2.micro", "State": {"Name": "running"}}]}]}
    ]

    result = scan_ec2_instances(set())

    assert len(result) == 1
    assert result[0]["id"] == "i-123"


@patch("handler.ec2_client")
def test_scan_nat_gateways(mock_ec2):
    """Test scanning NAT gateways."""
    mock_ec2.describe_nat_gateways.return_value = {
        "NatGateways": [{"NatGatewayId": "nat-123", "State": "available"}]
    }

    result = scan_nat_gateways(set())

    assert len(result) == 1
    assert result[0]["id"] == "nat-123"


@patch("handler.ec2_client")
def test_scan_ebs_volumes(mock_ec2):
    """Test scanning EBS volumes."""
    mock_paginator = MagicMock()
    mock_ec2.get_paginator.return_value = mock_paginator
    mock_paginator.paginate.return_value = [
        {"Volumes": [{"VolumeId": "vol-123", "Size": 10, "State": "available", "Attachments": []}]}
    ]

    result = scan_ebs_volumes(set())

    assert len(result) == 1
    assert result[0]["id"] == "vol-123"


@patch("handler.rds_client")
def test_scan_rds_instances(mock_rds):
    """Test scanning RDS instances."""
    mock_rds.describe_db_instances.return_value = {
        "DBInstances": [{"DBInstanceIdentifier": "db-123", "DBInstanceStatus": "available"}]
    }

    result = scan_rds_instances(set())

    assert len(result) == 1
    assert result[0]["id"] == "db-123"


@patch("handler.elb_client")
def test_scan_load_balancers(mock_elb):
    """Test scanning load balancers."""
    mock_elb.describe_load_balancers.return_value = {
        "LoadBalancers": [{"LoadBalancerArn": "arn:aws:elb:123", "LoadBalancerName": "lb-123", "Type": "application"}]
    }

    result = scan_load_balancers(set())

    assert len(result) == 1
    assert result[0]["name"] == "lb-123"


def test_evaluate_purge_plan():
    """Test evaluating purge plan."""
    resource_plan = {"ec2_instances": [{"id": "i-123"}]}

    result = evaluate_purge_plan(resource_plan, True)

    assert result["dry_run"] is True
    assert result["summary"]["ec2_instances"] == 1


@patch("handler.s3_client")
def test_state_file_exists_true(mock_s3):
    """Test state file exists."""
    mock_s3.head_object.return_value = {}

    result = state_file_exists("test-bucket", "test-key")

    assert result is True


@patch("handler.s3_client")
def test_state_file_exists_false(mock_s3):
    """Test state file does not exist."""
    from botocore.exceptions import ClientError
    mock_s3.head_object.side_effect = ClientError({"Error": {"Code": "404"}}, "HeadObject")

    result = state_file_exists("test-bucket", "test-key")

    assert result is False


@patch("handler.sns_client")
def test_publish_to_sns(mock_sns):
    """Test publishing to SNS."""
    publish_to_sns("arn:aws:sns:123", "Test Subject", "Test Message")

    mock_sns.publish.assert_called_once_with(
        TopicArn="arn:aws:sns:123",
        Subject="Test Subject",
        Message="Test Message"
    )
