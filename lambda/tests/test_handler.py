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
    scan_security_groups,
    scan_auto_scaling_groups,
    scan_ecs_clusters,
    scan_elasticache_clusters,
    scan_prometheus_workspaces,
    scan_s3_buckets,
    scan_iam_roles,
    scan_iam_users,
    scan_vpcs,
    delete_s3_bucket_contents,
    delete_iam_role,
    delete_iam_user,
    delete_vpc_resources,
    evaluate_purge_plan,
    get_extra_immune_iam_arns,
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


@patch.dict(os.environ, {
    "PURGE_EC2_INSTANCES": "true",
    "PURGE_NAT_GATEWAYS": "true",
    "PURGE_EBS_VOLUMES": "true",
    "PURGE_RDS_INSTANCES": "true",
    "PURGE_LOAD_BALANCERS": "true",
    "PURGE_SECURITY_GROUPS": "true",
    "PURGE_AUTO_SCALING_GROUPS": "true",
    "PURGE_ECS_CLUSTERS": "true",
    "PURGE_ELASTICACHE_CLUSTERS": "true",
    "PURGE_PROMETHEUS_WORKSPACES": "true",
    "PURGE_S3_BUCKETS": "true",
    "PURGE_IAM_ROLES": "true",
    "PURGE_IAM_USERS": "true",
    "PURGE_VPCS": "true",
})
@patch("handler.sts_client")
@patch("handler.ec2_client")
@patch("handler.rds_client")
@patch("handler.elb_client")
@patch("handler.autoscaling_client")
@patch("handler.ecs_client")
@patch("handler.elasticache_client")
@patch("handler.amp_client")
@patch("handler.s3_client")
@patch("handler.iam_client")
def test_evaluate_purge_plan_live(mock_iam, mock_s3, mock_amp, mock_elasticache, mock_ecs, mock_asg, mock_elb, mock_rds, mock_ec2, mock_sts):
    """Test evaluating purge plan and deleting resources when dry-run is disabled."""
    mock_sts.get_caller_identity.return_value = {"Arn": "arn:aws:iam::123:role/some-role"}
    
    # Mock paginators for S3 and IAM delete helpers
    mock_paginator_ov = MagicMock()
    mock_paginator_mu = MagicMock()
    mock_s3.get_paginator.side_effect = lambda service: mock_paginator_ov if service == "list_object_versions" else mock_paginator_mu
    mock_paginator_ov.paginate.return_value = [{"Versions": [], "DeleteMarkers": []}]
    mock_paginator_mu.paginate.return_value = [{"Uploads": []}]
    
    mock_paginator_ap = MagicMock()
    mock_paginator_rp = MagicMock()
    mock_iam.get_paginator.side_effect = lambda service: mock_paginator_ap if service == "list_attached_role_policies" else mock_paginator_rp
    mock_paginator_ap.paginate.return_value = [{"AttachedPolicies": []}]
    mock_paginator_rp.paginate.return_value = [{"PolicyNames": []}]
    mock_iam.list_instance_profiles_for_role.return_value = {"InstanceProfiles": []}

    # Mock VPC describes for VPC delete helper
    mock_ec2.describe_vpc_endpoints.return_value = {"VpcEndpoints": []}
    mock_ec2.describe_vpc_peering_connections.return_value = {"VpcPeeringConnections": []}
    mock_ec2.describe_network_interfaces.return_value = {"NetworkInterfaces": []}
    mock_ec2.describe_internet_gateways.return_value = {"InternetGateways": []}
    mock_ec2.describe_route_tables.return_value = {"RouteTables": []}
    mock_ec2.describe_security_groups.return_value = {"SecurityGroups": []}
    mock_ec2.describe_subnets.return_value = {"Subnets": []}

    resource_plan = {
        "ec2_instances": [{"id": "i-123"}],
        "nat_gateways": [{"id": "nat-123"}],
        "ebs_volumes": [{"id": "vol-123"}],
        "rds_instances": [{"id": "db-123"}],
        "load_balancers": [{"arn": "arn:aws:elb:123"}],
        "security_groups": [{"id": "sg-123"}],
        "auto_scaling_groups": [{"id": "asg-123"}],
        "ecs_clusters": [{"id": "cluster-123"}],
        "elasticache_clusters": [{"id": "cc-123", "is_replication_group": False}, {"id": "rg-123", "is_replication_group": True}],
        "prometheus_workspaces": [{"id": "ws-123"}],
        "s3_buckets": [{"id": "bucket-123"}],
        "iam_roles": [{"id": "role-123"}],
        "iam_users": [{"id": "user-123"}],
        "vpcs": [{"id": "vpc-123"}],
    }

    result = evaluate_purge_plan(resource_plan, False)

    assert result["dry_run"] is False
    assert "i-123" in result["deleted"]["ec2_instances"]
    assert "nat-123" in result["deleted"]["nat_gateways"]
    assert "vol-123" in result["deleted"]["ebs_volumes"]
    assert "db-123" in result["deleted"]["rds_instances"]
    assert "arn:aws:elb:123" in result["deleted"]["load_balancers"]
    assert "sg-123" in result["deleted"]["security_groups"]
    assert "asg-123" in result["deleted"]["auto_scaling_groups"]
    assert "cluster-123" in result["deleted"]["ecs_clusters"]
    assert "cc-123" in result["deleted"]["elasticache_clusters"]
    assert "rg-123" in result["deleted"]["elasticache_clusters"]
    assert "ws-123" in result["deleted"]["prometheus_workspaces"]
    assert "bucket-123" in result["deleted"]["s3_buckets"]
    assert "role-123" in result["deleted"]["iam_roles"]
    assert "user-123" in result["deleted"]["iam_users"]
    assert "vpc-123" in result["deleted"]["vpcs"]

    mock_ec2.terminate_instances.assert_called_once_with(InstanceIds=["i-123"])
    mock_ec2.delete_nat_gateway.assert_called_once_with(NatGatewayId="nat-123")
    mock_ec2.delete_volume.assert_called_once_with(VolumeId="vol-123")
    mock_rds.delete_db_instance.assert_called_once_with(DBInstanceIdentifier="db-123", SkipFinalSnapshot=True)
    mock_elb.delete_load_balancer.assert_called_once_with(LoadBalancerArn="arn:aws:elb:123")
    mock_ec2.delete_security_group.assert_called_once_with(GroupId="sg-123")
    mock_asg.delete_auto_scaling_group.assert_called_once_with(AutoScalingGroupName="asg-123", ForceDelete=True)
    mock_ecs.delete_cluster.assert_called_once_with(cluster="cluster-123")
    mock_elasticache.delete_cache_cluster.assert_called_once_with(CacheClusterId="cc-123")
    mock_elasticache.delete_replication_group.assert_called_once_with(ReplicationGroupId="rg-123", RetainPrimaryCluster=False)
    mock_amp.delete_workspace.assert_called_once_with(workspaceId="ws-123")
    mock_s3.delete_bucket.assert_called_once_with(Bucket="bucket-123")
    mock_iam.delete_role.assert_called_once_with(RoleName="role-123")
    mock_iam.delete_user.assert_called_once_with(UserName="user-123")
    mock_ec2.delete_vpc.assert_called_once_with(VpcId="vpc-123")


@patch("handler.ec2_client")
def test_scan_security_groups(mock_ec2):
    """Test scanning security groups."""
    mock_ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {"GroupId": "sg-123", "GroupName": "test-sg", "VpcId": "vpc-123"},
            {"GroupId": "sg-default", "GroupName": "default", "VpcId": "vpc-123"},
        ]
    }
    result = scan_security_groups(set())
    assert len(result) == 1
    assert result[0]["id"] == "sg-123"


@patch("handler.autoscaling_client")
def test_scan_auto_scaling_groups(mock_asg):
    """Test scanning Auto Scaling Groups."""
    mock_paginator = MagicMock()
    mock_asg.get_paginator.return_value = mock_paginator
    mock_paginator.paginate.return_value = [
        {"AutoScalingGroups": [{"AutoScalingGroupName": "asg-123", "AutoScalingGroupARN": "arn:aws:asg:123", "Status": "Healthy"}]}
    ]
    result = scan_auto_scaling_groups(set())
    assert len(result) == 1
    assert result[0]["id"] == "asg-123"


@patch("handler.ecs_client")
def test_scan_ecs_clusters(mock_ecs):
    """Test scanning ECS clusters."""
    mock_ecs.list_clusters.return_value = {"clusterArns": ["arn:aws:ecs:123"]}
    mock_ecs.describe_clusters.return_value = {
        "clusters": [{"clusterName": "cluster-123", "clusterArn": "arn:aws:ecs:123", "status": "ACTIVE"}]
    }
    result = scan_ecs_clusters(set())
    assert len(result) == 1
    assert result[0]["id"] == "cluster-123"


@patch("handler.elasticache_client")
def test_scan_elasticache_clusters(mock_elasticache):
    """Test scanning ElastiCache clusters."""
    mock_paginator_cc = MagicMock()
    mock_paginator_rg = MagicMock()
    mock_elasticache.get_paginator.side_effect = lambda service: mock_paginator_cc if service == "describe_cache_clusters" else mock_paginator_rg
    mock_paginator_cc.paginate.return_value = [
        {"CacheClusters": [{"CacheClusterId": "cc-123", "Engine": "redis", "CacheClusterStatus": "available"}]}
    ]
    mock_paginator_rg.paginate.return_value = [
        {"ReplicationGroups": [{"ReplicationGroupId": "rg-123", "Status": "available"}]}
    ]
    result = scan_elasticache_clusters(set())
    assert len(result) == 2
    assert {c["id"] for c in result} == {"cc-123", "rg-123"}


@patch("handler.amp_client")
def test_scan_prometheus_workspaces(mock_amp):
    """Test scanning Prometheus workspaces."""
    mock_amp.list_workspaces.return_value = {
        "workspaces": [{"workspaceId": "ws-123", "arn": "arn:aws:aps:ws-123", "status": {"statusCode": "ACTIVE"}}]
    }
    result = scan_prometheus_workspaces(set())
    assert len(result) == 1
    assert result[0]["id"] == "ws-123"


@patch.dict(os.environ, {"STATE_BUCKET_NAME": "test-bucket"})
@patch("handler.s3_client")
def test_scan_s3_buckets(mock_s3):
    """Test scanning S3 buckets."""
    mock_s3.list_buckets.return_value = {
        "Buckets": [
            {"Name": "test-bucket", "CreationDate": None},
            {"Name": "other-bucket", "CreationDate": None}
        ]
    }
    result = scan_s3_buckets(set())
    assert len(result) == 1
    assert result[0]["id"] == "other-bucket"


@patch("handler.sts_client")
@patch("handler.iam_client")
def test_scan_iam_roles(mock_iam, mock_sts):
    """Test scanning IAM roles."""
    mock_sts.get_caller_identity.return_value = {"Arn": "arn:aws:iam::123:role/heliopause-lambda-role"}
    mock_paginator = MagicMock()
    mock_iam.get_paginator.return_value = mock_paginator
    mock_paginator.paginate.return_value = [
        {"Roles": [
            {"RoleName": "heliopause-lambda-role", "Arn": "arn:aws:iam::123:role/heliopause-lambda-role", "Path": "/"},
            {"RoleName": "custom-role", "Arn": "arn:aws:iam::123:role/custom-role", "Path": "/"},
            {"RoleName": "service-role", "Arn": "arn:aws:iam::123:role/service-role", "Path": "/aws-service-role/some"}
        ]}
    ]
    result = scan_iam_roles(set())
    assert len(result) == 1
    assert result[0]["id"] == "custom-role"


@patch("handler.iam_client")
def test_scan_iam_users(mock_iam):
    """Test scanning IAM users."""
    mock_paginator = MagicMock()
    mock_iam.get_paginator.return_value = mock_paginator
    mock_paginator.paginate.return_value = [
        {"Users": [{"UserName": "user-123", "Arn": "arn:aws:iam::123:user/user-123"}]}
    ]
    result = scan_iam_users(set())
    assert len(result) == 1
    assert result[0]["id"] == "user-123"


@patch("handler.ec2_client")
def test_scan_vpcs(mock_ec2):
    """Test scanning VPCs."""
    mock_ec2.describe_vpcs.return_value = {
        "Vpcs": [
            {"VpcId": "vpc-123", "IsDefault": False, "CidrBlock": "10.0.0.0/16"},
            {"VpcId": "vpc-default", "IsDefault": True, "CidrBlock": "172.31.0.0/16"}
        ]
    }
    result = scan_vpcs(set())
    assert len(result) == 1
    assert result[0]["id"] == "vpc-123"


@patch("handler.s3_client")
def test_delete_s3_bucket_contents(mock_s3):
    """Test deleting S3 bucket contents."""
    mock_paginator_ov = MagicMock()
    mock_paginator_mu = MagicMock()
    mock_s3.get_paginator.side_effect = lambda service: mock_paginator_ov if service == "list_object_versions" else mock_paginator_mu
    
    mock_paginator_ov.paginate.return_value = [
        {"Versions": [{"Key": "k1", "VersionId": "v1"}], "DeleteMarkers": [{"Key": "k2", "VersionId": "v2"}]}
    ]
    mock_paginator_mu.paginate.return_value = [
        {"Uploads": [{"Key": "k3", "UploadId": "u3"}]}
    ]
    
    delete_s3_bucket_contents("test-bucket")
    mock_s3.delete_objects.assert_called_once()
    mock_s3.abort_multipart_upload.assert_called_once_with(Bucket="test-bucket", Key="k3", UploadId="u3")


@patch("handler.sts_client")
@patch("handler.iam_client")
def test_delete_iam_role(mock_iam, mock_sts):
    """Test deleting IAM role."""
    mock_sts.get_caller_identity.return_value = {"Arn": "arn:aws:iam::123:role/some-other-role"}
    mock_paginator_ap = MagicMock()
    mock_paginator_rp = MagicMock()
    mock_iam.get_paginator.side_effect = lambda service: mock_paginator_ap if service == "list_attached_role_policies" else mock_paginator_rp
    
    mock_paginator_ap.paginate.return_value = [{"AttachedPolicies": [{"PolicyArn": "arn:policy"}]}]
    mock_paginator_rp.paginate.return_value = [{"PolicyNames": ["policy-name"]}]
    mock_iam.list_instance_profiles_for_role.return_value = {"InstanceProfiles": [{"InstanceProfileName": "prof"}]}
    
    delete_iam_role("custom-role")
    
    mock_iam.detach_role_policy.assert_called_once_with(RoleName="custom-role", PolicyArn="arn:policy")
    mock_iam.delete_role_policy.assert_called_once_with(RoleName="custom-role", PolicyName="policy-name")
    mock_iam.remove_role_from_instance_profile.assert_called_once_with(InstanceProfileName="prof", RoleName="custom-role")
    mock_iam.delete_role.assert_called_once_with(RoleName="custom-role")


@patch("handler.iam_client")
def test_delete_iam_user(mock_iam):
    """Test deleting IAM user."""
    mock_paginator_ap = MagicMock()
    mock_paginator_up = MagicMock()
    mock_paginator_ak = MagicMock()
    
    def side_effect(service):
        if service == "list_attached_user_policies":
            return mock_paginator_ap
        elif service == "list_user_policies":
            return mock_paginator_up
        else:
            return mock_paginator_ak
            
    mock_iam.get_paginator.side_effect = side_effect
    
    mock_paginator_ap.paginate.return_value = [{"AttachedPolicies": [{"PolicyArn": "arn:policy"}]}]
    mock_paginator_up.paginate.return_value = [{"PolicyNames": ["policy-name"]}]
    mock_paginator_ak.paginate.return_value = [{"AccessKeyMetadata": [{"AccessKeyId": "key-id"}]}]
    
    mock_iam.list_signing_certificates.return_value = {"Certificates": [{"CertificateId": "cert-id"}]}
    mock_iam.list_ssh_public_keys.return_value = {"SSHPublicKeys": [{"SSHPublicKeyId": "ssh-id"}]}
    mock_iam.list_service_specific_credentials.return_value = {"ServiceSpecificCredentials": [{"ServiceSpecificCredentialId": "cred-id"}]}
    mock_iam.list_mfa_devices.return_value = {"MFADevices": [{"SerialNumber": "arn:aws:iam::123:mfa/device"}]}
    
    delete_iam_user("test-user")
    
    mock_iam.detach_user_policy.assert_called_once_with(UserName="test-user", PolicyArn="arn:policy")
    mock_iam.delete_user_policy.assert_called_once_with(UserName="test-user", PolicyName="policy-name")
    mock_iam.delete_access_key.assert_called_once_with(UserName="test-user", AccessKeyId="key-id")
    mock_iam.delete_login_profile.assert_called_once_with(UserName="test-user")
    mock_iam.delete_signing_certificate.assert_called_once_with(UserName="test-user", CertificateId="cert-id")
    mock_iam.delete_ssh_public_key.assert_called_once_with(UserName="test-user", SSHPublicKeyId="ssh-id")
    mock_iam.delete_service_specific_credentials.assert_called_once_with(UserName="test-user", ServiceSpecificCredentialId="cred-id")
    mock_iam.deactivate_mfa_device.assert_called_once_with(UserName="test-user", SerialNumber="arn:aws:iam::123:mfa/device")
    mock_iam.delete_virtual_mfa_device.assert_called_once_with(SerialNumber="arn:aws:iam::123:mfa/device")
    mock_iam.delete_user.assert_called_once_with(UserName="test-user")


@patch("handler.ec2_client")
def test_delete_vpc_resources(mock_ec2):
    """Test deleting VPC resources."""
    mock_ec2.describe_vpc_endpoints.return_value = {"VpcEndpoints": [{"VpcEndpointId": "vpce-123"}]}
    mock_ec2.describe_vpc_peering_connections.return_value = {"VpcPeeringConnections": [{"VpcPeeringConnectionId": "pcx-123", "RequesterVpcInfo": {"VpcId": "vpc-123"}}]}
    mock_ec2.describe_network_interfaces.return_value = {"NetworkInterfaces": [{"NetworkInterfaceId": "eni-123", "Attachment": {"AttachmentId": "eni-attach-123"}}]}
    mock_ec2.describe_internet_gateways.return_value = {"InternetGateways": [{"InternetGatewayId": "igw-123"}]}
    mock_ec2.describe_route_tables.return_value = {"RouteTables": [{"RouteTableId": "rtb-123", "Associations": [{"RouteTableAssociationId": "rtbassoc-123", "Main": False}]}]}
    mock_ec2.describe_security_groups.return_value = {"SecurityGroups": [{"GroupId": "sg-123", "GroupName": "test-sg", "IpPermissions": [{"IpProtocol": "-1"}], "IpPermissionsEgress": [{"IpProtocol": "-1"}]}]}
    mock_ec2.describe_subnets.return_value = {"Subnets": [{"SubnetId": "subnet-123"}]}
    
    delete_vpc_resources("vpc-123", set())
    
    mock_ec2.delete_vpc_endpoints.assert_called_once_with(VpcEndpointIds=["vpce-123"])
    mock_ec2.delete_vpc_peering_connection.assert_called_once_with(VpcPeeringConnectionId="pcx-123")
    mock_ec2.detach_network_interface.assert_called_once_with(AttachmentId="eni-attach-123", Force=True)
    mock_ec2.delete_network_interface.assert_called_once_with(NetworkInterfaceId="eni-123")
    mock_ec2.detach_internet_gateway.assert_called_once_with(InternetGatewayId="igw-123", VpcId="vpc-123")
    mock_ec2.delete_internet_gateway.assert_called_once_with(InternetGatewayId="igw-123")
    mock_ec2.disassociate_route_table.assert_called_once_with(AssociationId="rtbassoc-123")
    mock_ec2.delete_route_table.assert_called_once_with(RouteTableId="rtb-123")
    mock_ec2.revoke_security_group_ingress.assert_called_once_with(GroupId="sg-123", IpPermissions=[{"IpProtocol": "-1"}])
    mock_ec2.revoke_security_group_egress.assert_called_once_with(GroupId="sg-123", IpPermissions=[{"IpProtocol": "-1"}])
    mock_ec2.delete_security_group.assert_called_once_with(GroupId="sg-123")
    mock_ec2.delete_subnet.assert_called_once_with(SubnetId="subnet-123")
    mock_ec2.delete_vpc.assert_called_once_with(VpcId="vpc-123")


def test_get_extra_immune_iam_arns():
    """Test get_extra_immune_iam_arns parsing from environment."""
    with patch.dict(os.environ, {"EXTRA_IMMUNE_IAM_ARNS": '["arn:aws:iam::123:user/test-user", "arn:aws:iam::123:role/test-role"]'}):
        result = get_extra_immune_iam_arns()
        assert result == {"arn:aws:iam::123:user/test-user", "arn:aws:iam::123:role/test-role"}

    with patch.dict(os.environ, {"EXTRA_IMMUNE_IAM_ARNS": "arn:aws:iam::123:user/test-user, arn:aws:iam::123:role/test-role"}):
        result = get_extra_immune_iam_arns()
        assert result == {"arn:aws:iam::123:user/test-user", "arn:aws:iam::123:role/test-role"}

    with patch.dict(os.environ, {}, clear=True):
        result = get_extra_immune_iam_arns()
        assert result == set()


@patch("handler.sts_client")
@patch("handler.iam_client")
def test_scan_iam_roles_extra_immune(mock_iam, mock_sts):
    """Test that roles matching EXTRA_IMMUNE_IAM_ARNS are skipped."""
    mock_sts.get_caller_identity.return_value = {"Arn": "arn:aws:iam::123:role/heliopause-lambda-role"}
    mock_paginator = MagicMock()
    mock_iam.get_paginator.return_value = mock_paginator
    mock_paginator.paginate.return_value = [
        {"Roles": [
            {"RoleName": "heliopause-lambda-role", "Arn": "arn:aws:iam::123:role/heliopause-lambda-role", "Path": "/"},
            {"RoleName": "custom-role", "Arn": "arn:aws:iam::123:role/custom-role", "Path": "/"},
            {"RoleName": "immune-role", "Arn": "arn:aws:iam::123:role/immune-role", "Path": "/"},
        ]}
    ]
    with patch.dict(os.environ, {"EXTRA_IMMUNE_IAM_ARNS": '["arn:aws:iam::123:role/immune-role"]'}):
        result = scan_iam_roles(set())
        assert len(result) == 1
        assert result[0]["id"] == "custom-role"


@patch("handler.iam_client")
def test_scan_iam_users_extra_immune(mock_iam):
    """Test that users matching EXTRA_IMMUNE_IAM_ARNS are skipped."""
    mock_paginator = MagicMock()
    mock_iam.get_paginator.return_value = mock_paginator
    mock_paginator.paginate.return_value = [
        {"Users": [
            {"UserName": "user-123", "Arn": "arn:aws:iam::123:user/user-123"},
            {"UserName": "immune-user", "Arn": "arn:aws:iam::123:user/immune-user"}
        ]}
    ]
    with patch.dict(os.environ, {"EXTRA_IMMUNE_IAM_ARNS": '["arn:aws:iam::123:user/immune-user"]'}):
        result = scan_iam_users(set())
        assert len(result) == 1
        assert result[0]["id"] == "user-123"


@patch.dict(os.environ, {"STATE_BUCKET_NAME": "test-bucket", "STATE_PREFIX": "test-prefix/", "CORE_STATE_FILE": "heliopause.tfstate", "DRY_RUN": "true", "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123456789012:test-topic"})
@patch("handler.state_file_exists")
@patch("handler.list_state_files")
@patch("handler.build_immunity_list")
@patch("handler.scan_for_purge_candidates")
@patch("handler.evaluate_purge_plan")
@patch("handler.publish_to_sns")
def test_lambda_handler_warn_dry_run_true(mock_publish, mock_evaluate, mock_scan, mock_build, mock_list, mock_exists):
    """Event: {"action": "warn"} + DRY_RUN=true -> Short-circuit immediately, no SNS message, no discovery."""
    mock_exists.return_value = True
    event = {"action": "warn"}
    context = MagicMock()
    
    result = lambda_handler(event, context)
    
    assert result["dry_run"] is True
    assert result["action"] == "warn"
    assert "suppressed" in result["message"]
    
    # Discovery/API mocks must NOT be called
    mock_exists.assert_not_called()
    mock_list.assert_not_called()
    mock_build.assert_not_called()
    mock_scan.assert_not_called()
    mock_evaluate.assert_not_called()
    mock_publish.assert_not_called()


@patch.dict(os.environ, {"STATE_BUCKET_NAME": "test-bucket", "STATE_PREFIX": "test-prefix/", "CORE_STATE_FILE": "heliopause.tfstate", "DRY_RUN": "false", "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123456789012:test-topic"})
@patch("handler.state_file_exists")
@patch("handler.list_state_files")
@patch("handler.build_immunity_list")
@patch("handler.scan_for_purge_candidates")
@patch("handler.evaluate_purge_plan")
@patch("handler.publish_to_sns")
def test_lambda_handler_warn_dry_run_false(mock_publish, mock_evaluate, mock_scan, mock_build, mock_list, mock_exists):
    """Event: {"action": "warn"} + DRY_RUN=false -> Run sweep, publish warning to SNS, do NOT delete."""
    mock_exists.return_value = True
    mock_list.return_value = ["test-prefix/heliopause.tfstate"]
    mock_build.return_value = {"id1"}
    mock_scan.return_value = {"ec2_instances": [{"id": "i-warn123"}]}
    mock_evaluate.return_value = {
        "dry_run": True,
        "summary": {"ec2_instances": 1},
        "resources": {"ec2_instances": [{"id": "i-warn123"}]},
        "deleted": {"ec2_instances": []},
        "failures": {"ec2_instances": []}
    }
    
    event = {"action": "warn"}
    context = MagicMock()
    
    result = lambda_handler(event, context)
    
    # Verify deletions were NOT executed (evaluate_purge_plan called with dry_run=True)
    mock_evaluate.assert_called_once_with(mock_scan.return_value, True, context=context, immunity_ids={"id1"})
    
    # Verify SNS warning was published
    mock_publish.assert_called_once()
    subject = mock_publish.call_args[0][1]
    body = mock_publish.call_args[0][2]
    assert subject == "[Heliopause] [WARNING] Pending Purge"
    assert "i-warn123" in body


@patch.dict(os.environ, {"STATE_BUCKET_NAME": "test-bucket", "STATE_PREFIX": "test-prefix/", "CORE_STATE_FILE": "heliopause.tfstate", "DRY_RUN": "true", "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123456789012:test-topic"})
@patch("handler.state_file_exists")
@patch("handler.list_state_files")
@patch("handler.build_immunity_list")
@patch("handler.scan_for_purge_candidates")
@patch("handler.evaluate_purge_plan")
@patch("handler.publish_to_sns")
def test_lambda_handler_purge_dry_run_true(mock_publish, mock_evaluate, mock_scan, mock_build, mock_list, mock_exists):
    """Event: {"action": "purge"} + DRY_RUN=true -> Run sweep, publish DRY_RUN_COMPLETED, do NOT delete."""
    mock_exists.return_value = True
    mock_list.return_value = ["test-prefix/heliopause.tfstate"]
    mock_build.return_value = {"id1"}
    mock_scan.return_value = {"ec2_instances": [{"id": "i-dry123"}]}
    mock_evaluate.return_value = {
        "dry_run": True,
        "summary": {"ec2_instances": 1},
        "resources": {"ec2_instances": [{"id": "i-dry123"}]},
        "deleted": {"ec2_instances": []},
        "failures": {"ec2_instances": []}
    }
    
    event = {"action": "purge"}
    context = MagicMock()
    
    result = lambda_handler(event, context)
    
    # Verify dry_run passed to evaluate
    mock_evaluate.assert_called_once_with(mock_scan.return_value, True, context=context, immunity_ids={"id1"})
    
    # Verify SNS dry-run completed audit was published
    mock_publish.assert_called_once()
    subject = mock_publish.call_args[0][1]
    body = mock_publish.call_args[0][2]
    assert subject == "[Heliopause] [DRY_RUN_COMPLETED]"
    assert "i-dry123" in body


@patch.dict(os.environ, {"STATE_BUCKET_NAME": "test-bucket", "STATE_PREFIX": "test-prefix/", "CORE_STATE_FILE": "heliopause.tfstate", "DRY_RUN": "false", "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123456789012:test-topic"})
@patch("handler.state_file_exists")
@patch("handler.list_state_files")
@patch("handler.build_immunity_list")
@patch("handler.scan_for_purge_candidates")
@patch("handler.evaluate_purge_plan")
@patch("handler.publish_to_sns")
def test_lambda_handler_purge_dry_run_false(mock_publish, mock_evaluate, mock_scan, mock_build, mock_list, mock_exists):
    """Event: {"action": "purge"} + DRY_RUN=false -> Run sweep, execute deletions, publish PURGE_COMPLETED."""
    mock_exists.return_value = True
    mock_list.return_value = ["test-prefix/heliopause.tfstate"]
    mock_build.return_value = {"id1"}
    mock_scan.return_value = {"ec2_instances": [{"id": "i-purge123"}]}
    mock_evaluate.return_value = {
        "dry_run": False,
        "summary": {"ec2_instances": 1},
        "resources": {"ec2_instances": [{"id": "i-purge123"}]},
        "deleted": {"ec2_instances": ["i-purge123"]},
        "failures": {"ec2_instances": []}
    }
    
    event = {"action": "purge"}
    context = MagicMock()
    
    result = lambda_handler(event, context)
    
    # Verify dry_run=False passed to evaluate
    mock_evaluate.assert_called_once_with(mock_scan.return_value, False, context=context, immunity_ids={"id1"})
    
    # Verify SNS purge completed ledger was published
    mock_publish.assert_called_once()
    subject = mock_publish.call_args[0][1]
    body = mock_publish.call_args[0][2]
    assert subject == "[Heliopause] [PURGE_COMPLETED]"
    assert "i-purge123" in body


@patch("handler.publish_to_sns")
def test_send_sns_warning_payload_standard(mock_publish):
    """Test send_sns_warning_payload formats correctly under the 240 KB limit."""
    from handler import send_sns_warning_payload
    
    resource_plan = {
        "ec2_instances": [{"id": "i-123456789"}],
        "s3_buckets": [{"id": "untracked-dev-bucket-xyz"}]
    }
    
    send_sns_warning_payload("arn:aws:sns:123", "test-bucket", resource_plan)
    
    mock_publish.assert_called_once()
    subject = mock_publish.call_args[0][1]
    body = mock_publish.call_args[0][2]
    
    assert subject == "[Heliopause] [WARNING] Pending Purge"
    assert "The following unmanaged resources will be permanently purged at 00:00 UTC:" in body
    assert "- ec2: i-123456789" in body
    assert "- s3: untracked-dev-bucket-xyz" in body
    assert "Option A: The State Shield (Recommended)" in body
    assert "Option B: The Real-Time Tag Override" in body
    assert "Option C: Global Variable Lock (Emergency Mute)" in body


@patch("handler.s3_client")
@patch("handler.publish_to_sns")
def test_send_sns_warning_payload_overflow(mock_publish, mock_s3):
    """Test send_sns_warning_payload writes to S3 and formats warning text on overflow."""
    from handler import send_sns_warning_payload
    
    # Generate a massive ID to force overflow
    large_id = "a" * (241 * 1024)
    resource_plan = {
        "ec2_instances": [{"id": large_id}]
    }
    
    send_sns_warning_payload("arn:aws:sns:123", "test-bucket", resource_plan)
    
    # Assert it was written to S3
    mock_s3.put_object.assert_called_once_with(
        Bucket="test-bucket",
        Key="heliopause/pending_resource_purge_list.txt",
        Body=f"- ec2: {large_id}".encode("utf-8"),
        ContentType="text/plain"
    )
    
    # Assert notification was published with pointer instructions
    mock_publish.assert_called_once()
    subject = mock_publish.call_args[0][1]
    body = mock_publish.call_args[0][2]
    
    assert subject == "[Heliopause] [WARNING] Pending Purge"
    assert "offloaded to S3" in body
    assert "Bucket: test-bucket" in body
    assert "Key: heliopause/pending_resource_purge_list.txt" in body
    assert "aws s3 cp s3://test-bucket/heliopause/pending_resource_purge_list.txt ." in body
    assert "Option A: The State Shield (Recommended)" in body


@patch.dict(os.environ, {"STATE_BUCKET_NAME": "test-bucket", "STATE_PREFIX": "test-prefix/", "CORE_STATE_FILE": "heliopause.tfstate", "DRY_RUN": "true", "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123456789012:test-topic"})
@patch("handler.state_file_exists")
@patch("handler.list_state_files")
@patch("handler.build_immunity_list")
@patch("handler.scan_for_purge_candidates")
@patch("handler.evaluate_purge_plan")
@patch("handler.publish_to_sns")
@patch("handler.s3_client")
def test_purge_deletes_pending_list_from_s3(mock_s3, mock_publish, mock_evaluate, mock_scan, mock_build, mock_list, mock_exists):
    """Test that purge execution deletes the pending resource purge list from S3 if it exists."""
    mock_exists.return_value = True
    mock_list.return_value = ["test-prefix/heliopause.tfstate"]
    mock_build.return_value = {"id1"}
    mock_scan.return_value = {"ec2_instances": []}
    mock_evaluate.return_value = {
        "dry_run": True,
        "summary": {"ec2_instances": 0},
        "resources": {"ec2_instances": []},
        "deleted": {"ec2_instances": []},
        "failures": {"ec2_instances": []}
    }
    
    event = {"action": "purge"}
    context = MagicMock()
    
    result = lambda_handler(event, context)
    
    # Assert that delete_object was triggered on the state bucket
    mock_s3.delete_object.assert_called_once_with(
        Bucket="test-bucket",
        Key="heliopause/pending_resource_purge_list.txt"
    )


def test_format_sns_body_mapping():
    """Test format_sns_body maps raw resource keys (e.g. ec2_instances) to short prefixes (e.g. ec2)"""
    from handler import format_sns_body
    
    resource_plan = {
        "ec2_instances": [{"id": "i-123"}],
        "s3_buckets": [{"id": "bucket-1"}]
    }
    
    # warning state
    warning_body = format_sns_body("warning", resource_plan)
    assert "ec2:" in warning_body
    assert "s3:" in warning_body
    assert "ec2_instances:" not in warning_body
    assert "s3_buckets:" not in warning_body
    
    # dry_run state
    dry_run_body = format_sns_body("dry_run", resource_plan)
    assert "ec2:" in dry_run_body
    assert "s3:" in dry_run_body
    assert "ec2_instances:" not in dry_run_body
    assert "s3_buckets:" not in dry_run_body
    
    # purge state
    result = {
        "deleted": {
            "ec2_instances": ["i-123"],
            "s3_buckets": ["bucket-1"]
        },
        "failures": {
            "rds_instances": [{"id": "rds-1", "error": "AccessDenied"}]
        }
    }
    purge_body = format_sns_body("purge", resource_plan, result)
    assert "ec2:" in purge_body
    assert "s3:" in purge_body
    assert "rds:" in purge_body
    assert "ec2_instances:" not in purge_body
    assert "s3_buckets:" not in purge_body
    assert "rds_instances:" not in purge_body


@patch("handler.publish_to_sns")
def test_send_sns_warning_payload_offset_hours(mock_publish):
    """Test send_sns_warning_payload dynamically interpolates warning_offset_hours and correct singular/plural label"""
    from handler import send_sns_warning_payload
    
    resource_plan = {"ec2_instances": [{"id": "i-123"}]}
    
    # Test 4 hours
    with patch.dict(os.environ, {"WARNING_OFFSET_HOURS": "4"}):
        send_sns_warning_payload("arn:aws:sns:123", "test-bucket", resource_plan)
        body = mock_publish.call_args[0][2]
        assert "EXECUTION IN 4 HOURS" in body
        
    mock_publish.reset_mock()
    
    # Test 1 hour (singular)
    with patch.dict(os.environ, {"WARNING_OFFSET_HOURS": "1"}):
        send_sns_warning_payload("arn:aws:sns:123", "test-bucket", resource_plan)
        body = mock_publish.call_args[0][2]
        assert "EXECUTION IN 1 HOUR" in body
        assert "EXECUTION IN 1 HOURS" not in body


