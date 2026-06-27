# Heliopause

## The State-Aware AWS Resource Janitor

Heliopause is a precision cleanup utility designed to keep AWS development accounts lean and fiscally disciplined. Unlike "blind" destruction tools, Heliopause parses Terraform state files to build a dynamic, real-time whitelist—ensuring your vital infrastructure stays up while everything else is systematically torn down.

## The Problem

Maintaining a "Dev" or "Sandbox" account often leads to cost drift. Forgotten NAT Gateways, orphaned EBS volumes, and idling EKS clusters can quietly erode your budget. Traditional "nuke" scripts are often too blunt, accidentally destroying the IAM roles, S3 backends, or baseline networking required to keep the account functional.

## The Heliopause Solution: "State-Aware Immunity"

Heliopause operates on a Destroy-by-Default logic, governed by a sophisticated safety mechanism:

- **Management Immunity:** It automatically parses its own `.tfstate` file (configurable via `core_state_file` variable, default `heliopause.tfstate`) to ensure the cleanup engine never commits suicide by deleting its own resources. If the core state file is missing, the Lambda aborts with an error to prevent self-destruction.
- **The "Escape Hatch" Prefix:** Users can drop any number of additional `.tfstate` files into a designated S3 prefix.
- **Dynamic Whitelisting:** Heliopause aggregates every resource ID found across all detected state files into a master Immunity List.
- **The Purge:** It scans the account and terminates any cost-generating resource (and eventually all resources) not present in that list.
- **Notifications:** After each run, Heliopause publishes a summary to an SNS topic, reporting deletions or alerts (e.g., "X AWS resources deleted. See CloudWatch logs for details" or "Core state file missing. Aborting deletion").

This allows teams to use their own Terraform automation to protect specific resources simply by housing their state in the Heliopause bucket.

## Core Features

- **Zero-Maintenance Whitelisting:** No JSON/YAML lists to update; your Terraform state is your whitelist.
- **Cost-Centric Prioritization:** Targets the silent spend generators first: NAT Gateways, RDS, EC2, ELB, and EBS.
- **DevOps-First Workflow:** Encourages ephemerality by making untracked resources the primary target for destruction.
- **Dry-Run Mode:** Log exactly what would be destroyed before applying the purge.
- **Self-Preservation Safeguards:** Aborts execution if the core state file is missing to prevent accidental self-destruction.
- **Automated Notifications:** Publishes run summaries and alerts to an SNS topic for monitoring and alerting.

## Technical Architecture

Heliopause is deployed as a standalone management layer.

- **The Sentry:** An AWS Lambda function (Python 3.12 / Boto3).
- **The Shield:** A logic engine that recursively scans a specific S3 bucket prefix for `.tfstate` files.
- **The Trigger:** EventBridge (CloudWatch Events) on a cron schedule (for example, nightly at 00:00 UTC).
- **The Messenger:** An SNS topic for publishing run summaries and critical alerts.

## Configuration & Deployment

Heliopause is configured via Terraform variables. You can customize the deployment by creating a `terraform.tfvars` file.

### Optional Email Notifications
By default, Heliopause publishes its run summaries and critical alerts to an Amazon SNS topic (`heliopause-notifications`). To receive these alerts via email, configure the `notification_email` variable:

```hcl
notification_email = "maintainers@icarusdelduca.com"
```

When this variable is set, Terraform creates an SNS email subscription for the endpoint. Upon deployment, AWS will send a subscription confirmation email to the configured address. **You must click the confirmation link in that email to start receiving notifications.**

## Manual Invocation & Payloads

You can manually trigger the Heliopause Lambda function from the AWS Console or via the AWS CLI by providing a JSON payload that specifies the desired `action`.

### 1. Warning Trigger Payload
To run a dry-run sweep of the account and dispatch a warning manifest of pending deletions via SNS, invoke the Lambda with the following payload:

```json
{
  "action": "warn"
}
```

* **Safety Behavior:** 
  * If the Lambda's environment variable `DRY_RUN` is set to `true`, the execution will abort/short-circuit immediately before calling any discovery APIs. No SNS warning will be sent.
  * If `DRY_RUN` is set to `false`, a full account sweep is performed against the immunity list. The warning manifest is published to SNS, but no resource deletions are executed.

### 2. Purge Trigger Payload
To trigger an active purge (or a dry-run audit of a purge), use the `purge` action (which is also the default action if no payload is supplied):

```json
{
  "action": "purge"
}
```

* **Execution Behavior:**
  * If `DRY_RUN` is set to `true`, a standard `[Heliopause] [DRY_RUN_COMPLETED]` audit notification containing the list of resources that would have been deleted is published to SNS. No deletions occur.
  * If `DRY_RUN` is set to `false`, the active deletion routines are executed. A `[Heliopause] [PURGE_COMPLETED]` ledger of destroyed resource IDs is published to SNS.

### 3. AWS CLI Example
To invoke the function from your terminal, run:

```bash
aws lambda invoke \
  --function-name heliopause-cleanup \
  --payload '{"action": "warn"}' \
  --cli-binary-format raw-in-base64-out \
  response.json
```

## License

Heliopause is released under the Apache License 2.0. See `LICENSE` for details.
