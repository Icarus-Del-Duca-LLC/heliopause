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

## License

Heliopause is released under the Apache License 2.0. See `LICENSE` for details.
