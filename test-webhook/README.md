# test-webhook — create a webhook for an existing runbook

Standalone Terraform to add a **webhook** to a runbook that **already exists** in your test Automation
account, and print the secret URL. Portable — copy this folder to your laptop and run it.

## Prerequisites

- An existing **Automation account** and the **runbook** (`Check-AzFwAccessControl-Webhook`, or your name).
- `terraform` and `az` installed; `az login` to the test tenant.
- Permission to create a webhook on that account.

## Use

```bash
cp webhook.auto.tfvars.example webhook.auto.tfvars   # then fill in your test values
terraform init
terraform apply
terraform output -raw webhook_uri                    # the secret URL (copy it now)
```

> ⚠️ Azure shows a webhook's URL **only once, at creation**. Terraform captures it in state, so
> `terraform output -raw webhook_uri` works — but only from *this* state. Keep the state, or save the URL.
> `webhook.auto.tfvars`, `*.tfstate`, and `.terraform/` are gitignored — never commit them.

## Trigger it

**Option A — curl (one-off):**

```bash
URL=$(terraform output -raw webhook_uri)
curl -X POST "$URL" -H 'Content-Type: application/json' \
  -d '{"SourceIp":"10.20.5.7","Destination":"10.30.1.4","Protocol":"TCP","Port":443}'
# → HTTP 202 + JobId (fire-and-forget; read the verdict from the job output in the portal)
```

**Option B — bundled runner** (`run-webhook-tests.ps1` / `run-webhook-tests.sh`, included in this folder):
POSTs a set of flows to the webhook **and reads the verdict back** (DNAT → Network → Application + a deny).
It auto-reads the URL from `terraform output` in this folder, so just run it from here:

```powershell
Connect-AzAccount                                          # needed only to READ the job output
./run-webhook-tests.ps1 -AutomationAccount <your-account> -ResourceGroup <your-rg>
```

```bash
az login
AA=<your-account> RG=<your-rg> bash run-webhook-tests.sh
```

> Both default to `ac-runbook-azfw` / `rg-runbook-rbpal` — override with `-AutomationAccount` /
> `-ResourceGroup` (PowerShell) or `AA=` / `RG=` env vars (bash) if yours differ. Fully self-contained:
> no other repo files needed — carrying just this folder is enough.

## Rotate / invalidate the URL

```bash
terraform apply -replace=azurerm_automation_webhook.this   # new URL, old one stops working
```
