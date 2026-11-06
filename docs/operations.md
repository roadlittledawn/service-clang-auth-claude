# Operations guide

How to deploy clang-auth to AWS from scratch, keep the bill near zero, rotate keys, run day-to-day admin tasks, and respond when a credential leaks. Commands assume the repo root as the working directory and `example.com` as your domain; substitute your own.

> Blocks marked `sh` need an AWS account and were not run by the automated doc check. Blocks marked `bash` are local-only and were run (`scripts/run-doc-examples.sh`).

## Contents

1. [What gets deployed](#1-what-gets-deployed)
2. [First-time setup](#2-first-time-setup)
3. [Cost guardrails and the kill switch](#3-cost-guardrails-and-the-kill-switch)
4. [Rotating the signing key](#4-rotating-the-signing-key)
5. [Rotating the admin API key](#5-rotating-the-admin-api-key)
6. [Routine admin tasks](#6-routine-admin-tasks)
7. [If a credential leaks](#7-if-a-credential-leaks)
8. [Logs and auditing](#8-logs-and-auditing)

## 1. What gets deployed

`sam build && sam deploy` creates one CloudFormation stack (`infra/template.yaml`) containing:

| Resource | Purpose |
|---|---|
| Lambda function `clang-auth-service` (arm64, `provided.al2023`, 512 MB, 10 s timeout, reserved concurrency 5) | The Rust service. The same binary runs locally. |
| API Gateway **HTTP API** with stage throttling 5 rps / burst 10 | Public HTTPS entrypoint. |
| Custom domain `auth.example.com` + Route 53 alias record | Cookies are scoped to your domain, so the service must be reachable on it. The default `execute-api` URL is disabled. |
| `AWS::Logs::LogGroup` `/aws/lambda/clang-auth-service`, 14-day retention | Logs that expire. |
| IAM role allowing `ssm:GetParameters` on `/clang-auth/*` only | Reading secrets (and retired public keys) at cold start. |

Created outside the stack, by you, once: a MongoDB Atlas M0 cluster, three SSM SecureString parameters (plus an optional `signing-keys-retired` parameter during key rotations), an ACM certificate, and (if you don't already have one) a Route 53 hosted zone.

## 2. First-time setup

### 2.1 Prerequisites

- An AWS account and the [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html), signed in (`aws sts get-caller-identity` works).
- [AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html), [cargo-lambda](https://www.cargo-lambda.info/guide/installation.html) and Zig (cargo-lambda uses Zig to cross-compile for arm64). On macOS: `brew install aws-sam-cli cargo-lambda/tap/cargo-lambda` (installs Zig too).
- Your domain's DNS hosted in **Route 53** (a hosted zone costs $0.50/month).
- Pick a region and use it for everything below. This guide uses `us-east-1`:

  ```sh
  export AWS_REGION=us-east-1
  ```

### 2.2 MongoDB Atlas (free M0)

1. At <https://cloud.mongodb.com>, create a project and a cluster. Choose **M0 (Free)** and an AWS region close to yours. Do **not** choose Flex or Dedicated, and don't enable paid backups or add-ons.
2. **Database Access → Add New Database User.** Use password authentication with a long random password. Under *Built-in Role*, choose **Specific privileges**: `readWrite` on database `clang_auth` only. Scoping the user limits the damage if the URI leaks.
3. **Network Access → Add IP Address → `0.0.0.0/0`.** Lambda outside a VPC has no fixed IP, so it can't be allowlisted. The alternative is a NAT Gateway at about $32/month, which the cost budget forbids. The connection is still protected by TLS and the scoped password.
4. **Connect → Drivers** gives the `mongodb+srv://<user>:<password>@cluster0.xxxxx.mongodb.net/` URI. Keep it for 2.4.

### 2.3 TLS certificate (ACM)

The certificate must be in the **same region** as the stack (the custom domain is regional).

```sh
aws acm request-certificate --domain-name auth.example.com --validation-method DNS
# → "CertificateArn": "arn:aws:acm:us-east-1:…:certificate/…"
aws acm describe-certificate --certificate-arn <arn> \
  --query 'Certificate.DomainValidationOptions[0].ResourceRecord'
```

Create the CNAME record it shows in your hosted zone. In the console, *Create records in Route 53* does it in one click. Wait until `aws acm describe-certificate … --query Certificate.Status` says `ISSUED` (usually a few minutes). Note the hosted zone ID:

```sh
aws route53 list-hosted-zones-by-name --dns-name example.com --query 'HostedZones[0].Id'
# → "/hostedzone/Z0123456789ABC"   (use the part after /hostedzone/)
```

### 2.4 Secrets in SSM Parameter Store

The service needs three secrets. They live in SSM as **SecureString** parameters, encrypted with the free AWS-managed `aws/ssm` key (no customer-managed KMS key; those cost $1/month each). The Lambda reads them once per cold start. They never appear in the template, in Lambda's environment, or in the repo.

The service binary includes generators, so you don't need OpenSSL. First see what they print (run locally):

```bash
cargo run -q -p service -- gen-admin-key
```

```text
ADMIN KEY (give to the CLI as CLANG_AUTH_ADMIN_KEY): 3q2-…
ADMIN_API_KEY_HASH (give to the service):           9f86d0…
```

Now create the parameters. Run these in a shell with no history, or prefix each line with a space if your shell ignores those:

```sh
# 1. Signing key: an ES256 private key that signs every access token.
aws ssm put-parameter --name /clang-auth/signing-key --type SecureString \
  --value "$(cargo run -q -p service -- gen-signing-key)"

# 2. Admin API key. The service stores only its SHA-256 hash.
cargo run -q -p service -- gen-admin-key
#   → copy the ADMIN KEY into your password manager (you need it for the CLI)
aws ssm put-parameter --name /clang-auth/admin-api-key-hash --type SecureString \
  --value '<ADMIN_API_KEY_HASH from above>'

# 3. MongoDB connection string from 2.2.
aws ssm put-parameter --name /clang-auth/mongodb-uri --type SecureString \
  --value 'mongodb+srv://<user>:<password>@cluster0.xxxxx.mongodb.net/?retryWrites=true&w=majority'
```

To hash a key you already have: `cargo run -q -p service -- hash-admin-key '<key>'`.

### 2.5 Deploy

Edit `parameter_overrides` in `samconfig.toml`:

```toml
parameter_overrides = [
  "DomainName=auth.example.com",
  "CertificateArn=arn:aws:acm:us-east-1:123456789012:certificate/…",
  "HostedZoneId=Z0123456789ABC",
  "CookieDomain=.example.com",
]
```

Also set `region` in `samconfig.toml` to your region, then:

```sh
sam build      # cross-compiles the Rust binary for arm64 (first build takes a few minutes)
sam deploy     # shows a change set; confirm with "y"
```

`sam deploy` creates an S3 bucket for artifacts (`resolve_s3 = true`, a few cents per year) and then the stack. The stack also creates the DNS alias record for `auth.example.com`. When it finishes:

```sh
curl https://auth.example.com/health                  # {"status":"ok"}
curl https://auth.example.com/.well-known/jwks.json   # {"keys":[{"kty":"EC",…}]}
```

If `/health` returns `503 database_unavailable`, check the Atlas network access list (2.2 step 3) and the URI in SSM. CloudWatch logs (section 8) show the driver's error.

### 2.6 First app and first user

Point the CLI at production. Keep the key in a file only you can read:

```sh
mkdir -p ~/.config/clang-auth && chmod 700 ~/.config/clang-auth
cat > ~/.config/clang-auth/config.toml <<'EOF'
url = "https://auth.example.com"
admin_key = "<ADMIN KEY from 2.4>"
EOF
chmod 600 ~/.config/clang-auth/config.toml

clang-auth app create recipes --name Recipes --origin https://recipes.example.com
clang-auth user create you@example.com --name "Your Name" --grant recipes:admin
# → open the printed setup link, choose a password, and you're signed in
```

If you run the CLI from the repo root, the local `.env` takes precedence over `config.toml`. Run production commands from another directory, or pass `--url` and `--key`.

### 2.7 Cost alerts (do this now, not later)

AWS has **no automatic hard spending cap**. Budgets only send email. What actually bounds the bill is the throttling and concurrency limits in section 3. Set up both of these anyway:

**One AWS Budget with three alerts:** $5 actual, $10 actual, $20 forecasted. Budgets without actions are free.

```sh
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
EMAIL=you@example.com
aws budgets create-budget --account-id "$ACCOUNT" \
  --budget '{"BudgetName":"clang-auth-monthly","BudgetLimit":{"Amount":"25","Unit":"USD"},"TimeUnit":"MONTHLY","BudgetType":"COST"}' \
  --notifications-with-subscribers "[
    {\"Notification\":{\"NotificationType\":\"ACTUAL\",\"ComparisonOperator\":\"GREATER_THAN\",\"Threshold\":5,\"ThresholdType\":\"ABSOLUTE_VALUE\"},\"Subscribers\":[{\"SubscriptionType\":\"EMAIL\",\"Address\":\"$EMAIL\"}]},
    {\"Notification\":{\"NotificationType\":\"ACTUAL\",\"ComparisonOperator\":\"GREATER_THAN\",\"Threshold\":10,\"ThresholdType\":\"ABSOLUTE_VALUE\"},\"Subscribers\":[{\"SubscriptionType\":\"EMAIL\",\"Address\":\"$EMAIL\"}]},
    {\"Notification\":{\"NotificationType\":\"FORECASTED\",\"ComparisonOperator\":\"GREATER_THAN\",\"Threshold\":20,\"ThresholdType\":\"ABSOLUTE_VALUE\"},\"Subscribers\":[{\"SubscriptionType\":\"EMAIL\",\"Address\":\"$EMAIL\"}]}
  ]"
```

(Budgets are global; the CLI sends them to `us-east-1` regardless of your region.)

**Cost Anomaly Detection** (free), which emails you when spend jumps unexpectedly:

```sh
MONITOR=$(aws ce create-anomaly-monitor \
  --anomaly-monitor '{"MonitorName":"all-services","MonitorType":"DIMENSIONAL","MonitorDimension":"SERVICE"}' \
  --query MonitorArn --output text)
aws ce create-anomaly-subscription --anomaly-subscription "{
  \"SubscriptionName\":\"clang-auth-anomalies\",\"Frequency\":\"DAILY\",\"MonitorArnList\":[\"$MONITOR\"],
  \"Subscribers\":[{\"Type\":\"EMAIL\",\"Address\":\"$EMAIL\"}],
  \"ThresholdExpression\":{\"Dimensions\":{\"Key\":\"ANOMALY_TOTAL_IMPACT_ABSOLUTE\",\"MatchOptions\":[\"GREATER_THAN_OR_EQUAL\"],\"Values\":[\"3\"]}}}"
```

You're done. Integrate your apps using [integration-guide.md](integration-guide.md).

## 3. Cost guardrails and the kill switch

Expected spend is about **$0.60/month**: the Route 53 zone ($0.50), plus cents for API Gateway and S3. Lambda's always-free tier (1M requests and 400k GB-s per month) covers normal use. The design target is a hard ceiling of **$25/month even under a month of abusive traffic**. These template settings enforce it (`scripts/check-template.sh` verifies them):

| Guardrail | Setting | Why |
|---|---|---|
| API Gateway stage throttle | 5 rps steady, burst 10 | Bounds requests: 5 × 86,400 × 30 ≈ 13M/month at most, about $13 of API Gateway plus about $5 of Lambda and logs. Requests over the limit get `429` from API Gateway and never reach Lambda. |
| Lambda reserved concurrency | 5 | Bounds compute, and bounds MongoDB connections (Atlas M0 allows 500). |
| Lambda timeout / memory | 10 s / 512 MB | A stuck request can't burn minutes. 512 MB gives a fast CPU share for Argon2. You can try 256 MB if login latency is acceptable; Argon2 itself only needs about 19 MB. |
| Log group retention | 14 days | Lambda's default log groups keep logs forever. |
| Not used | VPC, NAT Gateway, Elastic IPs, provisioned concurrency, CloudFront, WAF, Secrets Manager, customer-managed KMS keys, X-Ray, dashboards/custom metrics, REST API (v1) | Each has a fixed monthly fee or a higher per-request price. |

Legitimate traffic is tiny: apps verify tokens locally, so the service only sees logins, one refresh per active user every 15 minutes, hourly JWKS fetches, and admin calls. 5 rps is plenty.

### Kill switch

If you see an attack (a budget alert, or a flood of requests in the logs), stop all traffic with **one command**:

```sh
aws lambda put-function-concurrency --function-name clang-auth-service --reserved-concurrent-executions 0
```

Every request now fails fast with no Lambda compute. Apps keep working for users whose access tokens haven't expired yet, but nobody can sign in or refresh. You can also, or instead, zero the API throttle, so API Gateway rejects requests with `429` before they reach Lambda:

```sh
API_ID=$(aws cloudformation describe-stacks --stack-name clang-auth \
  --query "Stacks[0].Outputs[?OutputKey=='HttpApiId'].OutputValue" --output text)
aws apigatewayv2 update-stage --api-id "$API_ID" --stage-name '$default' \
  --default-route-settings ThrottlingRateLimit=0,ThrottlingBurstLimit=0
```

To restore service, run `sam deploy` (which re-applies the template's values), or:

```sh
aws lambda put-function-concurrency --function-name clang-auth-service --reserved-concurrent-executions 5
aws apigatewayv2 update-stage --api-id "$API_ID" --stage-name '$default' \
  --default-route-settings ThrottlingRateLimit=5,ThrottlingBurstLimit=10
```

## 4. Rotating the signing key

The signing key signs every access token. Apps verify with the public half from JWKS. Rotate it yearly, or immediately if it may have leaked (section 7). The service publishes the **active** key plus any **retired** public keys, so tokens signed just before the rotation keep verifying until they expire. Nobody gets signed out.

1. Publish the **current** public key as retired. The parameter is a plain `String`, because public keys aren't secret:

   ```sh
   SIGNING_KEY="$(aws ssm get-parameter --name /clang-auth/signing-key --with-decryption \
     --query Parameter.Value --output text)" cargo run -q -p service -- public-key > old-public.pem
   aws ssm put-parameter --name /clang-auth/signing-keys-retired --type String --overwrite \
     --value "$(cat old-public.pem)"
   ```

2. Store a new private key:

   ```sh
   aws ssm put-parameter --name /clang-auth/signing-key --type SecureString --overwrite \
     --value "$(cargo run -q -p service -- gen-signing-key)"
   ```

3. Secrets are read once per cold start, so replace the warm containers. Any configuration change does it:

   ```sh
   aws lambda update-function-configuration --function-name clang-auth-service \
     --description "signing key rotated $(date -u +%FT%TZ)"
   ```

4. Check: `curl https://auth.example.com/.well-known/jwks.json` lists **two** keys, the new one first.
5. **Wait at least 15 minutes** (`ACCESS_TOKEN_TTL`) so every token signed with the old key has expired. Then remove the retired key and refresh the containers again:

   ```sh
   aws ssm delete-parameter --name /clang-auth/signing-keys-retired
   aws lambda update-function-configuration --function-name clang-auth-service \
     --description "retired key removed $(date -u +%FT%TZ)"
   rm old-public.pem
   ```

Apps need no changes. `jose`'s remote JWKS set re-fetches when it sees a token whose `kid` it doesn't know.

You can rehearse this locally: set `SIGNING_KEY_PATH` to a new file and `SIGNING_KEYS_RETIRED` to the output of `cargo run -q -p service -- public-key`, then restart the service.

## 5. Rotating the admin API key

The service only stores `sha256(admin key)`, so rotating means replacing the hash and restarting:

```sh
cargo run -q -p service -- gen-admin-key           # new key + hash
aws ssm put-parameter --name /clang-auth/admin-api-key-hash --type SecureString --overwrite \
  --value '<new ADMIN_API_KEY_HASH>'
# Secrets are read at cold start; force new containers:
aws lambda update-function-configuration --function-name clang-auth-service \
  --description "admin key rotated $(date -u +%FT%TZ)"
```

Put the new key in `~/.config/clang-auth/config.toml`, then check that `clang-auth app list` works. The old key stops working as soon as the new containers serve traffic, within a few seconds.

## 6. Routine admin tasks

All through the CLI ([cli.md](cli.md) has every command).

**Onboard someone:**

```sh
clang-auth user create sam@example.com --name Sam --grant recipes:member
# send them the printed link; it expires in 72 hours (INVITE_TTL)
```

If the link expired, `clang-auth user reset sam@example.com` issues a new one. It works for users who never finished setup, too.

**Forgotten password:** `clang-auth user reset <email>`. Send the link. When they use it, all their old sessions are signed out.

**Give or change access:** `clang-auth grant set <email> <app> --role <role>`. It takes effect on the user's next token refresh (within 15 minutes).

**Remove access to one app:**

```sh
clang-auth grant remove sam@example.com recipes
clang-auth session revoke sam@example.com      # optional: force re-login everywhere now
```

**Offboard someone entirely:** `clang-auth user disable sam@example.com`. This blocks login and revokes all sessions. `user delete` additionally erases the record.

In every case, an access token the user already holds stays valid until it expires (at most 15 minutes). This is the main trade-off of stateless tokens; see [how-it-works.md](how-it-works.md#4-security-decisions-and-threat-model).

**Add a new app:** `clang-auth app create <slug> --name <Name> --origin https://<slug>.example.com`, then follow [integration-guide.md](integration-guide.md).

## 7. If a credential leaks

| What leaked | Impact | Do this |
|---|---|---|
| **Admin API key** | Full control of users, apps, and grants (but not passwords, and no token minting in prod since `ALLOW_TOKEN_MINT=false`). | Rotate it (section 5) immediately. Then review admin activity in the logs (section 8) and undo anything unexpected: look for `user_created`, `grant_set`, and `invite_created` events you didn't make. Revoke sessions of any user who got an unexpected reset link. |
| **Signing private key** | Anyone can mint valid access tokens for any user and app. | Rotate (section 4), but **skip step 1**: don't publish the leaked key as retired. Forged tokens stop verifying once apps re-fetch the JWKS (immediately for apps that see an unknown `kid`; at most 1 hour for cached JWKS). Users aren't signed out: their sessions get fresh tokens on the next navigation or refresh. |
| **MongoDB URI / Atlas password** | Read and write access to all data. Session and invite tokens are stored only as SHA-256 hashes and passwords only as Argon2id hashes, so a read-only leak doesn't let anyone sign in. A writer could insert sessions or change grants. | In Atlas, change the database user's password (or create a new user and delete the old one). Update `/clang-auth/mongodb-uri` in SSM and force new containers (the `update-function-configuration` command in section 5). Then revoke every session: `mongosh "<new uri>" --eval 'db.getSiblingDB("clang_auth").sessions.deleteMany({})'`, and review grants with `clang-auth user list`. |
| **A user's password** | That user's access. | `clang-auth user reset <email>` (when used, it signs out all their sessions), or `clang-auth user disable <email>` until you can talk to them. |
| **A session cookie** (`ca_session`) | Acting as that user until it expires (up to 90 days). | `clang-auth session revoke <email>`. |
| **An access token** (`ca_access`) | Acting as that user for up to 15 minutes. | Nothing can revoke it early (by design). Revoke the session so it can't be refreshed. |
| **A setup or reset link** that hasn't been used yet | Whoever opens it first sets the password. | `clang-auth user reset <email>` invalidates every earlier link. Send the new one through a different channel. |

## 8. Logs and auditing

Logs go to the CloudWatch log group `/aws/lambda/clang-auth-service` (kept 14 days), one JSON object per line. Passwords, tokens, links, session IDs and keys are never logged; a test enforces this.

| Kind of line | `event` value(s) |
|---|---|
| Every request (method, path without query string, status, latency, request ID) | `http_request` |
| Sign-in and sign-out | `login_success`, `login_failure` (with a `reason` users never see), `logout`, `access_denied` |
| Invites | `invite_created`, `invite_used` |
| Blocked requests | `csrf_rejected`, `admin_auth_failed` |
| Admin changes | `app_created`, `app_updated`, `app_deleted`, `user_created`, `user_updated`, `user_deleted`, `grant_set`, `grant_removed`, `sessions_revoked`, `token_minted` |

Tail logs:

```sh
aws logs tail /aws/lambda/clang-auth-service --follow --format short
```

CloudWatch Logs Insights, for example "who did what in the admin API this week":

```text
fields @timestamp, event, user_id, app
| filter ispresent(event) and event not in ["http_request"]
| sort @timestamp desc
| limit 200
```

Failed logins by email (spot guessing):

```text
filter event = "login_failure" | stats count(*) as failures by email, reason | sort failures desc
```

Logs Insights charges per GB scanned. At this service's volume a query costs well under a cent.
