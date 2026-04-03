# GCP README

## Identity Aware Proxy Settings

```shell
gcloud iap settings get --project=gcp-asigbahgcp-nprd-47930 --resource-type=backend-services --service=cml-backend-controller-775d286d

accessSettings:
  allowedDomainsSettings:
    domains:
    - becomingahacker.com
    - labs.becomingahacker.com
    enable: true
name: projects/344691804483/iap_web/compute/services/7253440759400029238
```

```shell
gcloud iap web get-iam-policy --resource-type=backend-services --service=cml-backend-controller-775d286d
bindings:
- members:
  - serviceAccount:cmm-test@gcp-asigbahgcp-nprd-47930.iam.gserviceaccount.com
  role: roles/iap.httpsResourceAccessor
- condition:
    description: Allow IAP only when the HTTP Host header matches a configured load_balancer_fqdns
      entry.
    expression: request.host == "becomingahacker.com" || request.host == "labs.becomingahacker.com"
    title: CML LB virtual hosts (gcp.load_balancer_fqdns)
  members:
  - group:gcp-hackers@cisco.com
  - group:gcp-script-kiddies@cisco.com
  role: roles/iap.httpsResourceAccessor
etag: BwZOa7W4OVA=
version: 3
```

When using Google-Managed OAuth for IAP, the OAuth client ID is automatically
provisioned and linked to your IAP-protected resource. You can find this client
ID within the Identity-Aware Proxy section of the Google Cloud Console.  Here's
how to locate it:

Navigate to Identity-Aware Proxy: In the Google Cloud Console, go to the
Security section and select Identity-Aware Proxy.  Select your Resource: On the
IAP page, you will see a list of resources that are IAP-protected. Find and
select the specific web service, App Engine app, or GKE service that you are
trying to access programmatically.  View IAP Settings: Once you select the
resource, a side panel or details view should appear. Look for the "OAuth client
ID" field. This is the alphanumeric string, typically ending with
.apps.googleusercontent.com, that you need to use as the --audiences parameter.

After obtaining this client ID, you can use it in your gcloud auth print-identity-token command as follows:
curl -s [YOUR_RESOURCE_URL] -H "Proxy-Authorization: Bearer $(gcloud auth print-identity-token \
  [EMAIL_ADDRESS] \
  --include-email \
  --audiences=YOUR_GOOGLE_MANAGED_OAUTH_CLIENT_ID )"

Remember to replace [YOUR_RESOURCE_URL], [EMAIL_ADDRESS], and
YOUR_GOOGLE_MANAGED_OAUTH_CLIENT_ID with your actual values. The EMAIL_ADDRESS
should belong to an identity (user or service account) that has the necessary
IAP access roles (e.g., "IAP-secured Web App User") for the protected resource.

```shell
curl -s https://becomingahacker.com/ -H "Proxy-Authorization: Bearer $(gcloud auth print-identity-token \
  --impersonate-service-account=cmm-test@gcp-asigbahgcp-nprd-47930.iam.gserviceaccount.com \
  --include-email \
  --audiences=YOUR_GOOGLE_MANAGED_OAUTH_CLIENT_ID
```
