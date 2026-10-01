# Security Policy

Report a vulnerability through
[GitHub private vulnerability reporting](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-privately):
open this repository's **Security** tab and choose **Report a vulnerability**.
Do not open a public issue for a suspected security problem.

A finding in proxy-monster itself (the proxy, control plane, or web console)
belongs in [ridi-oss/proxy-monster](https://github.com/ridi-oss/proxy-monster/security).
This repository covers what the module deploys: IAM and KMS policies, network
exposure, secret handling, and the bootstrap Lambda.
