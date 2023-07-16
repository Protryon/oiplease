# oiplease

This is a barebones OIDC proxy for use with NGINX Ingress Controller

See `examples` dir for K8S deployment & configuration examples

## Motivation

I used `vouch-proxy` for a while but it was kind of buggy, and the code was overcomplicated. So I slapped this together to make my homelab login system for stable, and it's been stable for over a week with no issues.