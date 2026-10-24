# Container images

Release tags trigger `containers.yml`, publishing separate CLI and Prometheus exporter
images on GHCR for `linux/amd64` and `linux/arm64`. The images use musl
binaries on scratch; no shell is present.

```sh
docker run --rm ghcr.io/soroban-eas/soroban-sas-cli:v0.1.0 --help
docker run --rm -p 9090:9090 -e SAS_CONTRACT_ID=YOUR_CONTRACT_ID ghcr.io/soroban-eas/soroban-sas-exporter:v0.1.0
```

The exporter requires `SAS_CONTRACT_ID` and accepts `METRICS_ADDR` (default
`0.0.0.0:9090`). The CLI accepts its normal flags.

Images are tagged on releases only. Cosign uses GitHub Actions' OIDC identity
to sign the pushed manifest digest and verify it within the workflow.
A successful release workflow does not itself make a private GHCR package public;
the repository owner must select public visibility in GitHub Packages.

Validate images on target architectures, including `docker image inspect`,
`docker run ... --help`, and a metrics request against an exporter configured
with a real contract ID. Size is a release acceptance check, not a guarantee
of the Dockerfile.
