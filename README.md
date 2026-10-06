# HKS Security plugin for Morpheus

Adds an **HKS Security** tab to HKS clusters in Morpheus. Click **Scan** and the plugin checks the cluster with
[Trivy](https://trivy.dev) and [Kubescape](https://kubescape.io), shows the progress live, and then gives one
combined report.

![HKS Security report](https://github.com/NixndME/morpheus-HKS-security-plugin/releases/download/v0.1.14/hks-security-report.gif)

Full walkthrough (7 min, install to report): [hks-security-walkthrough.mp4](https://github.com/NixndME/morpheus-HKS-security-plugin/releases/download/v0.1.14/hks-security-walkthrough.mp4)

- Compliance score with the NSA and MITRE frameworks (Kubescape)
- Misconfigurations and RBAC issues (Trivy and Kubescape), with how to fix each one
- Image vulnerabilities and secrets in images (Trivy, full scan)
- Click a workload to see everything found in it
- Scan the whole cluster, or only your application namespaces
- Hide what HKS itself runs (kube-system, Calico, Rook/Ceph, ingress, logging, monitoring) in the report
- See how the score changed since the last scan of the same kind
- Export the report as a PDF

## Nothing runs between scans

The scanners are not installed permanently. When you start a scan the plugin:

1. creates the namespace `hks-security` and a read-only service account (first scan only)
2. runs Kubescape, then Trivy, as one-off jobs on the node with the most free memory,
   limited to 1 CPU and 1 GiB each
3. saves the report in the cluster (a ConfigMap in `hks-security`) and removes the jobs

**Quick scan** checks configuration and RBAC and takes about a minute. **Full scan** also downloads every
container image to look for vulnerabilities and secrets, so it takes longer and needs good network access to the
image registries.

**Remove** in the tab deletes the namespace and the scanner's cluster role. Uninstalling the plugin does the same
on every HKS cluster.

## Install

1. Download `morpheus-hks-security-plugin.jar` from the releases page.
2. In Morpheus go to *Administration > Integrations > Plugins* and upload it.
3. In *Administration > Roles* set **HKS Security** (in the HKS Security section):
   read to see reports, full to run scans. System Admin has full access.

There are no settings. The plugin uses the access Morpheus already has to each HKS cluster.

To upgrade, upload the new jar over the old one.

Morpheus 9.0.2 only shows the cluster tabs that fit on one line. If you have several plugins with cluster tabs
and **HKS Security** does not show, open it directly: `/infrastructure/clusters/<id>#!hks-security-tab`.

## Build

Needs JDK 17 and Gradle 8.

```bash
cd plugin
gradle clean shadowJar test
```

Tested with Morpheus 9.0.2, Trivy 0.75 and Kubescape 4.0.
