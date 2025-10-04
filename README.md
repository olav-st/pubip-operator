# pubip-operator
A Kubernetes operator that fetches your public IP and updates resources in the cluster.

## Description
pubip-operator is designed to monitor and update public IP addresses for Kubernetes resources. It fetches the current public IP, detects changes, and updates resources such as ConfigMaps, Services or any other custom resources in the cluster. This is useful for clusters running behind dynamic IPs, such as on home networks, cloud VMs, or edge devices. The operator is extensible and supports multiple IP sources.

## Getting Started

### Install with Helm

The operator can be installed with Helm in a single command:

```sh
helm install pubip-operator oci://ghcr.io/olav-st/pubip-operator/charts/pubip-operator --namespace pubip-operator --create-namespace --version v0.0.1
```

### Create a PublicIPUpdater Resource

To use the operator, apply a `PublicIPUpdater` resource to your cluster. For example:

```yaml
apiVersion: pubip.olav.ninja/v1
kind: PublicIPUpdater
metadata:
  name: my-publicip-updater
spec:
  sources:
    - akami
    - aws_checkip
    - ipify
    - ipinfo
  targets:
    - apiVersion: v1
      kind: ConfigMap
      name: my-configmap
      namespace: default
      fieldPath: data.PUBLIC_IP
```

This will update the `PUBLIC_IP` field in the specified ConfigMap with your public IP and ensure that it is kept up to date.

## Contributing
Contributions are welcome! Please pull requests for bug fixes, new features, or documentation improvements. For major changes, use the discussion tab to discuss what you would like to change first.

**NOTE:** Run `make help` for more information on all potential `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

## License

Copyright 2025 Olav Sortland Thoresen.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

