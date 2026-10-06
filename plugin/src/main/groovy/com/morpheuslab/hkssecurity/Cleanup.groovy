package com.morpheuslab.hkssecurity

/** Removes everything HKS Security created in a cluster. */
class Cleanup {
    static void remove(KubeClient kube) {
        kube.delete("/api/v1/namespaces/${Scanner.NS}")
        kube.delete('/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/hks-security-scanner')
        kube.delete('/apis/rbac.authorization.k8s.io/v1/clusterroles/hks-security-scanner')
    }
}
