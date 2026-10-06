package com.morpheuslab.hkssecurity

import groovy.util.logging.Slf4j

import java.util.concurrent.ConcurrentHashMap

/**
 * Runs one scan of one HKS cluster in the background: sets up the hks-security namespace, runs Kubescape
 * then Trivy as one-off Jobs on the node with the most free memory, builds the report and removes the Jobs.
 * Nothing keeps running between scans.
 */
@Slf4j
class Scanner {

    static final String NS = 'hks-security'
    static final String LABEL = 'app.kubernetes.io/managed-by'
    static final String MANAGED = 'morpheus-hks-security'
    static final String KUBESCAPE_IMAGE = 'quay.io/kubescape/kubescape-cli:v4.0.15'
    static final String TRIVY_IMAGE = 'aquasec/trivy:0.75.0'
    static final long JOB_TIMEOUT_MILLIS = 60 * 60 * 1000L

    static final List<String> STEPS = [
        'Prepare the hks-security namespace',
        'Pick the node with the most free memory',
        'Kubescape: compliance (NSA, MITRE)',
        'Trivy: vulnerabilities, misconfigurations, secrets, RBAC',
        'Build the report',
        'Remove the scan pods'
    ]

    /** Live state per cluster, read by the status route. */
    static final Map<Long, ScanState> STATES = new ConcurrentHashMap<>()

    static ScanState state(Long clusterId) { STATES[clusterId] }

    /** Ask a running scan to stop; it removes its pods on the way out. */
    static boolean cancel(Long clusterId) {
        ScanState s = STATES[clusterId]
        if (!s?.running) return false
        s.cancelled = true
        s.line = 'Cancelling'
        true
    }

    /**
     * Start a scan unless one is already running. The cluster decides: scan jobs started by an earlier plugin
     * version or another Morpheus node count too. Returns the state, or null when the cluster is busy.
     */
    static synchronized ScanState start(Long clusterId, String clusterName, KubeClient kube, String user, boolean images) {
        ScanState running = STATES[clusterId]
        if (running?.running) return running
        if (activeJobs(kube)) return null
        ScanState s = new ScanState(clusterId: clusterId, clusterName: clusterName, user: user, images: images,
            steps: STEPS.collect { [name: it, status: 'waiting'] })
        STATES[clusterId] = s
        Thread.start("hks-security-scan-${clusterId}") { new Scanner(kube: kube, s: s).run() }
        s
    }

    /** Scan jobs still running in the cluster, whoever started them. */
    static List<String> activeJobs(KubeClient kube) {
        Map r = kube.get("/apis/batch/v1/namespaces/${NS}/jobs?labelSelector=${LABEL}%3D${MANAGED}")
        ((r.data?.items ?: []) as List<Map>).findAll { (it.status?.active ?: 0) as int > 0 }.collect { it.metadata.name as String }
    }

    KubeClient kube
    ScanState s

    void run() {
        try {
            step(0) { prepare() }
            String node = step(1) { pickNode() }
            String ks = step(2) { runJob('kubescape', KUBESCAPE_IMAGE,
                ['scan', 'framework', 'nsa,mitre', '--format', 'json', '--output', '/dev/stdout', '--logger', 'warning'], node) }
            List<String> trivyArgs = ['k8s', '--report', 'all', '--format', 'json', '--disable-node-collector', '--timeout', '50m',
                                      '--scanners', s.images ? 'vuln,secret,misconfig,rbac' : 'misconfig,rbac']   // vuln and secret download every image
            String trivy = step(3) { runJob('trivy', TRIVY_IMAGE, trivyArgs, node) }
            Map report = step(4) {
                s.line = 'Merging the Kubescape and Trivy results'
                Map r = ReportBuilder.build(ScanOutput.kubescape(ks), ScanOutput.trivy(trivy), s)
                ReportStore.save(kube, r)
                r
            }
            s.summary = report.summary as Map
            step(5) { cleanup() }
            s.line = 'Scan finished'
            s.finish(null)
        } catch (Throwable t) {
            log.warn("HKS Security: scan of cluster ${s.clusterId} failed: ${t.message}")
            try { cleanup() } catch (Throwable ignored) { }
            s.finish(s.cancelled ? 'cancelled' : (t.message ?: t.class.simpleName))
        }
    }

    private <T> T step(int i, Closure<T> work) {
        s.current = i
        s.steps[i].status = 'running'
        s.steps[i].startedAt = System.currentTimeMillis()
        try {
            T out = work.call()
            s.steps[i].status = 'done'
            return out
        } catch (Throwable t) {
            s.steps[i].status = 'failed'
            throw t
        } finally {
            s.steps[i].seconds = (int) ((System.currentTimeMillis() - (s.steps[i].startedAt as long)) / 1000)
        }
    }

    /** Namespace, a read-only service account for the scanners, and nothing else. */
    void prepare() {
        Map meta = [labels: [(LABEL): MANAGED]]
        must(kube.ensure('/api/v1/namespaces', [apiVersion: 'v1', kind: 'Namespace', metadata: meta + [name: NS]]))
        must(kube.ensure("/api/v1/namespaces/${NS}/serviceaccounts", [apiVersion: 'v1', kind: 'ServiceAccount', metadata: meta + [name: 'scanner']]))
        must(kube.ensure('/apis/rbac.authorization.k8s.io/v1/clusterroles', [apiVersion: 'rbac.authorization.k8s.io/v1', kind: 'ClusterRole',
            metadata: meta + [name: 'hks-security-scanner'],
            rules: [[apiGroups: ['*'], resources: ['*'], verbs: ['get', 'list', 'watch']], [nonResourceURLs: ['*'], verbs: ['get']]]]))
        must(kube.ensure('/apis/rbac.authorization.k8s.io/v1/clusterrolebindings', [apiVersion: 'rbac.authorization.k8s.io/v1', kind: 'ClusterRoleBinding',
            metadata: meta + [name: 'hks-security-scanner'],
            roleRef: [apiGroup: 'rbac.authorization.k8s.io', kind: 'ClusterRole', name: 'hks-security-scanner'],
            subjects: [[kind: 'ServiceAccount', name: 'scanner', namespace: NS]]]))
        must(kube.ensure("/apis/rbac.authorization.k8s.io/v1/namespaces/${NS}/roles", [apiVersion: 'rbac.authorization.k8s.io/v1', kind: 'Role',
            metadata: meta + [name: 'scanner-events'], rules: [[apiGroups: [''], resources: ['events'], verbs: ['create', 'patch']]]]))
        must(kube.ensure("/apis/rbac.authorization.k8s.io/v1/namespaces/${NS}/rolebindings", [apiVersion: 'rbac.authorization.k8s.io/v1', kind: 'RoleBinding',
            metadata: meta + [name: 'scanner-events'], roleRef: [apiGroup: 'rbac.authorization.k8s.io', kind: 'Role', name: 'scanner-events'],
            subjects: [[kind: 'ServiceAccount', name: 'scanner', namespace: NS]]]))
        s.line = "Namespace ${NS} is ready"
    }

    /** Schedulable node with the most memory left, from the metrics API; null lets Kubernetes choose. */
    String pickNode() {
        Map nodes = kube.get('/api/v1/nodes')
        Map metrics = kube.get('/apis/metrics.k8s.io/v1beta1/nodes')
        Map<String, Long> used = ((metrics.data?.items ?: []) as List<Map>).collectEntries { [(it.metadata.name): Quantity.bytes(it.usage?.memory as String)] }
        List<Map> ready = ((nodes.data?.items ?: []) as List<Map>).findAll { Map n ->
            !(n.spec?.taints ?: []).any { it.effect == 'NoSchedule' } && (n.status?.conditions ?: []).any { it.type == 'Ready' && it.status == 'True' }
        }
        Map best = ready.max { Map n -> Quantity.bytes(n.status?.allocatable?.memory as String) - (used[n.metadata.name] ?: 0L) }
        if (!best) { s.line = 'No metrics; Kubernetes will place the scan'; return null }
        long free = Quantity.bytes(best.status.allocatable.memory as String) - (used[best.metadata.name] ?: 0L)
        s.line = "Scans run on ${best.metadata.name} (${(long) (free / 1024 / 1024)} MiB free)"
        s.node = best.metadata.name
        best.metadata.name
    }

    /** Run one scanner Job, show its progress, return its output. */
    String runJob(String name, String image, List<String> args, String node) {
        String job = "${name}-${System.currentTimeMillis()}"
        Map spec = [backoffLimit: 0, ttlSecondsAfterFinished: 600, template: [metadata: [labels: ['hks-security/scanner': name]], spec: [
            serviceAccountName: 'scanner', restartPolicy: 'Never', priorityClassName: null,
            containers: [[name: name, image: image, args: args,
                          resources: [requests: [cpu: '100m', memory: '256Mi'], limits: [cpu: '1', memory: '1Gi']]]]]]]
        if (node) (spec.template.spec as Map).nodeName = node
        (spec.template.spec as Map).remove('priorityClassName')
        s.jobs << job
        must(kube.post("/apis/batch/v1/namespaces/${NS}/jobs", [apiVersion: 'batch/v1', kind: 'Job',
            metadata: [name: job, labels: [(LABEL): MANAGED, 'hks-security/scanner': name]], spec: spec]))
        long deadline = System.currentTimeMillis() + JOB_TIMEOUT_MILLIS
        int missing = 0
        while (System.currentTimeMillis() < deadline) {
            sleep(3000)
            if (s.cancelled) throw new IllegalStateException('cancelled')
            if (kube.get("/apis/batch/v1/namespaces/${NS}/jobs/${job}").status == 404 && ++missing > 2) {
                throw new IllegalStateException("the ${name} job was deleted from the cluster")
            }
            Map pods = kube.get("/api/v1/namespaces/${NS}/pods?labelSelector=job-name%3D${job}")
            Map pod = ((pods.data?.items ?: []) as List<Map>).find()
            if (!pod) { s.line = "Waiting for the ${name} pod"; continue }
            Map cs = ((pod.status?.containerStatuses ?: []) as List<Map>).find() ?: [:]
            String podName = pod.metadata.name
            if (cs.state?.waiting) {
                String reason = cs.state.waiting.reason
                s.line = reason == 'ContainerCreating' ? "Downloading the ${name} image" : "${name}: ${reason}"
                if (reason in ['ErrImagePull', 'ImagePullBackOff', 'InvalidImageName']) throw new IllegalStateException("${name} image could not be pulled (${reason})")
            } else if (cs.state?.running) {
                String last = kube.text("/api/v1/namespaces/${NS}/pods/${podName}/log?tailLines=8")
                s.line = ScanOutput.progressLine(name, last) ?: "${name} is scanning"
            } else if (cs.state?.terminated) {
                String out = kube.text("/api/v1/namespaces/${NS}/pods/${podName}/log")
                if (cs.state.terminated.exitCode != 0) {
                    String why = cs.state.terminated.reason == 'OOMKilled' ? 'ran out of memory (limit 1 GiB)' : "exit code ${cs.state.terminated.exitCode}"
                    throw new IllegalStateException("${name} failed: ${why}")
                }
                return out
            }
        }
        throw new IllegalStateException("${name} did not finish within an hour")
    }

    /** Remove only this scan's jobs; old ones expire on their own (TTL). */
    void cleanup() {
        s.line = 'Removing the scan pods'
        s.jobs.each { kube.delete("/apis/batch/v1/namespaces/${NS}/jobs/${it}") }
    }

    private static Map must(Map r) {
        if (r.status >= 200 && r.status < 300) return r
        throw new IllegalStateException(r.error as String)
    }
}

/** What the panel shows while a scan runs and after it finished. */
class ScanState {
    Long clusterId
    String clusterName
    String user
    boolean images
    List<Map> steps = []
    int current
    String line = 'Starting'
    String node
    long startedAt = System.currentTimeMillis()
    Long finishedAt
    String error
    Map summary
    volatile boolean cancelled
    List<String> jobs = []

    boolean isRunning() { finishedAt == null }

    void finish(String err) { error = err; finishedAt = System.currentTimeMillis() }

    Map toMap() {
        [running: running, error: error, line: line, current: current, node: node, user: user,
         elapsed: (int) (((finishedAt ?: System.currentTimeMillis()) - startedAt) / 1000),
         steps: steps.collect { [name: it.name, status: it.status, seconds: it.seconds] }, summary: summary]
    }
}

/** Kubernetes quantities such as 3907472Ki or 2Gi, in bytes. */
class Quantity {
    static long bytes(String q) {
        if (!q) return 0L
        def m = q =~ /^([0-9.]+)([A-Za-z]*)$/
        if (!m.matches()) return 0L
        double n = m.group(1) as double
        Map<String, Double> unit = [Ki: 1024d, Mi: 1048576d, Gi: 1073741824d, Ti: 1099511627776d, k: 1000d, M: 1e6d, G: 1e9d, '': 1d]
        (long) (n * (unit[m.group(2)] ?: 1d))
    }
}
