package com.morpheuslab.hkssecurity

/**
 * Merges the Kubescape and Trivy reports into one compact report: scores, totals by severity,
 * the most important issues, and per workload everything both scanners found.
 */
class ReportBuilder {

    static final List<String> LEVELS = ['critical', 'high', 'medium', 'low']
    static final Set<String> WORKLOAD_KINDS = ['Deployment', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob', 'Pod', 'ReplicaSet'] as Set
    static final int MAX_VULNS_PER_WORKLOAD = 40
    static final int MAX_TOP = 15

    static Map build(Map ks, Map trivy, ScanState s) {
        Map<String, Map> workloads = [:]
        Map compliance = kubescape(ks, workloads)
        Map trivyTotals = trivyFindings(trivy, workloads)

        List<Map> wl = workloads.values().findAll { WORKLOAD_KINDS.contains(it.kind) }.collect { Map w ->
            w.sev = LEVELS.collectEntries { lvl ->
                [(lvl): (w.ks.count { it.severity == lvl } + w.tm.count { it.severity == lvl } + (w.vulnCounts[lvl] ?: 0) + w.secrets.count { it.severity == lvl }) as int]
            }
            w.vuln = (w.vuln as List<Map>).sort { a, b -> rank(a.severity) <=> rank(b.severity) }.take(MAX_VULNS_PER_WORKLOAD)
            w.ks = (w.ks as List<Map>).sort { a, b -> rank(a.severity) <=> rank(b.severity) }
            w.tm = (w.tm as List<Map>).sort { a, b -> rank(a.severity) <=> rank(b.severity) }
            w
        }.sort { a, b -> score(b.sev as Map) <=> score(a.sev as Map) ?: (a.key as String) <=> (b.key as String) }

        Map misconfig = LEVELS.collectEntries { lvl -> [(lvl): wl.sum { (it.ks.count { k -> k.severity == lvl } + it.tm.count { k -> k.severity == lvl }) as int } ?: 0] }
        Map vulns = LEVELS.collectEntries { lvl -> [(lvl): trivyTotals.vulns[lvl] ?: 0] }
        Map total = LEVELS.collectEntries { lvl -> [(lvl): (misconfig[lvl] as int) + (vulns[lvl] as int) + (trivyTotals.secretsBySeverity[lvl] ?: 0)] }
        [version: 1, scannedAt: System.currentTimeMillis(), seconds: s ? (int) ((System.currentTimeMillis() - s.startedAt) / 1000) : 0,
         node: s?.node, user: s?.user, images: s?.images,
         compliance: compliance,
         misconfig: misconfig, vulns: vulns, secrets: trivyTotals.secrets, rbac: trivyTotals.rbac,
         topControls: compliance.remove('topControls'), topCves: trivyTotals.topCves, rbacIssues: trivyTotals.rbacIssues,
         workloads: wl,
         summary: [score: compliance.score, critical: total.critical, high: total.high, medium: total.medium, low: total.low,
                   workloads: wl.size(), cves: LEVELS.sum { vulns[it] as int }, secrets: trivyTotals.secrets]]
    }

    /** Kubescape: compliance score, frameworks, top failing controls, failed controls per workload. */
    static Map kubescape(Map ks, Map<String, Map> workloads) {
        Map sd = (ks.summaryDetails ?: [:]) as Map
        Map<String, Map> controls = (sd.controls ?: [:]) as Map
        Map<String, Map> resources = ((ks.resources ?: []) as List<Map>).collectEntries { [(it.resourceID): (it.object ?: [:])] }
        ((ks.results ?: []) as List<Map>).each { Map r ->
            Map obj = resources[r.resourceID] as Map ?: [:]
            String kind = obj.kind ?: (r.resourceID as String)?.tokenize('/')?.with { it.size() >= 2 ? it[-2] : null }
            String name = obj.metadata?.name ?: obj.name ?: (r.resourceID as String)?.tokenize('/')?.last()
            String ns = obj.metadata?.namespace ?: obj.namespace ?: namespaceOf(r.resourceID as String)
            if (!kind || !name) return
            Map w = workload(workloads, ns, kind, name)
            ((r.controls ?: []) as List<Map>).findAll { it.status?.status == 'failed' }.each { Map c ->
                Map meta = controls[c.controlID] ?: [:]
                List<String> fixes = ((c.rules ?: []) as List<Map>).collectMany { Map rule -> (rule.paths ?: []) as List<Map> }.collect { Map p ->
                    Object f = p.fixPath
                    f instanceof Map ? "${f.path}=${f.value}" : (f ?: p.failedPath ?: p.reviewPath)
                }.findAll().collect { it as String }.unique().take(4)
                w.ks << [id: c.controlID, name: c.name ?: meta.name, severity: severity(meta.scoreFactor), fix: fixes]
            }
        }
        List<Map> top = controls.values().findAll { it.status == 'failed' || it.statusInfo?.status == 'failed' }.collect { Map c ->
            [id: c.controlID, name: c.name, severity: severity(c.scoreFactor),
             failed: c.ResourceCounters?.failedResources ?: 0, passed: c.ResourceCounters?.passedResources ?: 0]
        }.sort { a, b -> rank(a.severity) <=> rank(b.severity) ?: (b.failed as int) <=> (a.failed as int) }.take(MAX_TOP)
        [score: round(sd.complianceScore), frameworks: ((sd.frameworks ?: []) as List<Map>).collect { [name: it.name, score: round(it.complianceScore)] },
         topControls: top]
    }

    /** Trivy: vulnerabilities, misconfigurations and secrets per workload; RBAC issues per role. */
    static Map trivyFindings(Map trivy, Map<String, Map> workloads) {
        Map vulns = LEVELS.collectEntries { [(it): 0] }
        Map secretsBySeverity = LEVELS.collectEntries { [(it): 0] }
        int secrets = 0
        Map<String, Map> cves = [:]
        List<Map> rbacIssues = []
        Map rbac = LEVELS.collectEntries { [(it): 0] }
        ((trivy.Resources ?: []) as List<Map>).each { Map res ->
            String kind = res.Kind, ns = res.Namespace ?: '', name = res.Name
            if (!kind || !name) return
            boolean role = kind in ['Role', 'ClusterRole', 'RoleBinding', 'ClusterRoleBinding']
            Map w = role ? null : workload(workloads, ns, kind, name)
            ((res.Results ?: []) as List<Map>).each { Map result ->
                ((result.Vulnerabilities ?: []) as List<Map>).each { Map v ->
                    String sev = (v.Severity as String)?.toLowerCase()
                    if (!(sev in LEVELS)) return
                    vulns[sev]++
                    if (w) {
                        w.vulnCounts[sev] = (w.vulnCounts[sev] ?: 0) + 1
                        w.vuln << [id: v.VulnerabilityID, pkg: v.PkgName, installed: v.InstalledVersion, fixed: v.FixedVersion ?: '', severity: sev,
                                   title: (v.Title as String)?.take(120) ?: '', target: (result.Target as String)?.take(80)]
                    }
                    Map c = cves.computeIfAbsent(v.VulnerabilityID as String) {
                        [id: v.VulnerabilityID, severity: sev, pkg: v.PkgName, fixed: v.FixedVersion ?: '', title: (v.Title as String)?.take(120) ?: '', workloads: [] as Set]
                    }
                    (c.workloads as Set) << "${ns}/${name}".toString()
                }
                ((result.Misconfigurations ?: []) as List<Map>).findAll { it.Status == 'FAIL' }.each { Map m ->
                    String sev = (m.Severity as String)?.toLowerCase()
                    if (!(sev in LEVELS)) return
                    Map item = [id: m.ID ?: m.AVDID, title: m.Title, severity: sev, fix: (m.Resolution as String)?.take(200) ?: '']
                    if (role) { rbac[sev]++; rbacIssues << item + [resource: "${kind} ${ns ? ns + '/' : ''}${name}".toString()] }
                    else w.tm << item
                }
                ((result.Secrets ?: []) as List<Map>).each { Map sc ->
                    String sev = (sc.Severity as String)?.toLowerCase() ?: 'high'
                    secrets++
                    if (sev in LEVELS) secretsBySeverity[sev]++
                    w?.secrets << [rule: sc.RuleID, title: sc.Title, severity: sev, target: (result.Target as String)?.take(80)]
                }
            }
        }
        List<Map> topCves = cves.values().collect { it + [workloads: (it.workloads as Set).size()] }
            .sort { a, b -> rank(a.severity) <=> rank(b.severity) ?: (b.workloads as int) <=> (a.workloads as int) }.take(MAX_TOP)
        [vulns: vulns, secrets: secrets, secretsBySeverity: secretsBySeverity, topCves: topCves, rbac: rbac,
         rbacIssues: rbacIssues.sort { a, b -> rank(a.severity) <=> rank(b.severity) }.take(MAX_TOP)]
    }

    static Map workload(Map<String, Map> workloads, String ns, String kind, String name) {
        String key = "${ns}/${kind}/${name}".toString()
        workloads.computeIfAbsent(key) { [key: key, ns: ns ?: '', kind: kind, name: name, ks: [], tm: [], vuln: [], vulnCounts: [:], secrets: []] }
    }

    /** Kubescape score factor to severity: 1-3 low, 4-6 medium, 7-8 high, 9-10 critical. */
    static String severity(Object scoreFactor) {
        double f = scoreFactor instanceof Number ? (scoreFactor as Number).doubleValue() : 0
        f >= 9 ? 'critical' : f >= 7 ? 'high' : f >= 4 ? 'medium' : 'low'
    }

    static int rank(String severity) {
        int i = LEVELS.indexOf(severity)
        i < 0 ? 9 : i
    }

    static long score(Map sev) { ((sev.critical ?: 0) as long) * 1_000_000L + ((sev.high ?: 0) as long) * 1_000L + ((sev.medium ?: 0) as long) }

    static Integer round(Object n) { n instanceof Number ? (int) Math.round((n as Number).doubleValue()) : null }

    /** Kubescape resource IDs look like group/version/namespace/kind/name. */
    static String namespaceOf(String id) {
        List<String> p = (id ?: '').tokenize('/')
        p.size() >= 3 ? p[-3] : ''
    }
}
