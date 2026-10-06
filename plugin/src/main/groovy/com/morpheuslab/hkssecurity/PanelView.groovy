package com.morpheuslab.hkssecurity

import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/** Everything the HKS Security tab shows, ready for Handlebars (which cannot compute). */
class PanelView {

    static final List<String> LEVELS = ReportBuilder.LEVELS
    static final int MAX_ROWS = 80

    Long clusterId
    String clusterName
    String accessLevel
    String csrfParam, csrfToken
    String error
    boolean running
    List<String> busyJobs = []     // scan jobs running in the cluster that this Morpheus did not start (older plugin version, other node)
    boolean getBusy() { !running && !busyJobs.isEmpty() }
    boolean printAll        // the PDF export lists every workload
    Map report

    boolean getCanScan() { accessLevel == 'full' }
    boolean getHasReport() { report != null && !running }
    boolean getNeverScanned() { report == null && !running }     // after a failed first scan too, so it can be retried
    boolean getHasError() { error != null }
    boolean runningImages
    String getStepsJson() { groovy.json.JsonOutput.toJson(Scanner.steps(runningImages)) }

    // ---- report header ----
    Integer getScore() { report?.compliance?.score as Integer }
    String getScoreCls() { score == null ? 'hs-muted' : score >= 80 ? 'hs-good' : score >= 60 ? 'hs-medium' : 'hs-high' }
    /** Length of the green arc on the score ring (circumference about 314). */
    int getScoreDash() { (int) Math.round((score ?: 0) * 3.14) }
    List<Map> getFrameworks() { (report?.compliance?.frameworks ?: []) as List<Map> }
    String getScannedAt() {
        report?.scannedAt ? DateTimeFormatter.ofPattern('yyyy-MM-dd HH:mm').withZone(ZoneOffset.UTC).format(Instant.ofEpochMilli(report.scannedAt as long)) + ' UTC' : ''
    }
    String getScannedAgo() { ago(report?.scannedAt as Long) }
    String getScanKind() {
        (report?.images ? 'full scan (with image vulnerabilities)' : 'quick scan (configuration and RBAC)') + (report?.appsOnly ? ', application namespaces only' : '')
    }
    boolean getAppsOnly() { report?.appsOnly as boolean }

    // ---- history ----
    List<Map> getHistory() { ((report?.history ?: []) as List<Map>) }
    /** Scans of the same kind as the last one (same scanners and scope), so the line compares like with like. */
    List<Map> getSameKind() {
        Map now = history ? history[-1] : null
        now ? history.findAll { it.images == now.images && it.appsOnly == now.appsOnly } : []
    }
    boolean getHasTrend() { sameKind.size() >= 2 }
    /** Points of the compliance line (0-100%) across the last scans, for a 160x40 SVG. */
    String getTrendPoints() {
        List<Map> h = sameKind
        if (h.size() < 2) return ''
        h.withIndex().collect { Map e, int i -> "${(int) (i * 160 / (h.size() - 1))},${40 - (int) (((e.score ?: 0) as int) * 40 / 100)}" }.join(' ')
    }
    int getHistorySize() { sameKind.size() }

    /** What changed since the last scan of the same kind (same scanners and scope). */
    String getTrendText() {
        List<Map> h = history
        Map now = h ? h[-1] : null
        Map before = h.size() > 1 ? h[0..-2].reverse().find { it.images == now.images && it.appsOnly == now.appsOnly } : null
        if (!before) return 'First scan of this kind.'
        int ds = ((now.score ?: 0) as int) - ((before.score ?: 0) as int)
        List<String> parts = []
        if (ds) parts << "compliance ${ds > 0 ? 'up' : 'down'} ${Math.abs(ds)} point${Math.abs(ds) == 1 ? '' : 's'}"
        ['critical', 'high'].each { String level ->
            int d = ((now[level] ?: 0) as int) - ((before[level] ?: 0) as int)
            if (d) parts << "${Math.abs(d)} ${d > 0 ? 'more' : 'fewer'} ${level}"
        }
        parts ? "Since the last scan of the same kind: ${parts.join(', ')}." : 'No change since the last scan of the same kind.'
    }
    boolean getImagesScanned() { report?.images as boolean }

    List<Map> getTotals() {
        LEVELS.collect { lvl ->
            int m = (report.misconfig[lvl] ?: 0) as int, v = (report.vulns[lvl] ?: 0) as int, r = (report.rbac?.getAt(lvl) ?: 0) as int
            [level: lvl.capitalize(), count: m + v + r, cls: (m + v + r) ? "hs-${lvl}" : 'hs-zero',
             detail: ([m ? "${m} config" : null, v ? "${v} CVE" : null, r ? "${r} RBAC" : null].findAll().join(' · ') ?: 'none')]
        }
    }

    List<Map> getControls() { ((report?.topControls ?: []) as List<Map>).collect { it + [chip: chip(it.severity as String)] } }
    List<Map> getCves() { ((report?.topCves ?: []) as List<Map>).collect { it + [chip: chip(it.severity as String)] } }
    List<Map> getRbacIssues() { ((report?.rbacIssues ?: []) as List<Map>).collect { it + [chip: chip(it.severity as String)] } }
    boolean getHasCves() { !cves.isEmpty() }
    boolean getHasRbac() { !rbacIssues.isEmpty() }

    List<Map> getRows() {
        List<Map> all = (report?.workloads ?: []) as List<Map>
        (printAll ? all : all.take(MAX_ROWS)).withIndex().collect { Map w, int i ->
            Map sev = w.sev as Map
            [index: i, ns: w.ns, kind: w.kind, name: w.name, sys: Scanner.SYSTEM_NAMESPACES.contains(w.ns),
             cells: LEVELS.collect { [count: sev[it] ?: 0, cls: sev[it] ? "hs-${it}" : 'hs-zero'] },
             ks: (w.ks as List<Map>).collect { it + [chip: chip(it.severity as String), hasFix: !(it.fix as List).isEmpty()] },
             tm: (w.tm as List<Map>).collect { it + [chip: chip(it.severity as String)] },
             vuln: (w.vuln as List<Map>).collect { it + [chip: chip(it.severity as String)] },
             secrets: (w.secrets as List<Map>).collect { it + [chip: chip(it.severity as String)] },
             hasKs: !(w.ks as List).isEmpty(), hasTm: !(w.tm as List).isEmpty(), hasVuln: !(w.vuln as List).isEmpty(), hasSecrets: !(w.secrets as List).isEmpty()]
        }
    }
    int getSystemRows() { rows.count { it.sys } as int }
    boolean getHasSystemRows() { systemRows > 0 }

    int getHiddenRows() { printAll ? 0 : Math.max(0, ((report?.workloads ?: []) as List).size() - MAX_ROWS) }

    /** Click-to-toggle rows without reloading: one radio per workload. */
    String getRowCss() {
        rows.collect { Map r ->
            String on = "#hs-w-${r.index}:checked~.hs-views"
            "${on} tr.hs-detail-${r.index}{display:table-row}${on} .hs-row-${r.index} td{background:rgba(1,169,130,.10)}" +
                "${on} .hs-row-${r.index} .hs-open{display:none}${on} .hs-row-${r.index} .hs-shut{display:block!important}"
        }.join('')
    }

    static String chip(String severity) { "hs-chip hs-chip-${severity ?: 'low'}" }

    static String ago(Long ms) {
        if (!ms) return ''
        long s = Math.max(0L, (long) ((System.currentTimeMillis() - ms) / 1000))
        s < 60 ? "${s}s ago" : s < 3600 ? "${(long) (s / 60)}m ago" : s < 86400 ? "${(long) (s / 3600)}h ago" : "${(long) (s / 86400)}d ago"
    }
}
