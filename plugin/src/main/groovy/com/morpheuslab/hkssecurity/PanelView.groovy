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
    String getStepsJson() { groovy.json.JsonOutput.toJson(Scanner.STEPS) }

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
    String getScanKind() { report?.images ? 'full scan (with image vulnerabilities)' : 'quick scan (configuration and RBAC)' }
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
            [index: i, ns: w.ns, kind: w.kind, name: w.name,
             cells: LEVELS.collect { [count: sev[it] ?: 0, cls: sev[it] ? "hs-${it}" : 'hs-zero'] },
             ks: (w.ks as List<Map>).collect { it + [chip: chip(it.severity as String), hasFix: !(it.fix as List).isEmpty()] },
             tm: (w.tm as List<Map>).collect { it + [chip: chip(it.severity as String)] },
             vuln: (w.vuln as List<Map>).collect { it + [chip: chip(it.severity as String)] },
             secrets: (w.secrets as List<Map>).collect { it + [chip: chip(it.severity as String)] },
             hasKs: !(w.ks as List).isEmpty(), hasTm: !(w.tm as List).isEmpty(), hasVuln: !(w.vuln as List).isEmpty(), hasSecrets: !(w.secrets as List).isEmpty()]
        }
    }
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
