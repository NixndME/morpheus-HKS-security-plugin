package com.morpheuslab.hkssecurity

import groovy.json.JsonOutput
import groovy.json.JsonSlurper

import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream

/**
 * The last report lives in the cluster itself (ConfigMap hks-security/hks-security-report, gzipped),
 * so it survives Morpheus restarts and goes away with the namespace.
 */
class ReportStore {

    static final String NAME = 'hks-security-report'
    static final int MAX_BYTES = 900_000

    static void save(KubeClient kube, Map report) {
        byte[] gz = gzip(JsonOutput.toJson(report))
        if (gz.length > MAX_BYTES) {
            report.workloads.each { Map w -> w.vuln = (w.vuln as List).take(10) }    // keep it under the ConfigMap limit
            gz = gzip(JsonOutput.toJson(report))
        }
        Map cm = [apiVersion: 'v1', kind: 'ConfigMap',
                  metadata: [name: NAME, namespace: Scanner.NS, labels: [(Scanner.LABEL): Scanner.MANAGED]],
                  binaryData: ['report.json.gz': gz.encodeBase64().toString()]]
        String path = "/api/v1/namespaces/${Scanner.NS}/configmaps"
        kube.delete("${path}/${NAME}")
        Map r = kube.post(path, cm)
        if (r.status >= 300) throw new IllegalStateException("could not store the report: ${r.error}")
    }

    /** The last report, or null when this cluster was never scanned. */
    static Map load(KubeClient kube) {
        Map r = kube.get("/api/v1/namespaces/${Scanner.NS}/configmaps/${NAME}")
        String b64 = r.status == 200 ? r.data?.binaryData?.get('report.json.gz') : null
        if (!b64) return null
        new JsonSlurper().parseText(gunzip(b64.decodeBase64())) as Map
    }

    static byte[] gzip(String text) {
        ByteArrayOutputStream out = new ByteArrayOutputStream()
        new GZIPOutputStream(out).withStream { it.write(text.getBytes('UTF-8')) }
        out.toByteArray()
    }

    static String gunzip(byte[] data) {
        new GZIPInputStream(new ByteArrayInputStream(data)).getText('UTF-8')
    }
}
