package com.morpheuslab.hkssecurity

import groovy.json.JsonSlurper

/** Turns scanner pod logs into JSON reports and one-line progress messages. */
class ScanOutput {

    /** Log lines that are not part of the JSON report: structured logs, klog lines, the closing score line. */
    static boolean isLogLine(String l) {
        l.startsWith('{"level"') || l ==~ /^[EIWF]\d{4} .*/ || l.startsWith('Overall compliance') ||
            l ==~ /^\d{4}-\d\d-\d\dT\S+\s+(INFO|WARN|ERROR|DEBUG|FATAL)\b.*/
    }

    /** The report is the JSON between the log lines; text after it (progress bars) is ignored. */
    static Map json(String log) {
        if (!log) return null
        String body = log.readLines().findAll { it && !isLogLine(it) }.join('\n')
        String obj = firstObject(body)
        if (!obj) return null
        try { new JsonSlurper().parseText(obj) as Map } catch (Exception ignored) { null }
    }

    /** The first balanced {...} in the text, respecting strings and escapes. */
    static String firstObject(String text) {
        int start = text.indexOf('{')
        if (start < 0) return null
        int depth = 0
        boolean inString = false, escaped = false
        for (int i = start; i < text.length(); i++) {
            char c = text.charAt(i)
            if (inString) {
                if (escaped) escaped = false
                else if (c == ((char) '\\')) escaped = true
                else if (c == ((char) '"')) inString = false
            } else if (c == ((char) '"')) inString = true
            else if (c == ((char) '{')) depth++
            else if (c == ((char) '}') && --depth == 0) return text.substring(start, i + 1)
        }
        null
    }

    static Map kubescape(String log) { json(log) ?: [:] }

    static Map trivy(String log) { json(log) ?: [:] }

    /** Harmless messages that would only worry a reader (features we do not install, events we may not write). */
    static final List<String> NOISE = ['Server rejected event', 'host scanner', 'node-agent', 'not found in Kubernetes discovery',
                                       'is not updated to the latest release', 'skipping live query']

    static String friendly(String msg) {
        if (msg.startsWith('Overall compliance-score')) return "compliance score ${msg.replaceAll(/.*:\s*/, '')}%"
        if (msg.startsWith('Scanning K8s')) return 'checking every resource in the cluster'
        msg
    }

    /** A short, human line from the last log lines of a running scanner. */
    static String progressLine(String scanner, String tail) {
        if (!tail) return null
        def counter = tail =~ /(\d+) \/ (\d+) \[/          // Trivy's progress bar: "13 / 547 [--->..."
        String last = null
        while (counter.find()) last = "${counter.group(1)} of ${counter.group(2)}"
        if (last && scanner == 'trivy') return "Trivy: ${last} resources checked"
        List<String> lines = tail.readLines().findAll { isLogLine(it) && !NOISE.any { n -> it.contains(n) } }
        if (!lines) return null
        String l = lines.last()
        String msg
        if (l.startsWith('{')) {
            try { msg = (new JsonSlurper().parseText(l) as Map).msg as String } catch (Exception ignored) { msg = null }
        } else {
            def m = l =~ /^\S+\s+(?:INFO|WARN|ERROR|DEBUG)\s+(?:\[[^\]]+\]\s*)?(.*)$/
            msg = m.find() ? m.group(1) : l
        }
        msg ? "${scanner == 'kubescape' ? 'Kubescape' : 'Trivy'}: ${friendly(msg).take(140)}" : null
    }
}
