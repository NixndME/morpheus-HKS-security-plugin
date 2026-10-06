import com.morpheuslab.hkssecurity.PanelView
import com.morpheuslab.hkssecurity.ScanOutput
import spock.lang.Specification

class ScanOutputSpec extends Specification {

    def 'cuts the JSON report out of log lines and trailing progress bars'() {
        given:
        String log = '{"level":"warn","msg":"x"}\nE1006 17:02:41.5 1 event.go] rejected\n{"a":\n[1,{"b":"}{"}]\n}\n12 KiB / 20 KiB [----] 60%\n'
        expect:
        ScanOutput.json(log) == [a: [1, [b: '}{']]]
    }

    def 'live line skips harmless noise and reads plainly'() {
        expect:
        ScanOutput.progressLine('kubescape', '{"level":"error","msg":"failed to init host scanner"}') == null
        ScanOutput.progressLine('kubescape', '{"level":"info","msg":"Overall compliance-score (100- Excellent, 0- All failed): 61"}') == 'Kubescape: compliance score 61%'
        ScanOutput.progressLine('trivy', '2026-10-06T17:16:44Z\tINFO\tScanning K8s...\tK8s=""') == 'Trivy: checking every resource in the cluster'
        ScanOutput.progressLine('trivy', '12 / 547 [->___] 2% 0 p/s13 / 547 [->___] 2.38% 0 p/s') == 'Trivy: 13 of 547 resources checked'
    }

    def 'the PDF lists every workload without trimming'() {
        given:
        def report = [workloads: (1..90).collect { [key: "$it", ns: 'n', kind: 'Deployment', name: "w$it", sev: [critical: 0, high: 1, medium: 0, low: 0], ks: [], tm: [], vuln: [], secrets: []] }]
        expect:
        new PanelView(report: report, printAll: true).rows.size() == 90
        new PanelView(report: report).rows.size() == PanelView.MAX_ROWS
    }
}
