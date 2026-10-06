import com.morpheuslab.hkssecurity.ReportBuilder
import com.morpheuslab.hkssecurity.ReportStore
import com.morpheuslab.hkssecurity.ScanOutput
import groovy.json.JsonOutput
import spock.lang.IgnoreIf
import spock.lang.Specification

/** Runs on real scanner logs from the lab when they are present (qa/fixtures is not committed). */
@IgnoreIf({ !new File('../qa/fixtures/kubescape.log').exists() })
class RealOutputSpec extends Specification {

    def 'real Kubescape and Trivy logs give one report that fits in a ConfigMap'() {
        given:
        Map ks = ScanOutput.kubescape(new File('../qa/fixtures/kubescape.log').text)
        Map tv = ScanOutput.trivy(new File('../qa/fixtures/trivy-quick.log').text)
        when:
        Map r = ReportBuilder.build(ks, tv, null)
        byte[] gz = ReportStore.gzip(JsonOutput.toJson(r))
        println "score=${r.compliance.score} frameworks=${r.compliance.frameworks} misconfig=${r.misconfig} rbac=${r.rbac} workloads=${r.workloads.size()} gz=${gz.length}B"
        println "top control: ${r.topControls[0]}"
        println "riskiest workload: ${r.workloads[0].key} ${r.workloads[0].sev} ks=${r.workloads[0].ks.size()} trivy=${r.workloads[0].tm.size()}"
        then:
        ks.summaryDetails && tv.Resources
        r.compliance.score > 0
        r.workloads.size() > 10
        r.workloads[0].ks && r.workloads[0].tm
        gz.length < ReportStore.MAX_BYTES
    }
}
