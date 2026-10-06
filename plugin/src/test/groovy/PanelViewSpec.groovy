import com.morpheuslab.hkssecurity.PanelView
import spock.lang.Specification

class PanelViewSpec extends Specification {

    static Map entry(int score, int critical, int high, boolean images = false, boolean appsOnly = false) {
        [at: 1L, score: score, critical: critical, high: high, images: images, appsOnly: appsOnly]
    }

    def 'trend compares with the previous scan of the same kind'() {
        given:
        def v = new PanelView(report: [history: [entry(55, 3, 40), entry(70, 0, 5, false, true), entry(61, 1, 30)]])
        expect:
        v.hasTrend
        v.trendText == 'Since the last scan of the same kind: compliance up 6 points, 2 fewer critical, 10 fewer high.'
        new PanelView(report: [history: [entry(61, 1, 30), entry(61, 1, 30)]]).trendText == 'No change since the last scan of the same kind.'
        v.trendPoints.split(' ').size() == 2   // the apps-only scan is not on the line
    }

    def 'a first scan of a kind says so'() {
        expect:
        new PanelView(report: [history: [entry(61, 1, 30)]]).trendText == 'First scan of this kind.'
        new PanelView(report: [history: [entry(61, 1, 30), entry(70, 0, 5, true)]]).trendText == 'First scan of this kind.'
    }

    def 'system namespaces are marked so the report can hide them'() {
        given:
        def w = { String ns -> [key: ns, ns: ns, kind: 'Deployment', name: 'x', sev: [critical: 0, high: 0, medium: 0, low: 0], ks: [], tm: [], vuln: [], secrets: []] }
        def v = new PanelView(report: [workloads: [w('demo'), w('kube-system'), w('rook-ceph')]])
        expect:
        v.rows*.sys == [false, true, true]
        v.systemRows == 2
    }
}
