package com.morpheuslab.hkssecurity

import com.morpheusdata.core.AbstractClusterTabProvider
import com.morpheusdata.core.MorpheusContext
import com.morpheusdata.core.Plugin
import com.morpheusdata.model.Account
import com.morpheusdata.model.ComputeServerGroup
import com.morpheusdata.model.ContentSecurityPolicy
import com.morpheusdata.model.User
import com.morpheusdata.views.HTMLResponse
import com.morpheusdata.views.ViewModel
import groovy.util.logging.Slf4j

/** The "HKS Security" tab, on HKS clusters only. */
@Slf4j
class SecurityTabProvider extends AbstractClusterTabProvider {

    private static final ThreadLocal<String> ACCESS = new ThreadLocal<>()

    Plugin plugin
    MorpheusContext morpheus

    SecurityTabProvider(Plugin plugin, MorpheusContext morpheus) { this.plugin = plugin; this.morpheus = morpheus }

    String getCode() { 'hks-security-tab' }
    String getName() { 'HKS Security' }
    MorpheusContext getMorpheus() { morpheus }
    Plugin getPlugin() { plugin }

    Boolean show(ComputeServerGroup cluster, User user, Account account) {
        ACCESS.set(Access.level(user))
        Access.isHks(cluster) && Access.canRead(user)
    }

    HTMLResponse renderTemplate(ComputeServerGroup cluster) {
        String level = ACCESS.get() ?: 'read'
        ACCESS.remove()
        Map csrf = Csrf.token()
        PanelView v = new PanelView(clusterId: cluster.id, clusterName: cluster.name, accessLevel: level,
            csrfParam: csrf.param, csrfToken: csrf.value)
        ScanState s = Scanner.state(cluster.id)
        v.running = s?.running as boolean
        v.runningImages = s?.images as boolean
        if (!v.running) {
            try { v.busyJobs = Scanner.activeJobs(KubeClient.of(morpheus, cluster)) } catch (Throwable ignored) { }
        }
        if (s && !s.running && s.error) v.error = s.error == 'cancelled' ? 'The last scan was cancelled.' : "The last scan failed: ${s.error}"
        if (!v.running) {
            try { v.report = ReportStore.load(KubeClient.of(morpheus, cluster)) }
            catch (Throwable t) { log.warn("HKS Security: cannot read the report of cluster ${cluster.id}: ${t}"); v.error = v.error ?: "Cannot read the last report: ${t.message}" }
        }
        ViewModel<PanelView> m = new ViewModel<>()
        m.object = v
        getRenderer().renderTemplate('hbs/cluster/security-tab', m)
    }

    ContentSecurityPolicy getContentSecurityPolicy() { new ContentSecurityPolicy(connectSrc: "'self'") }
}
