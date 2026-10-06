package com.morpheuslab.hkssecurity

import com.morpheusdata.core.MorpheusContext
import com.morpheusdata.core.Plugin
import com.morpheusdata.model.ComputeServerGroup
import com.morpheusdata.model.Permission
import com.morpheusdata.views.HTMLResponse
import com.morpheusdata.views.JsonResponse
import com.morpheusdata.views.ViewModel
import com.morpheusdata.web.PluginController
import com.morpheusdata.web.Route
import groovy.util.logging.Slf4j

/** Start a scan, report its live status, print the report, remove HKS Security from a cluster. */
@Slf4j
class SecurityController implements PluginController {

    Plugin plugin
    MorpheusContext morpheus

    SecurityController(Plugin plugin, MorpheusContext morpheus) { this.plugin = plugin; this.morpheus = morpheus }

    String getCode() { 'hks-security-controller' }
    String getName() { 'HKS Security Controller' }
    MorpheusContext getMorpheus() { morpheus }
    Plugin getPlugin() { plugin }

    List<Route> getRoutes() {
        Permission read = Permission.build(HksSecurityPlugin.PERMISSION, 'read')
        Permission full = Permission.build(HksSecurityPlugin.PERMISSION, 'full')
        [Route.build('/hks-security/status', 'status', read),
         Route.build('/hks-security/report', 'report', read),
         Route.build('/hks-security/scan', 'scan', full),
         Route.build('/hks-security/remove', 'remove', full),
         Route.build('/hks-security/cancel', 'cancel', full)]
    }

    /** Live progress, polled by the tab while a scan runs. */
    def status(ViewModel<Map> model) {
        if (!Access.canRead(model.user)) return JsonResponse.of([error: 'no access'])
        ScanState s = Scanner.state(param(model, 'clusterId') as Long)
        JsonResponse.of(s ? s.toMap() : [running: false])
    }

    def scan(ViewModel<Map> model) {
        Long id = param(model, 'clusterId') as Long
        ComputeServerGroup c = hks(id)
        if (!'POST'.equalsIgnoreCase(model.request?.method as String) || !Access.canScan(model.user) || !c) {
            log.warn("HKS Security: DENIED ${model.user?.username} scan cluster=${id}")
            return back(id, model)
        }
        boolean full = param(model, 'mode') == 'full'
        boolean appsOnly = param(model, 'appsOnly') == 'true'
        ScanState started = Scanner.start(id, c.name, KubeClient.of(morpheus, c), model.user?.username, full, appsOnly)
        if (started) log.info("HKS Security: ${model.user?.username} started a ${full ? 'full' : 'quick'} scan${appsOnly ? ' of application namespaces' : ''} of cluster ${c.name} (${id})")
        else log.info("HKS Security: ${model.user?.username} asked for a scan of cluster ${c.name} (${id}) while one is still running in the cluster")
        back(id, model)
    }

    def cancel(ViewModel<Map> model) {
        Long id = param(model, 'clusterId') as Long
        if ('POST'.equalsIgnoreCase(model.request?.method as String) && Access.canScan(model.user) && hks(id)) {
            if (Scanner.cancel(id)) log.info("HKS Security: ${model.user?.username} cancelled the scan of cluster ${id}")
        }
        back(id, model)
    }

    /** Printable report: open it and use the browser's "Save as PDF". */
    def report(ViewModel<Map> model) {
        Long id = param(model, 'clusterId') as Long
        ComputeServerGroup c = hks(id)
        if (!Access.canRead(model.user) || !c) return HTMLResponse.error('No access to this cluster', 403)
        Map report = ReportStore.load(KubeClient.of(morpheus, c))
        if (!report) return HTMLResponse.error('This cluster has not been scanned yet', 404)
        PanelView v = new PanelView(clusterId: id, clusterName: c.name, report: report, accessLevel: Access.level(model.user), printAll: true)
        ViewModel<PanelView> m = new ViewModel<>()
        m.object = v
        plugin.renderer.renderTemplate('hbs/report-print', m)
    }

    /** Delete the hks-security namespace and the scanner's cluster role from this cluster. */
    def remove(ViewModel<Map> model) {
        Long id = param(model, 'clusterId') as Long
        ComputeServerGroup c = hks(id)
        if (!'POST'.equalsIgnoreCase(model.request?.method as String) || !Access.canScan(model.user) || !c) return back(id, model)
        if (Scanner.state(id)?.running) return back(id, model)
        Cleanup.remove(KubeClient.of(morpheus, c))
        Scanner.STATES.remove(id)
        log.info("HKS Security: ${model.user?.username} removed HKS Security from cluster ${c.name} (${id})")
        back(id, model)
    }

    private ComputeServerGroup hks(Long id) {
        if (!id) return null
        ComputeServerGroup c = null
        try { c = morpheus.services.cluster.get(id) } catch (Throwable ignored) { }
        Access.isHks(c) ? c : null
    }

    private static String param(ViewModel<Map> model, String name) {
        try { (model.request?.parameterMap?.get(name) as List)?.first() as String } catch (Throwable ignored) { null }
    }

    private static HTMLResponse back(Long clusterId, ViewModel model) {
        String url = "/infrastructure/clusters/${clusterId}#!hks-security-tab"
        try { model?.response?.sendRedirect(url); return HTMLResponse.success('') } catch (Throwable ignored) { }
        HTMLResponse.success("<html><head><meta http-equiv=\"refresh\" content=\"0;url=${url}\"></head></html>")
    }
}
