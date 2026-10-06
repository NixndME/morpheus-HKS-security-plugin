package com.morpheuslab.hkssecurity

import com.morpheusdata.core.Plugin
import com.morpheusdata.core.data.DataQuery
import com.morpheusdata.model.ComputeServerGroup
import com.morpheusdata.model.Permission
import com.morpheusdata.views.HandlebarsRenderer
import groovy.util.logging.Slf4j

/** HKS Security: on-demand Trivy + Kubescape scans of HKS clusters, shown in Morpheus. */
@Slf4j
class HksSecurityPlugin extends Plugin {

    static final String PERMISSION = 'hks-security'

    @Override
    String getCode() { 'hks-security' }

    @Override
    void initialize() {
        setName('HKS Security')
        setDescription('On-demand Trivy and Kubescape security scans for HKS clusters')
        // a plugin with controllers must own its renderer (Morpheus 9.0.2), which also gives the nonce helper
        HandlebarsRenderer r = new HandlebarsRenderer('renderer', getClassLoader())
        r.registerAssetHelper(getName())
        r.registerNonceHelper(morpheus.getWebRequest())
        r.registerI18nHelper(this, morpheus)
        setRenderer(r)
        Permission p = Permission.build('HKS Security', PERMISSION, [Permission.AccessType.none, Permission.AccessType.read, Permission.AccessType.full])
        p.subCategory = 'HKS Security'
        setPermissions([p])
        registerProvider(new SecurityTabProvider(this, morpheus))
        controllers.add(new SecurityController(this, morpheus))
    }

    /**
     * Morpheus calls this on upgrade and restart as well as on uninstall. Clean the HKS clusters only when it was
     * an uninstall: after a short wait our jar is gone and no newer copy of this plugin is loaded.
     */
    @Override
    void onDestroy() {
        String jar = getFileName()
        def manager = getPluginManager()
        Plugin self = this
        List<KubeClient> clusters = []
        try {
            clusters = morpheus.services.cluster.list(new DataQuery()).findAll { ComputeServerGroup c -> Access.isHks(c) }
                .collect { ComputeServerGroup c -> KubeClient.of(morpheus, c) }.findAll { it.usable }
        } catch (Throwable t) {
            log.warn("HKS Security: cannot list clusters for clean-up: ${t}")
        }
        Thread t = new Thread({
            try {
                Thread.sleep(20_000)
                boolean jarGone = jar && !new File(jar).exists()
                boolean replaced = manager?.getPlugins()?.any { Plugin p -> p.code == 'hks-security' && !p.is(self) }
                if (!jarGone || replaced) return          // upgrade, restart or shutdown: keep everything
                for (KubeClient k : clusters) {
                    try { Cleanup.remove(k) } catch (Throwable ignored) { }
                }
                log.warn("HKS Security: plugin removed, cleaned ${clusters.size()} HKS cluster(s)")
            } catch (Throwable ignored) { }
        } as Runnable, 'hks-security-uninstall')
        t.daemon = true
        t.start()
        log.info("HKS Security: stopping; HKS clusters are cleaned only if the plugin was removed")
    }
}
