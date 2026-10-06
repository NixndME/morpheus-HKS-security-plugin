package com.morpheuslab.hkssecurity

import com.morpheusdata.model.ComputeServerGroup
import com.morpheusdata.model.User
import groovy.util.logging.Slf4j

/** Morpheus role permission "HKS Security": none / read (see reports) / full (scan, remove). */
class Access {
    static String level(User user) { user?.permissions?.get(HksSecurityPlugin.PERMISSION) ?: 'none' }
    static boolean canRead(User user) { level(user) in ['read', 'full'] }
    static boolean canScan(User user) { level(user) == 'full' }

    /** HKS clusters are Morpheus-provisioned Kubernetes clusters (type kubernetes-cluster). */
    static boolean isHks(ComputeServerGroup cluster) { cluster?.type?.code == 'kubernetes-cluster' }
}

/** Spring's CSRF token for plain HTML forms, read without a compile dependency on Spring. */
@Slf4j
class Csrf {
    static Map token() {
        try {
            ClassLoader cl = Thread.currentThread().contextClassLoader
            Class rch = Class.forName('org.springframework.web.context.request.RequestContextHolder', true, cl)
            Object req = rch.getMethod('getRequestAttributes').invoke(null)?.getRequest()
            Object tok = req?.getAttribute('_csrf') ?: req?.getAttribute('org.springframework.security.web.csrf.CsrfToken')
            if (tok) return [param: tok.parameterName as String, value: tok.token as String]
        } catch (Throwable t) {
            log.warn("HKS Security: no CSRF token available: ${t}")
        }
        [param: '_csrf', value: '']
    }
}
