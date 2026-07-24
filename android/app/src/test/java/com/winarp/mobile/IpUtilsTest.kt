package com.winarp.mobile

import com.winarp.mobile.net.IpUtils
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class IpUtilsTest {
    @Test
    fun parseRangeShortForm() {
        val ips = IpUtils.parseIpList("192.168.31.105-110")
        assertEquals(6, ips.size)
        assertEquals("192.168.31.105", ips.first())
        assertEquals("192.168.31.110", ips.last())
    }

    @Test
    fun collectTargetsFromTo() {
        val ips = IpUtils.collectTargets("", "192.168.31.105", "192.168.31.110")
        assertEquals(6, ips.size)
    }

    @Test
    fun cidrHostsSlash24() {
        val hosts = IpUtils.cidrHosts("192.168.1.10", 24)
        assertTrue(hosts.contains("192.168.1.1"))
        assertTrue(hosts.contains("192.168.1.254"))
        assertEquals(254, hosts.size)
    }
}
