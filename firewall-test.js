// static/js/firewall-test.js
async function testFirewallConnectivity() {
    const portsToTest = [80, 443, 8080];
    const results = {};
    
    for (const port of portsToTest) {
        try {
            // Use fetch with a timeout to test connectivity
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 2000);
            
            const response = await fetch(`https://your-test-domain.com:${port}/ping`, {
                signal: controller.signal
            });
            
            clearTimeout(timeoutId);
            results[port] = response.ok;
        } catch (e) {
            results[port] = false;
        }
    }
    
    // Send results back to server
    fetch('/api/firewall-test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(results)
    });
    
    return results;
}
