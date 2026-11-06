import { request } from './trace-client.js';

export async function resolveTarget(input, settings, signal, choose) {
    let host = input.trim();
    if (host.includes('/')) host = new URL(host.includes('://') ? host : 'https://' + host).hostname;
    if (host.startsWith('[')) host = host.slice(1, host.indexOf(']'));
    else if (host.split(':').length === 2) host = host.split(':')[0];
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) || (host.includes(':') && /^[a-f\d:]+$/i.test(host))) return host;
    let addresses = [];
    if (!settings.localResolve) {
        addresses = (await request('api/traces/resolve', {target:host, ipVersion:settings.ipVersion}, signal)).addresses;
    } else {
        const types = settings.ipVersion === 'ipv4' ? [1] : settings.ipVersion === 'ipv6' ? [28] : [28, 1];
        for (const server of ['https://cloudflare-dns.com/dns-query', 'https://doh.sb/dns-query']) {
            if (signal.aborted) return null;
            try {
                const results = await Promise.all(types.map(async type => {
                    const controller = new AbortController();
                    const abort = () => controller.abort();
                    signal.addEventListener('abort', abort, {once:true});
                    if (signal.aborted) abort();
                    const timer = setTimeout(abort, 3000);
                    try {
                        const response = await fetch(server + '?name=' + encodeURIComponent(host) + '&type=' + type, {headers:{accept:'application/dns-json'}, signal:controller.signal});
                        if (!response.ok) throw new Error('DNS resolve failed');
                        const data = await response.json();
                        return (data.Answer || []).filter(answer => answer.type === type).map(answer => answer.data);
                    } finally { clearTimeout(timer); signal.removeEventListener('abort', abort); }
                }));
                addresses = [...new Set(results.flat())];
                if (addresses.length) break;
            } catch (error) { if (signal.aborted) return null; }
        }
    }
    if (signal.aborted) return null;
    if (addresses.length > 1) return choose(addresses);
    return addresses[0] || null;
}
