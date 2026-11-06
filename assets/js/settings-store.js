export const defaults = {ipVersion:'all', protocol:'icmp', language:'cn', intervalSeconds:'1.000', packetSize:'52', maxHop:'30', minHop:'1', port:'80', device:'', dataProvider:'', localResolve:true};
export function readSettings() {
    const result = {...defaults};
    for (const key of Object.keys(defaults)) {
        const value = localStorage.getItem(key);
        if (value !== null) result[key] = key === 'localResolve' ? value === 'true' : value;
    }
    result.ipVersion = document.getElementById('ipVersion').value;
    result.protocol = document.getElementById('protocol').value;
    return result;
}
export function saveSettings(values) {
    for (const [key, value] of Object.entries(values)) localStorage.setItem(key, String(value));
}
