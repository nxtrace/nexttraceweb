(function (root, factory) {
    var api = factory();
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = api;
    }
    if (root) {
        root.nextTraceMTRAgg = api;
    }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    var TABLE_HEADER_HTML = [
        '<tr>',
        '<th>HOP</th>',
        '<th>IP</th>',
        '<th>ASN</th>',
        '<th>LOCATION</th>',
        '<th>OWNER</th>',
        '<th>LOSS%</th>',
        '<th>SENT</th>',
        '<th>LAST</th>',
        '<th>AVG</th>',
        '<th>BEST</th>',
        '<th>WORST</th>',
        '<th>STDEV</th>',
        '<th>PTR</th>',
        '</tr>'
    ].join('');

    function createMTRAggregator() {
        return {
            rows: new Map()
        };
    }

    function resetMTRAggregator(aggregator) {
        if (aggregator && aggregator.rows) {
            aggregator.rows.clear();
        }
    }

    function createTraceViewState() {
        return {
            acceptUpdates: false,
            intentToken: 0
        };
    }

    function beginTraceIntent(state) {
        state.intentToken += 1;
        state.acceptUpdates = true;
        return state.intentToken;
    }

    function cancelTraceIntent(state) {
        state.intentToken += 1;
        state.acceptUpdates = false;
        return state.intentToken;
    }

    function isCurrentTraceIntent(state, token) {
        return !!state && state.acceptUpdates && state.intentToken === token;
    }

    function ingestMTRRawRecord(aggregator, rec) {
        if (!aggregator || !aggregator.rows) {
            return null;
        }
        var ttl = Number(rec && rec.ttl);
        if (!Number.isFinite(ttl)) {
            return null;
        }

        var row = aggregator.rows.get(ttl);
        if (!row) {
            row = createEmptyRow(ttl);
            aggregator.rows.set(ttl, row);
        }

        row.sent += 1;

        assignIfPresent(row, 'ip', rec && rec.ip);
        assignIfPresent(row, 'ptr', rec && rec.host);
        assignIfPresent(row, 'asn', rec && rec.asn);
        assignIfPresent(row, 'country', rec && rec.country);
        assignIfPresent(row, 'prov', rec && rec.prov);
        assignIfPresent(row, 'city', rec && rec.city);
        assignIfPresent(row, 'district', rec && rec.district);
        assignIfPresent(row, 'owner', rec && rec.owner);

        var rttMs = toFiniteNumber(rec && rec.rtt_ms);
        if (rec && rec.success && rttMs > 0) {
            row.lastMs = rttMs;
            row.lastIsTimeout = false;
            row.latencySum += rttMs;
            row.latencies.push(rttMs);
            if (row.bestMs === 0 || rttMs < row.bestMs) {
                row.bestMs = rttMs;
            }
            if (rttMs > row.worstMs) {
                row.worstMs = rttMs;
            }
        } else {
            row.lastIsTimeout = true;
        }

        return row;
    }

    function buildRenderableRows(aggregator) {
        if (!aggregator || !aggregator.rows) {
            return [];
        }

        return Array.from(aggregator.rows.values())
            .sort(function (left, right) {
                return left.ttl - right.ttl;
            })
            .map(function (row) {
                var successCount = row.latencies.length;
                var lossCount = Math.max(0, row.sent - successCount);
                var avgMs = successCount > 0 ? row.latencySum / successCount : 0;
                var stdevMs = calculateStdev(row.latencies, avgMs);

                return {
                    ttl: row.ttl,
                    ip: row.ip,
                    ptr: row.ptr,
                    asn: row.asn,
                    location: formatLocation(row.country, row.prov, row.city, row.district),
                    owner: row.owner,
                    sent: row.sent,
                    successCount: successCount,
                    lossCount: lossCount,
                    lossPercent: row.sent > 0 ? (lossCount / row.sent) * 100 : 0,
                    lastMs: row.lastMs,
                    lastIsTimeout: row.lastIsTimeout,
                    avgMs: avgMs,
                    bestMs: row.bestMs,
                    worstMs: row.worstMs,
                    stdevMs: stdevMs
                };
            });
    }

    function renderTableHtml(rows) {
        var bodyHtml = TABLE_HEADER_HTML;
        (rows || []).forEach(function (row) {
            bodyHtml += renderRowHtml(row);
        });
        return bodyHtml;
    }

    function renderRowHtml(row) {
        return [
            '<tr>',
            renderCell('hops', row.ttl),
            renderCell('ip', row.ip),
            renderCell('asn', row.asn),
            renderCell('location', row.location),
            renderCell('owner', row.owner),
            renderCell('lossPktRate', formatLossPercent(row.lossPercent), buildLossStyle(row.lossPercent)),
            renderCell('sent', row.sent),
            renderCell('latency_last', formatLastValue(row), buildLatencyStyle(row.lastIsTimeout ? 0 : row.lastMs)),
            renderCell('latency_avg', formatMetricValue(row.successCount, row.avgMs), buildLatencyStyle(row.avgMs)),
            renderCell('latency_best', formatMetricValue(row.successCount, row.bestMs), buildLatencyStyle(row.bestMs)),
            renderCell('latency_worst', formatMetricValue(row.successCount, row.worstMs), buildLatencyStyle(row.worstMs)),
            renderCell('latency_std', formatStdevValue(row), buildStdevStyle(row.stdevMs)),
            renderCell('rdns', row.ptr),
            '</tr>'
        ].join('');
    }

    function renderCell(className, value, style) {
        var styleAttr = style ? ' style="' + style + '"' : '';
        return '<td class="' + className + '"' + styleAttr + '>' + escapeHTML(String(value)) + '</td>';
    }

    function formatLossPercent(lossPercent) {
        return String(Math.round(lossPercent * 10) / 10);
    }

    function formatLastValue(row) {
        if (!row || row.successCount === 0 || row.lastIsTimeout) {
            return '-';
        }
        return row.lastMs.toFixed(2);
    }

    function formatMetricValue(successCount, value) {
        if (successCount === 0 || value <= 0) {
            return '-';
        }
        return value.toFixed(2);
    }

    function formatStdevValue(row) {
        if (!row || row.successCount === 0) {
            return '0';
        }
        return row.stdevMs.toFixed(2);
    }

    function buildLatencyStyle(latency) {
        if (!latency || isNaN(latency)) {
            return '';
        }
        var color = getRGB(latency);
        return 'background-color: rgb(' + color.r + ',' + color.g + ',' + color.b + ')';
    }

    function buildStdevStyle(stdev) {
        if (!stdev || isNaN(stdev)) {
            return '';
        }
        var color = getRGBstdev(stdev);
        return 'background-color: rgb(' + color.r + ',' + color.g + ',' + color.b + ')';
    }

    function buildLossStyle(lossPercent) {
        if (!lossPercent || isNaN(lossPercent)) {
            return '';
        }
        return 'background-color: ' + getLossColor(lossPercent);
    }

    function escapeHTML(value) {
        return value
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function formatLocation(country, prov, city, district) {
        return [country, prov, city, district]
            .map(normalizeString)
            .filter(function (part) {
                return part !== '';
            })
            .join(' / ');
    }

    function createEmptyRow(ttl) {
        return {
            ttl: ttl,
            ip: '',
            ptr: '',
            asn: '',
            country: '',
            prov: '',
            city: '',
            district: '',
            owner: '',
            sent: 0,
            lastMs: 0,
            lastIsTimeout: false,
            bestMs: 0,
            worstMs: 0,
            latencySum: 0,
            latencies: []
        };
    }

    function assignIfPresent(target, key, value) {
        var normalized = normalizeString(value);
        if (normalized !== '') {
            target[key] = normalized;
        }
    }

    function normalizeString(value) {
        if (typeof value === 'string') {
            return value.trim();
        }
        if (value === undefined || value === null) {
            return '';
        }
        return String(value).trim();
    }

    function toFiniteNumber(value) {
        var number = Number(value);
        return Number.isFinite(number) ? number : 0;
    }

    function calculateStdev(values, avgMs) {
        if (!values || values.length === 0) {
            return 0;
        }

        var variance = 0;
        values.forEach(function (value) {
            variance += Math.pow(value - avgMs, 2);
        });
        return Math.sqrt(variance / values.length);
    }

    function getRGB(latency) {
        var result = { r: 0, g: 0, b: 0 };
        if (isNaN(latency) || latency === 0) {
            return result;
        }
        var colorR = Math.round((latency - 180) / 2);
        if (colorR < 0) colorR = 0;
        if (colorR > 100) colorR = 100;

        var colorG = Math.round(40 - 0.000005 * Math.pow(latency, 3));
        if (colorG < 0) colorG = 0;
        if (colorG > 40) colorG = 40;

        result.r = colorR;
        result.g = colorG;
        return result;
    }

    function getRGBstdev(stdev) {
        var result = { r: 0, g: 0, b: 0 };
        if (isNaN(stdev) || stdev === 0) {
            return result;
        }
        var colorR = Math.round((stdev - 5) * 4);
        if (colorR < 0) colorR = 0;
        if (colorR > 100) colorR = 100;

        result.r = colorR;
        return result;
    }

    function getLossColor(loss) {
        var colorLossR = Math.round(Math.pow(loss, 1.6) + 10);
        if (colorLossR < 11) colorLossR = 0;
        if (colorLossR > 160) colorLossR = 160;
        return 'rgba(' + colorLossR + ',0,0,1)';
    }

    return {
        TABLE_HEADER_HTML: TABLE_HEADER_HTML,
        beginTraceIntent: beginTraceIntent,
        buildLatencyStyle: buildLatencyStyle,
        buildLossStyle: buildLossStyle,
        buildRenderableRows: buildRenderableRows,
        buildStdevStyle: buildStdevStyle,
        cancelTraceIntent: cancelTraceIntent,
        createMTRAggregator: createMTRAggregator,
        createTraceViewState: createTraceViewState,
        escapeHTML: escapeHTML,
        formatLastValue: formatLastValue,
        formatLocation: formatLocation,
        formatLossPercent: formatLossPercent,
        formatMetricValue: formatMetricValue,
        formatStdevValue: formatStdevValue,
        ingestMTRRawRecord: ingestMTRRawRecord,
        isCurrentTraceIntent: isCurrentTraceIntent,
        renderRowHtml: renderRowHtml,
        renderTableHtml: renderTableHtml,
        resetMTRAggregator: resetMTRAggregator
    };
});
