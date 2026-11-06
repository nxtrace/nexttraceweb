(function (root, factory) {
    var api = factory();
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = api;
    }
    if (root) {
        root.nextTraceMTRAgg = api;
    }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    var DEFAULT_TABLE_HEADER_LABELS = [
        'HOP',
        'IP',
        'ASN',
        'LOCATION',
        'OWNER',
        'LOSS%',
        'SENT',
        'LAST',
        'AVG',
        'BEST',
        'WORST',
        'STDEV',
        'PTR'
    ];

    function buildTableHeaderHtml(labels) {
        var headerLabels = Array.isArray(labels) && labels.length === DEFAULT_TABLE_HEADER_LABELS.length
            ? labels
            : DEFAULT_TABLE_HEADER_LABELS;

        return '<tr>' + headerLabels.map(function (label) {
            return '<th>' + escapeHTML(String(label)) + '</th>';
        }).join('') + '</tr>';
    }

    var TABLE_HEADER_HTML = buildTableHeaderHtml();

    function renderTableHtml(rows, headerHtml) {
        var bodyHtml = typeof headerHtml === 'string' && headerHtml !== '' ? headerHtml : TABLE_HEADER_HTML;
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
        if (successCount === 0 || value < 0) {
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
        buildTableHeaderHtml: buildTableHeaderHtml,
        renderTableHtml: renderTableHtml,
        renderRowHtml: renderRowHtml,
        escapeHTML: escapeHTML,
        formatLastValue: formatLastValue
    };
});
