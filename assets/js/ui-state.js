(function (root, factory) {
    var api = factory();
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = api;
    }
    if (root) {
        root.nextTraceUIState = api;
    }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    var DEFAULT_RECENT_QUERY_LIMIT = 6;

    function normalizeQuery(value) {
        if (typeof value === 'string') {
            return value.trim();
        }
        if (value === undefined || value === null) {
            return '';
        }
        return String(value).trim();
    }

    function loadRecentQueries(storedValue, limit) {
        var parsed = storedValue;
        if (typeof storedValue === 'string') {
            try {
                parsed = JSON.parse(storedValue);
            } catch (_error) {
                parsed = [];
            }
        }

        if (!Array.isArray(parsed)) {
            return [];
        }
        return dedupeQueries(parsed, limit);
    }

    function upsertRecentQuery(existingQueries, query, limit) {
        var normalizedQuery = normalizeQuery(query);
        var queries = dedupeQueries(existingQueries, limit).filter(function (item) {
            return item.toLowerCase() !== normalizedQuery.toLowerCase();
        });

        if (normalizedQuery !== '') {
            queries.unshift(normalizedQuery);
        }
        return queries.slice(0, resolveRecentLimit(limit));
    }

    function buildShareUrl(origin, pathname, query) {
        var normalizedQuery = normalizeQuery(query);
        if (normalizedQuery === '') {
            return '';
        }

        var url = new URL(pathname || '/', origin || 'http://localhost');
        url.searchParams.set('trace', normalizedQuery);
        return url.toString();
    }

    function getResolveModeLabel(localResolve) {
        return localResolve ? 'Local Resolve' : 'Server Resolve';
    }

    function buildSettingsSummary(settings) {
        settings = settings || {};
        var summary = [];
        var language = normalizeQuery(settings.language).toUpperCase() || 'CN';
        var intervalSeconds = Number(settings.intervalSeconds);
        var packetSize = normalizeQuery(settings.packetSize);
        var dataProvider = normalizeQuery(settings.dataProvider);

        summary.push(language);
        summary.push(getResolveModeLabel(Boolean(settings.localResolve)));

        if (Number.isFinite(intervalSeconds) && intervalSeconds > 0) {
            summary.push(String(Math.round(intervalSeconds * 1000)) + ' ms');
        }
        if (packetSize !== '') {
            summary.push(packetSize + ' B');
        }
        if (dataProvider !== '') {
            summary.push(dataProvider);
        }

        return summary;
    }

    function formatTargetSummary(query, resolvedTarget) {
        var normalizedQuery = normalizeQuery(query);
        var normalizedResolvedTarget = normalizeQuery(resolvedTarget);

        if (normalizedQuery === '' && normalizedResolvedTarget === '') {
            return 'Not set';
        }
        if (
            normalizedQuery !== '' &&
            normalizedResolvedTarget !== '' &&
            normalizedQuery.toLowerCase() !== normalizedResolvedTarget.toLowerCase()
        ) {
            return normalizedQuery + ' -> ' + normalizedResolvedTarget;
        }
        return normalizedResolvedTarget || normalizedQuery;
    }

    function deriveActionState(connectionStatus, taskStatus, query) {
        var hasQuery = normalizeQuery(query) !== '';
        var isBusy = ['resolving', 'waiting', 'running'].indexOf(taskStatus) !== -1;

        return {
            startDisabled: connectionStatus !== 'connected' || !hasQuery || isBusy,
            stopDisabled: connectionStatus !== 'connected' || !isBusy,
            shareDisabled: !hasQuery
        };
    }

    function deriveTaskMeta(taskStatus, connectionStatus, rowCount) {
        if (connectionStatus === 'disconnected') {
            return {
                label: 'Disconnected',
                tone: 'error',
                detail: rowCount > 0
                    ? 'Connection lost. Current results stay on screen.'
                    : 'Connection lost. Reconnect before starting a new trace.'
            };
        }

        switch (taskStatus) {
        case 'resolving':
            return { label: 'Resolving', tone: 'info', detail: 'Resolving the target before starting the trace.' };
        case 'waiting':
            return { label: 'Waiting', tone: 'warning', detail: 'Trace started. Waiting for the first hop.' };
        case 'running':
            return { label: 'Running', tone: 'success', detail: 'Streaming hop data in real time.' };
        case 'complete':
            return {
                label: 'Complete',
                tone: rowCount > 0 ? 'success' : 'info',
                detail: rowCount > 0
                    ? 'Trace finished. Results are retained until you reset.'
                    : 'Trace finished without any hop data.'
            };
        case 'error':
            return {
                label: 'Error',
                tone: 'error',
                detail: rowCount > 0
                    ? 'The trace ended with an error. Current results are retained.'
                    : 'The trace could not be started. Adjust the target or settings.'
            };
        default:
            return { label: 'Idle', tone: 'neutral', detail: 'Ready for a new trace.' };
        }
    }

    function deriveEmptyState(taskStatus, connectionStatus, hasRows) {
        if (hasRows) {
            return {
                visible: false,
                tone: 'neutral',
                title: '',
                description: ''
            };
        }

        if (connectionStatus === 'disconnected') {
            return {
                visible: true,
                tone: 'error',
                title: 'Disconnected',
                description: 'The trace service is unreachable. Reconnect and start again when the session returns.'
            };
        }

        switch (taskStatus) {
        case 'resolving':
            return {
                visible: true,
                tone: 'info',
                title: 'Resolving target',
                description: 'Checking the target and resolving DNS before the trace starts.'
            };
        case 'waiting':
        case 'running':
            return {
                visible: true,
                tone: 'warning',
                title: 'Waiting for first hop',
                description: 'The trace is running. Results will appear here as soon as the first hop arrives.'
            };
        case 'error':
            return {
                visible: true,
                tone: 'error',
                title: 'Trace failed',
                description: 'Adjust the target or settings, then try again.'
            };
        case 'complete':
            return {
                visible: true,
                tone: 'info',
                title: 'Trace finished',
                description: 'The task completed, but no hop data was captured.'
            };
        default:
            return {
                visible: true,
                tone: 'neutral',
                title: 'Ready for a new trace',
                description: 'Enter an IP, domain, or URL to start streaming hop data.'
            };
        }
    }

    function dedupeQueries(values, limit) {
        var sanitized = [];
        var seen = new Set();
        var recentLimit = resolveRecentLimit(limit);

        (Array.isArray(values) ? values : []).forEach(function (value) {
            var normalizedValue = normalizeQuery(value);
            var lookupKey = normalizedValue.toLowerCase();
            if (normalizedValue === '' || seen.has(lookupKey)) {
                return;
            }
            seen.add(lookupKey);
            sanitized.push(normalizedValue);
        });

        return sanitized.slice(0, recentLimit);
    }

    function resolveRecentLimit(limit) {
        var parsedLimit = Number(limit);
        if (!Number.isFinite(parsedLimit) || parsedLimit < 1) {
            return DEFAULT_RECENT_QUERY_LIMIT;
        }
        return Math.floor(parsedLimit);
    }

    return {
        DEFAULT_RECENT_QUERY_LIMIT: DEFAULT_RECENT_QUERY_LIMIT,
        buildSettingsSummary: buildSettingsSummary,
        buildShareUrl: buildShareUrl,
        deriveActionState: deriveActionState,
        deriveEmptyState: deriveEmptyState,
        deriveTaskMeta: deriveTaskMeta,
        formatTargetSummary: formatTargetSummary,
        getResolveModeLabel: getResolveModeLabel,
        loadRecentQueries: loadRecentQueries,
        normalizeQuery: normalizeQuery,
        upsertRecentQuery: upsertRecentQuery
    };
});
