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

    // Translation keys are returned instead of literals so this module stays free of
    // user-facing copy. Callers pass a translate function; without one the key comes back.
    function createKeyTranslator(translate) {
        if (typeof translate === 'function') {
            return translate;
        }
        return function (key) {
            return key;
        };
    }

    function getResolveModeKey(localResolve) {
        return localResolve ? 'summary.resolve.local' : 'summary.resolve.server';
    }

    function getConnectionStatusKey(connectionStatus) {
        if (connectionStatus === 'connected') {
            return 'connection.connected';
        }
        if (connectionStatus === 'disconnected') {
            return 'connection.disconnected';
        }
        return 'connection.connecting';
    }

    function buildSettingsSummary(settings, translate) {
        settings = settings || {};
        var translateKey = createKeyTranslator(translate);
        var summary = [];
        var language = normalizeQuery(settings.language).toUpperCase() || 'CN';
        var intervalSeconds = Number(settings.intervalSeconds);
        var packetSize = normalizeQuery(settings.packetSize);
        var dataProvider = normalizeQuery(settings.dataProvider);

        summary.push(language);
        summary.push(translateKey(getResolveModeKey(Boolean(settings.localResolve))));

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

    function formatTargetSummary(query, resolvedTarget, translate) {
        var normalizedQuery = normalizeQuery(query);
        var normalizedResolvedTarget = normalizeQuery(resolvedTarget);

        if (normalizedQuery === '' && normalizedResolvedTarget === '') {
            return createKeyTranslator(translate)('target.notSet');
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
                labelKey: 'state.disconnected.label',
                tone: 'error',
                detailKey: rowCount > 0
                    ? 'state.disconnected.detail'
                    : 'state.disconnected.detailEmpty'
            };
        }

        switch (taskStatus) {
        case 'resolving':
            return { labelKey: 'state.resolving.label', tone: 'info', detailKey: 'state.resolving.detail' };
        case 'waiting':
            return { labelKey: 'state.waiting.label', tone: 'warning', detailKey: 'state.waiting.detail' };
        case 'running':
            return { labelKey: 'state.running.label', tone: 'success', detailKey: 'state.running.detail' };
        case 'complete':
            return {
                labelKey: 'state.complete.label',
                tone: rowCount > 0 ? 'success' : 'info',
                detailKey: rowCount > 0
                    ? 'state.complete.detail'
                    : 'state.complete.detailEmpty'
            };
        case 'error':
            return {
                labelKey: 'state.error.label',
                tone: 'error',
                detailKey: rowCount > 0
                    ? 'state.error.detail'
                    : 'state.error.detailEmpty'
            };
        default:
            return { labelKey: 'state.idle.label', tone: 'neutral', detailKey: 'state.idle.detail' };
        }
    }

    function deriveEmptyState(taskStatus, connectionStatus, hasRows) {
        if (hasRows) {
            return {
                visible: false,
                tone: 'neutral',
                titleKey: '',
                descriptionKey: ''
            };
        }

        if (connectionStatus === 'disconnected') {
            return {
                visible: true,
                tone: 'error',
                titleKey: 'empty.disconnected.title',
                descriptionKey: 'empty.disconnected.description'
            };
        }

        switch (taskStatus) {
        case 'resolving':
            return {
                visible: true,
                tone: 'info',
                titleKey: 'empty.resolving.title',
                descriptionKey: 'empty.resolving.description'
            };
        case 'waiting':
        case 'running':
            return {
                visible: true,
                tone: 'warning',
                titleKey: 'empty.waiting.title',
                descriptionKey: 'empty.waiting.description'
            };
        case 'error':
            return {
                visible: true,
                tone: 'error',
                titleKey: 'empty.error.title',
                descriptionKey: 'empty.error.description'
            };
        case 'complete':
            return {
                visible: true,
                tone: 'info',
                titleKey: 'empty.complete.title',
                descriptionKey: 'empty.complete.description'
            };
        default:
            return {
                visible: true,
                tone: 'neutral',
                titleKey: 'empty.idle.title',
                descriptionKey: 'empty.idle.description'
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
        getConnectionStatusKey: getConnectionStatusKey,
        getResolveModeKey: getResolveModeKey,
        loadRecentQueries: loadRecentQueries,
        normalizeQuery: normalizeQuery,
        upsertRecentQuery: upsertRecentQuery
    };
});
