var socket = io.connect(location.origin);
var mtrAggApi = window.nextTraceMTRAgg;
var uiStateApi = window.nextTraceUIState;
var mtrAggregator = mtrAggApi.createMTRAggregator();
var traceViewState = mtrAggApi.createTraceViewState();
var renderTimer = null;
var shareTimer = null;
var modalCancelHandler = null;
var MTR_RENDER_INTERVAL_MS = 100;
var RECENT_QUERIES_STORAGE_KEY = 'ntwaRecentQueries';

var uiState = {
    connectionStatus: 'connecting',
    taskStatus: 'idle',
    requestedTarget: '',
    resolvedTarget: '',
    rowsRendered: 0,
    noticeMessage: '',
    noticeTone: 'info',
    recentQueries: [],
    shareCopied: false
};

function $(id) {
    return document.getElementById(id);
}

socket.on('connect', function () {
    console.log('Connected');
    uiState.connectionStatus = 'connected';
    if (uiState.taskStatus === 'disconnected') {
        uiState.taskStatus = uiState.rowsRendered > 0 ? 'complete' : 'idle';
        setNotice('Connection restored. Start a new trace when ready.', 'info');
    }
    renderUi();
});

socket.on('disconnect', function () {
    console.log('Disconnected');
    mtrAggApi.cancelTraceIntent(traceViewState);
    traceViewState.acceptUpdates = false;
    uiState.connectionStatus = 'disconnected';
    uiState.taskStatus = 'disconnected';
    hideSelectionModal(false);
    clearScheduledRender();
    setNotice('Connection to the trace service was lost. Current results stay on screen.', 'error');
    renderUi();
});

socket.on('mtr_raw', function (data) {
    if (!traceViewState.acceptUpdates) {
        return;
    }
    if (uiState.taskStatus !== 'running') {
        uiState.taskStatus = 'running';
        clearNotice();
        renderUi();
    }
    mtrAggApi.ingestMTRRawRecord(mtrAggregator, data);
    scheduleTableRender();
});

socket.on('nexttrace_complete', function () {
    console.log('Nexttrace complete');
    traceViewState.acceptUpdates = false;
    if (uiState.connectionStatus === 'connected' && uiState.taskStatus !== 'error') {
        uiState.taskStatus = 'complete';
    }
    renderUi();
});

socket.on('nexttrace_error', function (data) {
    traceViewState.acceptUpdates = false;
    uiState.taskStatus = 'error';
    setNotice(getErrorMessage(data), 'error');
    console.error('Nexttrace error:', data);
    renderUi();
});

socket.on('nexttrace_options', function (data) {
    showSelectionModal('Choose a resolved IP', data, function (index) {
        socket.emit('nexttrace_options_choice', { choice: index + 1 });
    }, function () {
        traceViewState.acceptUpdates = false;
        uiState.taskStatus = 'idle';
        setNotice('Target selection cancelled.', 'info');
        renderUi();
    });
});

function initializePage() {
    uiState.recentQueries = uiStateApi.loadRecentQueries(localStorage.getItem(RECENT_QUERIES_STORAGE_KEY));
    restorePrimaryControls();
    bindPageEvents();
    initTable();
    syncTargetPreview();
    renderUi();
}

function bindPageEvents() {
    $('traceForm').addEventListener('submit', function (event) {
        event.preventDefault();
        startNexttrace();
    });
    $('params').addEventListener('keydown', handleParamsKeyDown);
    $('params').addEventListener('input', function () {
        syncTargetPreview();
        renderActionButtons();
    });
    $('ipVersion').addEventListener('change', persistPrimaryControlState);
    $('protocol').addEventListener('change', persistPrimaryControlState);
    $('startBtn').addEventListener('click', function () {
        startNexttrace();
    });
    $('stopBtn').addEventListener('click', function () {
        stopNexttrace();
    });
    $('resetBtn').addEventListener('click', function () {
        resetForm();
    });
    $('shareBtn').addEventListener('click', function () {
        copyShareLink();
    });
    $('recentQueries').addEventListener('click', handleRecentQueryClick);
    document.querySelectorAll('[data-example-query]').forEach(function (button) {
        button.addEventListener('click', function () {
            $('params').value = button.getAttribute('data-example-query') || '';
            syncTargetPreview();
            renderActionButtons();
            $('params').focus();
        });
    });
    $('ipSelectorClose').addEventListener('click', function () {
        hideSelectionModal(true);
    });
    $('ipSelector').addEventListener('click', function (event) {
        if (event.target === $('ipSelector')) {
            hideSelectionModal(true);
        }
    });
    document.addEventListener('keydown', handleGlobalKeyDown);
    document.addEventListener('ntwa:settings-changed', function () {
        renderStatusSummary();
        renderSettingsSummaryPanel();
    });
}

function restorePrimaryControls() {
    var storedIpVersion = getValueFromLocalStorage('ipVersion');
    var storedProtocol = getValueFromLocalStorage('protocol');

    if (storedIpVersion) {
        $('ipVersion').value = storedIpVersion;
    }
    if (storedProtocol) {
        $('protocol').value = storedProtocol;
    }
}

function persistPrimaryControlState() {
    localStorage.setItem('ipVersion', $('ipVersion').value);
    localStorage.setItem('protocol', $('protocol').value);
    renderStatusSummary();
    renderSettingsSummaryPanel();
}

function prepareTraceStart(query) {
    socket.emit('stop_nexttrace');
    mtrAggApi.cancelTraceIntent(traceViewState);
    hideSelectionModal(false);
    clearScheduledRender();
    mtrAggApi.resetMTRAggregator(mtrAggregator);
    initTable();
    uiState.rowsRendered = 0;
    uiState.requestedTarget = query;
    uiState.resolvedTarget = '';
    uiState.taskStatus = 'resolving';
    traceViewState.acceptUpdates = false;
    clearNotice();
    renderUi();
}

async function startNexttrace() {
    var params = uiStateApi.normalizeQuery($('params').value);
    if (params === '') {
        uiState.taskStatus = 'error';
        setNotice('Enter an IP, domain, or URL before starting a trace.', 'error');
        renderUi();
        return;
    }

    prepareTraceStart(params);
    var startToken = mtrAggApi.beginTraceIntent(traceViewState);

    persistPrimaryControlState();

    var extraSettings = getFormattedSettings();
    var resolvedTarget = await parseDomain(params);
    if (!mtrAggApi.isCurrentTraceIntent(traceViewState, startToken)) {
        return;
    }

    if (resolvedTarget == null) {
        traceViewState.acceptUpdates = false;
        uiState.taskStatus = 'error';
        setNotice('Invalid input or unresolvable domain. Adjust the target or switch resolve mode.', 'error');
        renderUi();
        return;
    }

    uiState.resolvedTarget = resolvedTarget;
    uiState.taskStatus = 'waiting';
    mtrAggApi.setMTRTargetIp(mtrAggregator, isIpLiteral(resolvedTarget) ? resolvedTarget : '');
    rememberRecentQuery(params);
    socket.emit('start_nexttrace', { ip: resolvedTarget, extra: extraSettings });
    renderUi();
}

function stopNexttrace() {
    socket.emit('stop_nexttrace');
    mtrAggApi.cancelTraceIntent(traceViewState);
    traceViewState.acceptUpdates = false;
    clearScheduledRender();
    hideSelectionModal(false);
    uiState.taskStatus = uiState.rowsRendered > 0 ? 'complete' : 'idle';
    setNotice(uiState.rowsRendered > 0 ? 'Trace stopped. Current results are retained.' : '', 'info');
    renderUi();
}

function resetForm() {
    socket.emit('stop_nexttrace');
    mtrAggApi.cancelTraceIntent(traceViewState);
    traceViewState.acceptUpdates = false;
    hideSelectionModal(false);
    clearScheduledRender();
    mtrAggApi.resetMTRAggregator(mtrAggregator);
    uiState.rowsRendered = 0;
    uiState.taskStatus = 'idle';
    uiState.requestedTarget = '';
    uiState.resolvedTarget = '';
    clearNotice();
    $('params').value = '';
    initTable();
    syncTargetPreview();
    renderUi();
}

function clearScheduledRender() {
    if (renderTimer !== null) {
        clearTimeout(renderTimer);
        renderTimer = null;
    }
}

function scheduleTableRender() {
    if (renderTimer !== null) {
        return;
    }
    renderTimer = setTimeout(function () {
        renderTimer = null;
        renderTable();
    }, MTR_RENDER_INTERVAL_MS);
}

function renderTable() {
    var rows = mtrAggApi.buildRenderableRows(mtrAggregator);
    uiState.rowsRendered = rows.length;
    $('output').querySelector('tbody').innerHTML = mtrAggApi.renderTableHtml(rows);
    renderStatusStrip();
    renderEmptyState();
}

function initTable() {
    $('output').querySelector('tbody').innerHTML = mtrAggApi.TABLE_HEADER_HTML;
}

function renderUi() {
    renderStatusStrip();
    renderNotice();
    renderEmptyState();
    renderRecentQueries();
    renderSettingsSummaryPanel();
    renderActionButtons();
}

function renderStatusStrip() {
    var meta = uiStateApi.deriveTaskMeta(uiState.taskStatus, uiState.connectionStatus, uiState.rowsRendered);
    $('taskStatusBadge').textContent = meta.label;
    $('taskStatusBadge').setAttribute('data-tone', meta.tone);
    $('taskStatusDetail').textContent = meta.detail;
    $('targetSummary').textContent = uiStateApi.formatTargetSummary(uiState.requestedTarget, uiState.resolvedTarget);
    $('connectionSummary').textContent = formatConnectionStatus(uiState.connectionStatus);
    renderStatusSummary();
}

function renderStatusSummary() {
    var settings = readCurrentSettings();
    var summary = uiStateApi.buildSettingsSummary(settings);
    $('resolveModeSummary').textContent = uiStateApi.getResolveModeLabel(settings.localResolve);
    $('settingsSummaryInline').textContent = summary.join(' · ');
}

function renderNotice() {
    var notice = $('noticeBanner');
    if (!uiState.noticeMessage) {
        notice.hidden = true;
        notice.textContent = '';
        return;
    }

    notice.hidden = false;
    notice.setAttribute('data-tone', uiState.noticeTone || 'info');
    notice.textContent = uiState.noticeMessage;
}

function renderEmptyState() {
    var emptyState = uiStateApi.deriveEmptyState(
        uiState.taskStatus,
        uiState.connectionStatus,
        uiState.rowsRendered > 0
    );
    var panel = $('resultEmptyState');

    panel.hidden = !emptyState.visible;
    panel.setAttribute('data-tone', emptyState.tone);
    $('resultStateTitle').textContent = emptyState.title;
    $('resultStateText').textContent = emptyState.description;
}

function renderRecentQueries() {
    var container = $('recentQueries');
    container.innerHTML = '';

    if (!uiState.recentQueries.length) {
        container.classList.add('chip-list-empty');
        var emptyLabel = document.createElement('span');
        emptyLabel.className = 'helper-empty';
        emptyLabel.textContent = 'Your recent traces will appear here.';
        container.appendChild(emptyLabel);
        return;
    }

    container.classList.remove('chip-list-empty');
    uiState.recentQueries.forEach(function (query) {
        var button = document.createElement('button');
        button.type = 'button';
        button.className = 'chip-button';
        button.textContent = query;
        button.setAttribute('data-recent-query', query);
        container.appendChild(button);
    });
}

function renderSettingsSummaryPanel() {
    var container = $('settingsSummaryPanel');
    var settings = readCurrentSettings();
    var summaryItems = [
        $('ipVersion').value.toUpperCase(),
        $('protocol').value.toUpperCase()
    ].concat(uiStateApi.buildSettingsSummary(settings));

    container.innerHTML = '';
    summaryItems.forEach(function (item) {
        var chip = document.createElement('span');
        chip.className = 'summary-chip';
        chip.textContent = item;
        container.appendChild(chip);
    });
}

function renderActionButtons() {
    var actionState = uiStateApi.deriveActionState(
        uiState.connectionStatus,
        uiState.taskStatus,
        $('params').value
    );

    $('startBtn').disabled = actionState.startDisabled;
    $('stopBtn').disabled = actionState.stopDisabled;
    $('shareBtn').disabled = actionState.shareDisabled;
    $('shareBtn').textContent = uiState.shareCopied ? 'Link Copied' : 'Copy Share Link';
}

function syncTargetPreview() {
    uiState.requestedTarget = uiStateApi.normalizeQuery($('params').value);
    if (uiState.taskStatus === 'idle') {
        uiState.resolvedTarget = '';
    }
    renderStatusStrip();
}

function rememberRecentQuery(query) {
    uiState.recentQueries = uiStateApi.upsertRecentQuery(uiState.recentQueries, query);
    localStorage.setItem(RECENT_QUERIES_STORAGE_KEY, JSON.stringify(uiState.recentQueries));
    renderRecentQueries();
}

function handleRecentQueryClick(event) {
    var button = event.target.closest('[data-recent-query]');
    if (!button) {
        return;
    }
    $('params').value = button.getAttribute('data-recent-query') || '';
    syncTargetPreview();
    renderActionButtons();
    $('params').focus();
}

function copyShareLink() {
    var shareUrl = uiStateApi.buildShareUrl(
        window.location.origin,
        window.location.pathname,
        $('params').value
    );

    if (!shareUrl) {
        return;
    }

    copyTextToClipboard(shareUrl)
        .then(function () {
            uiState.shareCopied = true;
            setNotice('Share link copied to clipboard.', 'success');
            renderActionButtons();
            if (shareTimer !== null) {
                clearTimeout(shareTimer);
            }
            shareTimer = setTimeout(function () {
                uiState.shareCopied = false;
                renderActionButtons();
            }, 1800);
        })
        .catch(function () {
            setNotice('Copy failed. You can still copy the current URL manually.', 'error');
        });
}

function copyTextToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
        return navigator.clipboard.writeText(text);
    }

    return new Promise(function (resolve, reject) {
        var input = document.createElement('textarea');
        input.value = text;
        input.setAttribute('readonly', '');
        input.style.position = 'absolute';
        input.style.left = '-9999px';
        document.body.appendChild(input);
        input.select();

        try {
            document.execCommand('copy');
            document.body.removeChild(input);
            resolve();
        } catch (error) {
            document.body.removeChild(input);
            reject(error);
        }
    });
}

function handleParamsKeyDown(event) {
    if (event.key === 'Enter') {
        event.preventDefault();
        startNexttrace();
    }
}

function handleGlobalKeyDown(event) {
    if (event.key !== 'Escape') {
        return;
    }
    hideSelectionModal(true);
    if (typeof window.closeSettingsMenu === 'function') {
        window.closeSettingsMenu();
    }
}

function showSelectionModal(title, options, onSelect, onCancel) {
    var modal = $('ipSelector');
    var titleNode = $('ipSelectorTitle');
    var ipListDiv = $('ip-list');
    var safeOptions = Array.isArray(options) ? options : [];

    modalCancelHandler = typeof onCancel === 'function' ? onCancel : null;
    titleNode.textContent = title;
    ipListDiv.innerHTML = '';

    safeOptions.forEach(function (optionLabel, index) {
        var ipElement = document.createElement('button');
        ipElement.type = 'button';
        ipElement.textContent = String(optionLabel);
        ipElement.addEventListener('click', function () {
            hideSelectionModal(false);
            onSelect(index, optionLabel);
        });
        ipListDiv.appendChild(ipElement);
    });

    modal.classList.add('is-open');
}

function hideSelectionModal(triggerCancel) {
    var modal = $('ipSelector');
    if (!modal.classList.contains('is-open')) {
        modalCancelHandler = null;
        return;
    }
    modal.classList.remove('is-open');
    $('ip-list').innerHTML = '';

    if (triggerCancel && modalCancelHandler) {
        var cancelHandler = modalCancelHandler;
        modalCancelHandler = null;
        cancelHandler();
        return;
    }

    modalCancelHandler = null;
}

function setNotice(message, tone) {
    uiState.noticeMessage = message || '';
    uiState.noticeTone = tone || 'info';
    renderNotice();
}

function clearNotice() {
    uiState.noticeMessage = '';
    uiState.noticeTone = 'info';
    renderNotice();
}

function getErrorMessage(data) {
    if (typeof data === 'string' && data.trim() !== '') {
        return data.trim();
    }
    if (data && typeof data.message === 'string' && data.message.trim() !== '') {
        return data.message.trim();
    }
    return '任务执行失败';
}

function getValueFromLocalStorage(key) {
    var value = localStorage.getItem(key);
    return value ? value : null;
}

function readBooleanFromLocalStorage(key, defaultValue) {
    var value = localStorage.getItem(key);
    if (value === null) {
        return defaultValue;
    }
    return value === 'true';
}

function readCurrentSettings() {
    return {
        language: getValueFromLocalStorage('language') || $('language').value || 'cn',
        intervalSeconds: getValueFromLocalStorage('intervalSeconds') || $('intervalTimeInput').value || '0.040',
        packetSize: getValueFromLocalStorage('packetSize') || $('packetSizeInput').value || '52',
        dataProvider: getValueFromLocalStorage('dataProvider') || $('dataProvider').value || '',
        localResolve: readBooleanFromLocalStorage('localResolve', true)
    };
}

function getFormattedSettings() {
    var settings = {
        ipVersion: $('ipVersion').value,
        protocol: $('protocol').value,
        language: getValueFromLocalStorage('language'),
        intervalSeconds: getValueFromLocalStorage('intervalSeconds'),
        packetSize: getValueFromLocalStorage('packetSize'),
        maxHop: getValueFromLocalStorage('maxHop'),
        minHop: getValueFromLocalStorage('minHop'),
        port: getValueFromLocalStorage('port'),
        dataProvider: getValueFromLocalStorage('dataProvider'),
        device: getValueFromLocalStorage('device')
    };

    return JSON.stringify(settings);
}

function fetchWithTimeout(url, options, timeout) {
    timeout = timeout || 3000;
    return Promise.race([
        fetch(url, options),
        new Promise(function (_, reject) {
            setTimeout(function () {
                reject(new Error('请求超时'));
            }, timeout);
        })
    ]);
}

function resolveDomain(domain) {
    return new Promise(function (resolve) {
        var ipVersion = $('ipVersion').value;
        var types = [];
        if (ipVersion === 'ipv6') {
            types = ['AAAA'];
        } else if (ipVersion === 'all') {
            types = ['AAAA', 'A'];
        } else {
            types = ['A'];
        }

        var resolvedAddresses = [];

        function doResolve(dnsUrl) {
            var promises = types.map(function (type) {
                return fetchWithTimeout(dnsUrl + '?name=' + domain + '&type=' + type, {
                    headers: { accept: 'application/dns-json' }
                }, 3000)
                    .then(function (response) {
                        return response.json();
                    })
                    .then(function (data) {
                        if (!data || !data.Answer) {
                            return;
                        }
                        data.Answer.forEach(function (answer) {
                            if (answer && answer.data) {
                                resolvedAddresses.push(answer.data);
                            }
                        });
                    });
            });

            return Promise.all(promises);
        }

        doResolve('https://cloudflare-dns.com/dns-query')
            .catch(function () {
                console.log('Cloudflare DoH failed, retrying with doh.sb');
                return doResolve('https://doh.sb/dns-query');
            })
            .then(function () {
                if (resolvedAddresses.length > 1) {
                    showSelectionModal('Choose a resolved IP', resolvedAddresses, function (index) {
                        resolve(resolvedAddresses[index]);
                    }, function () {
                        resolve(null);
                    });
                    return;
                }
                resolve(resolvedAddresses[0] || null);
            })
            .catch(function () {
                resolve(null);
            });
    });
}

function parseDomain(domain) {
    if ((domain.match(/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/)) || (domain.match(/^[a-fA-F0-9:]+$/))) {
        return Promise.resolve(domain);
    }

    return new Promise(function (resolve) {
        if (!domain || domain === '') {
            resolve(null);
            return;
        }

        if (domain.includes('/')) {
            domain = domain.split('/')[2];
        }

        if (domain.includes(']')) {
            domain = domain.split(']')[0].split('[')[1];
        } else if (domain.includes(':') && (domain.match(/:/g) || []).length === 1) {
            domain = domain.split(':')[0];
        }

        if (readBooleanFromLocalStorage('localResolve', true)) {
            resolveDomain(domain).then(resolve);
            return;
        }

        resolve(domain);
    });
}

function isIpLiteral(value) {
    return /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(value) || /^[a-fA-F0-9:]+$/.test(value);
}

function formatConnectionStatus(status) {
    if (status === 'connected') {
        return 'Connected';
    }
    if (status === 'disconnected') {
        return 'Disconnected';
    }
    return 'Connecting';
}

function deviceValidateInput() {
    var allowedPattern = '^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,126}$';
    var inputElement = $('devInput');
    var errorMessageElement = $('dev-error-message');

    if (inputElement.value === '') {
        errorMessageElement.style.display = 'none';
        return true;
    }

    if (!inputElement.value.match(allowedPattern)) {
        errorMessageElement.style.display = 'inline';
        inputElement.value = '';
        return false;
    }

    errorMessageElement.style.display = 'none';
    return true;
}

function dataProviderValidateInput() {
    var allowedValues = [
        'Ip2region', 'ip2region', 'IP.SB', 'ip.sb', 'IPInfo', 'ipinfo',
        'IPInsight', 'ipinsight', 'IPAPI.com', 'ip-api.com', 'IPInfoLocal',
        'ipinfolocal', 'chunzhen', 'LeoMoeAPI', 'leomoeapi', 'disable-geoip'
    ];
    var inputElement = $('dataProvider');
    var errorMessageElement = $('dp-error-message');

    if (inputElement.value === '') {
        errorMessageElement.style.display = 'none';
        return true;
    }

    if (allowedValues.indexOf(inputElement.value) === -1) {
        errorMessageElement.style.display = 'inline';
        inputElement.value = '';
        return false;
    }

    errorMessageElement.style.display = 'none';
    return true;
}

initializePage();

window.startNexttrace = startNexttrace;
window.stopNexttrace = stopNexttrace;
window.resetForm = resetForm;
window.deviceValidateInput = deviceValidateInput;
window.dataProviderValidateInput = dataProviderValidateInput;
window.syncSettingsSummary = function () {
    renderStatusSummary();
    renderSettingsSummaryPanel();
};
window.syncTargetPreview = syncTargetPreview;
