import { resolveTarget } from './target-resolver.js';
import { createView } from './view.js';
import { TraceClient, request } from './trace-client.js';
import { readSettings } from './settings-store.js';
var mtrAggApi = window.nextTraceMTRAgg;
var uiStateApi = window.nextTraceUIState;
var i18nApi = window.nextTraceI18n;
var pathsApi = window.nextTracePaths;
var snapshotRows = [];
var activeIntent = 0;
var resolutionController = null;
var busy = false;
var resumeTimer = null;
var shareTimer = null;
var modalCancelHandler = null;
var activeLocale = i18nApi.DEFAULT_LOCALE;
var tableHeaderHtml = mtrAggApi.TABLE_HEADER_HTML;
var RECENT_QUERIES_STORAGE_KEY = 'ntwaRecentQueries';
var UI_LANGUAGE_STORAGE_KEY = 'uiLanguage';
var LOCALIZED_SERVER_ERROR_CODES = [
    'invalid_payload',
    'invalid_target',
    'start_failed',
    'trace_capacity_exceeded',
    'trace_idle_timeout',
    'trace_max_duration_reached',
    'trace_not_running',
    'trace_rate_limited'
];
var SERVER_ERROR_CODES_WITH_DETAILS = [
    'invalid_payload',
    'invalid_target',
    'trace_not_running'
];

var uiState = {
    connectionStatus: 'connecting',
    taskStatus: 'idle',
    requestedTarget: '',
    resolvedTarget: '',
    rowsRendered: 0,
    noticeKey: '',
    noticeMessage: '',
    noticeTone: 'info',
    recentQueries: [],
    shareCopied: false
};

function $(id) {
    return document.getElementById(id);
}

function t(key) {
    return i18nApi.translate(activeLocale, key);
}

function getBrowserLanguages() {
    if (typeof navigator === 'undefined' || !navigator) {
        return [];
    }
    if (Array.isArray(navigator.languages) && navigator.languages.length > 0) {
        return navigator.languages;
    }
    return [navigator.language];
}

// A stored 'auto' preference (the default) resolves through the browser languages.
function resolveActiveLocale() {
    return i18nApi.detectLocale(localStorage.getItem(UI_LANGUAGE_STORAGE_KEY), getBrowserLanguages());
}

function applyLocale(locale) {
    activeLocale = locale;
    tableHeaderHtml = mtrAggApi.buildTableHeaderHtml(i18nApi.getTableHeaderLabels(locale));
    i18nApi.applyDocumentTranslations(document, locale);
}

function syncLanguageSelect() {
    $('uiLanguage').value = i18nApi.normalizePreference(localStorage.getItem(UI_LANGUAGE_STORAGE_KEY));
}

function handleLanguageChange() {
    localStorage.setItem(UI_LANGUAGE_STORAGE_KEY, i18nApi.normalizePreference($('uiLanguage').value));
    applyLocale(resolveActiveLocale());
    renderUi();
    renderTable();
}

var { renderTable, initTable, renderUi, renderStatusStrip, renderStatusSummary, renderNotice, renderEmptyState, renderRecentQueries, renderSettingsSummaryPanel, renderActionButtons } = createView({$, t, uiState, uiStateApi, mtrAggApi, readCurrentSettings, getRows: function () { return snapshotRows; }, getHeader: function () { return tableHeaderHtml; }});

var traceClient = new TraceClient(function (snapshot) {
    snapshotRows = snapshot.rows;
    uiState.resolvedTarget = snapshot.target || uiState.resolvedTarget;
    if (!uiState.requestedTarget) uiState.requestedTarget = sessionStorage.getItem('ntwaTaskQuery') || snapshot.target || '';
    uiState.taskStatus = {starting:'waiting', running:'running', stopping:'running', completed:'complete', cancelled:'complete', failed:'error'}[snapshot.state];
    busy = ['starting','running','stopping'].includes(snapshot.state);
    if (snapshot.error) {
        var key = getServerErrorKey(snapshot.error);
        if (key) setNotice(key, 'error', shouldShowServerErrorDetail(snapshot.error) ? snapshot.error.message : '');
        else setNoticeText(snapshot.error.message || t('error.taskFailed'), 'error');
    }
    renderTable();
    renderUi();
}, function (connected) {
    uiState.connectionStatus = connected ? 'connected' : 'disconnected';
    renderUi();
});
window.addEventListener('pagehide', function () { hideSelectionModal(true); ++activeIntent; resolutionController?.abort(); traceClient.detach(); clearTimeout(resumeTimer); busy = false; });
window.addEventListener('pageshow', function (event) { if (event.persisted) resumeTrace(); });
async function resumeTrace() {
    var token = activeIntent;
    try {
        await request('api/devices');
        if (token !== activeIntent) return true;
        uiState.connectionStatus = 'connected';
        var resumed = await traceClient.resume();
        if (token !== activeIntent) return true;
        if (resumed) $('params').value = sessionStorage.getItem('ntwaTaskQuery') || uiState.resolvedTarget;
        renderUi();
        return resumed;
    } catch (error) {
        if (token !== activeIntent) return true;
        uiState.connectionStatus = error.status ? 'connected' : 'disconnected';
        if (error.status === 404) {
            traceClient.detach();
            traceClient.id = null;
            busy = false;
            uiState.taskStatus = snapshotRows.length ? 'complete' : 'idle';
        }
        if (error.status && error.status !== 404) {
            busy = false;
            uiState.taskStatus = 'error';
            var key = getServerErrorKey(error);
            if (key) setNotice(key, 'error'); else setNoticeText(error.message, 'error');
            renderUi();
            return true;
        }
        renderUi();
        if (!error.status && (sessionStorage.getItem('ntwaTaskId') || sessionStorage.getItem('ntwaPendingTrace'))) {
            clearTimeout(resumeTimer);
            resumeTimer = setTimeout(resumeTrace, 3000);
            return true;
        }
        return error.status === 404;
    }
}
window.resumeTrace = resumeTrace;

function initializePage() {
    applyLocale(resolveActiveLocale());
    syncLanguageSelect();
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
    $('uiLanguage').addEventListener('change', handleLanguageChange);
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

async function startNexttrace() {
    var query = uiStateApi.normalizeQuery($('params').value);
    if (!query || busy) return;
    busy = true;
    clearTimeout(resumeTimer);
    var token = ++activeIntent;
    resolutionController?.abort();
    resolutionController = new AbortController();
    uiState.taskStatus = 'resolving';
    uiState.requestedTarget = query;
    clearNotice();
    renderUi();
    try {
        var previousId = traceClient.id;
        traceClient.detach();
        traceClient.id = null;
        if (previousId) {
            try { await traceClient.stop(previousId); }
            catch (error) { if (error.status !== 404) throw error; }
        }
        if (token !== activeIntent) return;
        busy = true;
        uiState.taskStatus = 'resolving';
        renderUi();
        snapshotRows = [];
        renderTable();
        var settings = readSettings();
        var resolved = await resolveTarget(query, settings, resolutionController.signal, function (addresses) {
            return new Promise(function (resolve) {
                showSelectionModal(t('modal.ipSelector.title'), addresses, function (index) { resolve(addresses[index]); }, function () {
                    ++activeIntent;
                    busy = false;
                    uiState.taskStatus = 'idle';
                    setNotice('notice.selectionCancelled', 'info');
                    renderUi();
                    resolve(null);
                });
            });
        });
        if (token !== activeIntent) return;
        if (!resolved) throw new Error(t('notice.unresolvable'));
        uiState.resolvedTarget = resolved;
        sessionStorage.setItem('ntwaTaskQuery', query);
        var snapshot = await traceClient.create(resolved, settings);
        if (token !== activeIntent) {
            if (traceClient.id !== snapshot.task_id && sessionStorage.getItem('ntwaTaskId') !== snapshot.task_id) await traceClient.stop(snapshot.task_id);
            return;
        }
        rememberRecentQuery(query);
        traceClient.attach(snapshot);
    } catch (error) {
        if (token !== activeIntent) return;
        busy = false;
        uiState.taskStatus = 'error';
        var key = getServerErrorKey(error);
        if (key) setNotice(key, 'error'); else setNoticeText(error.message, 'error');
        renderUi();
    }
}

async function stopNexttrace() {
    hideSelectionModal(true);
    var token = ++activeIntent;
    clearTimeout(resumeTimer);
    traceClient.detach();
    sessionStorage.removeItem('ntwaPendingTrace');
    sessionStorage.removeItem('ntwaPendingTraceAt');
    resolutionController?.abort();
    busy = true;
    var id = traceClient.id || sessionStorage.getItem('ntwaTaskId');
    try {
        var snapshot = await traceClient.stop(id);
        if (token !== activeIntent) return false;
        if (snapshot) traceClient.attach(snapshot);
    } catch (error) {
        if (token !== activeIntent) return false;
        if (error.status !== 404) {
            busy = false;
            setNoticeText(error.message, 'error');
            renderUi();
            return false;
        }
        traceClient.detach();
        traceClient.id = null;
        if (sessionStorage.getItem('ntwaTaskId') === id) sessionStorage.removeItem('ntwaTaskId');
    }
    if (token !== activeIntent) return false;
    busy = false;
    uiState.taskStatus = snapshotRows.length ? 'complete' : 'idle';
    renderTable();
    renderUi();
    return true;
}

async function resetForm() {
    hideSelectionModal(true);
    var token = activeIntent + 1;
    if (!await stopNexttrace() || token !== activeIntent) return;
    traceClient.detach();
    traceClient.id = null;
    sessionStorage.removeItem('ntwaTaskId');
    sessionStorage.removeItem('ntwaTaskQuery');
    snapshotRows = [];
    uiState.rowsRendered = 0;
    uiState.taskStatus = 'idle';
    uiState.requestedTarget = '';
    uiState.resolvedTarget = '';
    clearNotice();
    $('params').value = '';
    renderTable();
    renderUi();
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
            setNotice('notice.shareCopied', 'success');
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
            setNotice('notice.shareFailed', 'error');
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

// Notices keep a translation key so they follow a language switch. A server-provided
// detail can be retained verbatim alongside the localized summary.
function setNotice(messageKey, tone, detailMessage) {
    uiState.noticeKey = messageKey || '';
    uiState.noticeMessage = detailMessage || '';
    uiState.noticeTone = tone || 'info';
    renderNotice();
}

function setNoticeText(message, tone) {
    uiState.noticeKey = '';
    uiState.noticeMessage = message || '';
    uiState.noticeTone = tone || 'info';
    renderNotice();
}

function clearNotice() {
    uiState.noticeKey = '';
    uiState.noticeMessage = '';
    uiState.noticeTone = 'info';
    renderNotice();
}

// Known codes get a localized summary. Parameter-specific validation codes retain their
// server detail; nexttrace_exit_nonzero and nexttrace_invalid_args remain verbatim.
function getServerErrorKey(data) {
    var code = data && typeof data.code === 'string' ? data.code : '';
    if (code === '') {
        return '';
    }
    return LOCALIZED_SERVER_ERROR_CODES.indexOf(code) === -1 ? '' : 'serverError.' + code;
}

function shouldShowServerErrorDetail(data) {
    var code = data && typeof data.code === 'string' ? data.code : '';
    return SERVER_ERROR_CODES_WITH_DETAILS.indexOf(code) !== -1;
}

function getServerErrorMessage(data) {
    if (typeof data === 'string' && data.trim() !== '') {
        return data.trim();
    }
    if (data && typeof data.message === 'string' && data.message.trim() !== '') {
        return data.message.trim();
    }
    return '';
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

function readCurrentSettings() { return readSettings(); }

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
