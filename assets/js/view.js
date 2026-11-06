export function createView({$, t, uiState, uiStateApi, mtrAggApi, readCurrentSettings, getRows, getHeader}) {
function renderTable() {
    var rows = getRows();
    uiState.rowsRendered = rows.length;
    $('output').querySelector('tbody').innerHTML = mtrAggApi.renderTableHtml(rows, getHeader());
    renderStatusStrip();
    renderEmptyState();
}

function initTable() {
    $('output').querySelector('tbody').innerHTML = getHeader();
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
    $('taskStatusBadge').textContent = t(meta.labelKey);
    $('taskStatusBadge').setAttribute('data-tone', meta.tone);
    $('taskStatusDetail').textContent = t(meta.detailKey);
    $('targetSummary').textContent = uiStateApi.formatTargetSummary(uiState.requestedTarget, uiState.resolvedTarget, t);
    $('connectionSummary').textContent = t(uiStateApi.getConnectionStatusKey(uiState.connectionStatus));
    renderStatusSummary();
}

function renderStatusSummary() {
    var settings = readCurrentSettings();
    var summary = uiStateApi.buildSettingsSummary(settings, t);
    $('resolveModeSummary').textContent = t(uiStateApi.getResolveModeKey(settings.localResolve));
    $('settingsSummaryInline').textContent = summary.join(' · ');
}

function renderNotice() {
    var notice = $('noticeBanner');
    var message = uiState.noticeKey !== '' ? t(uiState.noticeKey) : '';

    if (uiState.noticeMessage !== '') {
        message = message !== '' ? message + ' — ' + uiState.noticeMessage : uiState.noticeMessage;
    }

    if (!message) {
        notice.hidden = true;
        notice.textContent = '';
        return;
    }

    notice.hidden = false;
    notice.setAttribute('data-tone', uiState.noticeTone || 'info');
    notice.textContent = message;
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
    $('resultStateTitle').textContent = t(emptyState.titleKey);
    $('resultStateText').textContent = t(emptyState.descriptionKey);
}

function renderRecentQueries() {
    var container = $('recentQueries');
    container.innerHTML = '';

    if (!uiState.recentQueries.length) {
        container.classList.add('chip-list-empty');
        var emptyLabel = document.createElement('span');
        emptyLabel.className = 'helper-empty';
        emptyLabel.textContent = t('panel.history.empty');
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
    ].concat(uiStateApi.buildSettingsSummary(settings, t));

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
    $('shareBtn').textContent = uiState.shareCopied ? t('action.shareCopied') : t('action.share');
}


return {renderTable, initTable, renderUi, renderStatusStrip, renderStatusSummary, renderNotice, renderEmptyState, renderRecentQueries, renderSettingsSummaryPanel, renderActionButtons};
}
