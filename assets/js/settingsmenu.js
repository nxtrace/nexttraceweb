import { readSettings, saveSettings } from './settings-store.js';
var pathsApi = window.nextTracePaths;
var settingBtn = document.getElementById('settingBtn');
var settingMenu = document.getElementById('settingMenu');
var settingCloseBtn = document.getElementById('settingCloseBtn');
var settingsBackdrop = document.getElementById('settingsBackdrop');
var saveBtn = document.getElementById('saveBtn');
var intervalTimeRange = document.getElementById('intervalTimeRange');
var intervalTimeInput = document.getElementById('intervalTimeInput');
var packetSizeRange = document.getElementById('packetSizeRange');
var packetSizeInput = document.getElementById('packetSizeInput');
var deviceOptions = document.getElementById('deviceOptions');
var settingsFirstFocusable = document.getElementById('language');
var lastSettingsTrigger = null;

settingBtn.addEventListener('click', function (event) {
    event.preventDefault();
    toggleSettingsMenu();
});

settingCloseBtn.addEventListener('click', function () {
    closeSettingsMenu();
});

settingsBackdrop.addEventListener('click', function () {
    closeSettingsMenu();
});

document.addEventListener('click', function (event) {
    if (!settingMenu.classList.contains('is-open')) {
        return;
    }
    if (settingMenu.contains(event.target) || event.target === settingBtn) {
        return;
    }
    closeSettingsMenu();
});

intervalTimeRange.addEventListener('input', function () {
    intervalTimeInput.value = intervalTimeRange.value;
});

intervalTimeInput.addEventListener('input', function () {
    intervalTimeRange.value = intervalTimeInput.value;
});

packetSizeRange.addEventListener('input', function () {
    packetSizeInput.value = packetSizeRange.value;
});

packetSizeInput.addEventListener('input', function () {
    packetSizeRange.value = packetSizeInput.value;
});

loadAvailableDevices();

saveBtn.addEventListener('click', function (event) {
    event.preventDefault();

    if (!(window.deviceValidateInput() && window.dataProviderValidateInput())) {
        return;
    }

    saveSettings({
        ...readSettings(),
        language: document.getElementById('language').value,
        intervalSeconds: intervalTimeInput.value,
        packetSize: packetSizeInput.value,
        maxHop: document.getElementById('maxHopInput').value,
        minHop: document.getElementById('minHopInput').value,
        port: document.getElementById('portInput').value,
        device: document.getElementById('devInput').value,
        dataProvider: document.getElementById('dataProvider').value,
        localResolve: document.getElementById('localResolveCheckbox').checked
    });

    closeSettingsMenu();
    notifySettingsChanged();
});

document.addEventListener('DOMContentLoaded', async function () {
    loadStoredSettings();
    notifySettingsChanged();

    var resumed = await window.resumeTrace();
    if (resumed) return;

    var urlParams = new URLSearchParams(window.location.search);
    var trace = urlParams.get('trace');
    if (trace) {
        document.getElementById('params').value = trace;
        if (typeof window.syncTargetPreview === 'function') {
            window.syncTargetPreview();
        }
        try {
            await window.startNexttrace();
            console.log('startNexttrace function has completed');
        } catch (error) {
            console.error('An error occurred:', error);
        }
    }
});

function toggleSettingsMenu() {
    if (settingMenu.classList.contains('is-open')) {
        closeSettingsMenu();
        return;
    }
    openSettingsMenu();
}

function openSettingsMenu() {
    lastSettingsTrigger = document.activeElement || settingBtn;
    settingMenu.classList.add('is-open');
    settingMenu.setAttribute('aria-hidden', 'false');
    settingsBackdrop.setAttribute('aria-hidden', 'false');
    settingBtn.setAttribute('aria-expanded', 'true');
    document.body.classList.add('settings-open');
    if (settingsFirstFocusable && typeof settingsFirstFocusable.focus === 'function') {
        settingsFirstFocusable.focus();
    }
}

function closeSettingsMenu() {
    settingMenu.classList.remove('is-open');
    settingMenu.setAttribute('aria-hidden', 'true');
    settingsBackdrop.setAttribute('aria-hidden', 'true');
    settingBtn.setAttribute('aria-expanded', 'false');
    document.body.classList.remove('settings-open');
    if (lastSettingsTrigger && typeof lastSettingsTrigger.focus === 'function') {
        lastSettingsTrigger.focus();
    }
    lastSettingsTrigger = null;
}

function loadStoredSettings() {
    var settings = readSettings();
    var fields = {language:'language', intervalSeconds:'intervalTimeInput', packetSize:'packetSizeInput', maxHop:'maxHopInput', minHop:'minHopInput', port:'portInput', device:'devInput', dataProvider:'dataProvider'};
    Object.keys(fields).forEach(function (key) { document.getElementById(fields[key]).value = settings[key]; });
    intervalTimeRange.value = settings.intervalSeconds;
    packetSizeRange.value = settings.packetSize;
    document.getElementById('localResolveCheckbox').checked = settings.localResolve;
}

function loadAvailableDevices() {
    if (!deviceOptions || !pathsApi || typeof fetch !== 'function') {
        return Promise.resolve();
    }

    return fetch(pathsApi.joinBasePath(window.location.pathname, 'api/devices'), {
        headers: { accept: 'application/json' }
    })
        .then(function (response) {
            if (!response.ok) {
                throw new Error('device list request failed');
            }
            return response.json();
        })
        .then(function (payload) {
            renderDeviceOptions(payload && payload.devices);
        })
        .catch(function () {
            renderDeviceOptions([]);
        });
}

function renderDeviceOptions(devices) {
    deviceOptions.innerHTML = '';
    if (!Array.isArray(devices)) {
        return;
    }

    devices.forEach(function (deviceName) {
        if (typeof deviceName !== 'string' || deviceName.trim() === '') {
            return;
        }
        var option = document.createElement('option');
        option.value = deviceName;
        deviceOptions.appendChild(option);
    });
}

function notifySettingsChanged() {
    document.dispatchEvent(new CustomEvent('ntwa:settings-changed'));
    if (typeof window.syncSettingsSummary === 'function') {
        window.syncSettingsSummary();
    }
}

window.closeSettingsMenu = closeSettingsMenu;
