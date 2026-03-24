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

    localStorage.setItem('language', document.getElementById('language').value);
    localStorage.setItem('intervalSeconds', document.getElementById('intervalTimeInput').value);
    localStorage.setItem('packetSize', document.getElementById('packetSizeInput').value);
    localStorage.setItem('maxHop', document.getElementById('maxHopInput').value);
    localStorage.setItem('minHop', document.getElementById('minHopInput').value);
    localStorage.setItem('port', document.getElementById('portInput').value);
    localStorage.setItem('device', document.getElementById('devInput').value);
    localStorage.setItem('dataProvider', document.getElementById('dataProvider').value);
    localStorage.setItem('localResolve', document.getElementById('localResolveCheckbox').checked);

    closeSettingsMenu();
    notifySettingsChanged();
});

document.addEventListener('DOMContentLoaded', async function () {
    loadStoredSettings();
    notifySettingsChanged();

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
    if (localStorage.getItem('localResolve') === null) {
        localStorage.setItem('localResolve', true);
    }
    if (localStorage.getItem('protocol')) {
        document.getElementById('protocol').value = localStorage.getItem('protocol');
    }
    if (localStorage.getItem('ipVersion')) {
        document.getElementById('ipVersion').value = localStorage.getItem('ipVersion');
    }
    if (localStorage.getItem('language')) {
        document.getElementById('language').value = localStorage.getItem('language');
    }
    if (localStorage.getItem('intervalSeconds')) {
        var intervalSeconds = localStorage.getItem('intervalSeconds');
        document.getElementById('intervalTimeInput').value = intervalSeconds;
        document.getElementById('intervalTimeRange').value = intervalSeconds;
    }
    if (localStorage.getItem('packetSize')) {
        var packetSize = localStorage.getItem('packetSize');
        document.getElementById('packetSizeInput').value = packetSize;
        document.getElementById('packetSizeRange').value = packetSize;
    }
    if (localStorage.getItem('maxHop')) {
        document.getElementById('maxHopInput').value = localStorage.getItem('maxHop');
    }
    if (localStorage.getItem('minHop')) {
        document.getElementById('minHopInput').value = localStorage.getItem('minHop');
    }
    if (localStorage.getItem('port')) {
        document.getElementById('portInput').value = localStorage.getItem('port');
    }
    if (localStorage.getItem('device')) {
        document.getElementById('devInput').value = localStorage.getItem('device');
    }
    if (localStorage.getItem('dataProvider')) {
        document.getElementById('dataProvider').value = localStorage.getItem('dataProvider');
    }
    if (localStorage.getItem('localResolve')) {
        document.getElementById('localResolveCheckbox').checked = localStorage.getItem('localResolve') === 'true';
    }
}

function loadAvailableDevices() {
    if (!deviceOptions || typeof fetch !== 'function') {
        return Promise.resolve();
    }

    return fetch('/api/devices', {
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
