var socket = io.connect(location.origin);
var mtrAggApi = window.nextTraceMTRAgg;
var mtrAggregator = mtrAggApi.createMTRAggregator();
var traceViewState = mtrAggApi.createTraceViewState();
var renderTimer = null;
var MTR_RENDER_INTERVAL_MS = 100;
var modalCancelHandler = null;

function $(id) {
    return document.getElementById(id);
}

socket.on('connect', function () {
    console.log('Connected');
});

socket.on('disconnect', function () {
    console.log('Disconnected');
    resetTraceView(false);
});

socket.on('mtr_raw', function (data) {
    if (!traceViewState.acceptUpdates) {
        return;
    }
    mtrAggApi.ingestMTRRawRecord(mtrAggregator, data);
    scheduleTableRender();
});

socket.on('nexttrace_complete', function () {
    console.log('Nexttrace complete');
});

socket.on('nexttrace_error', function (data) {
    resetTraceView(false);
    var message = '任务执行失败';
    if (typeof data === 'string' && data.trim() !== '') {
        message = data.trim();
    } else if (data && typeof data.message === 'string' && data.message.trim() !== '') {
        message = data.message.trim();
    }
    console.error('Nexttrace error:', data);
    alert(message);
});

socket.on('nexttrace_options', function (data) {
    showSelectionModal('请选择一个 IP 地址:', data, function (index) {
        socket.emit('nexttrace_options_choice', { choice: index + 1 });
    });
});

function initializePage() {
    $('params').addEventListener('keydown', handleParamsKeyDown);
    $('startBtn').addEventListener('click', function () {
        startNexttrace();
    });
    $('stopBtn').addEventListener('click', function () {
        stopNexttrace();
    });
    $('resetBtn').addEventListener('click', function () {
        resetForm();
    });
    $('ipSelectorClose').addEventListener('click', function () {
        hideSelectionModal(true);
    });
    $('ipSelector').addEventListener('click', function (event) {
        if (event.target === $('ipSelector')) {
            hideSelectionModal(true);
        }
    });
    initTable();
}

function prepareTraceStart() {
    clearScheduledRender();
    hideSelectionModal(false);
    mtrAggApi.resetMTRAggregator(mtrAggregator);
    traceViewState.acceptUpdates = false;
    initTable();
    socket.emit('stop_nexttrace');
}

function resetTraceView(emitStop) {
    mtrAggApi.cancelTraceIntent(traceViewState);
    clearScheduledRender();
    hideSelectionModal(false);
    mtrAggApi.resetMTRAggregator(mtrAggregator);
    initTable();
    if (emitStop) {
        socket.emit('stop_nexttrace');
    }
}

async function startNexttrace() {
    prepareTraceStart();
    var startToken = mtrAggApi.beginTraceIntent(traceViewState);
    var params = $('params').value;

    localStorage.setItem('ipVersion', $('ipVersion').value);
    localStorage.setItem('protocol', $('protocol').value);

    var extraSettings = getFormattedSettings();
    var ip = await parseDomain(params);
    if (!mtrAggApi.isCurrentTraceIntent(traceViewState, startToken)) {
        return;
    }

    if (ip == null) {
        $('params').placeholder = 'Invalid input or unresolvable domain';
        traceViewState.acceptUpdates = false;
        alert('Invalid input or unresolvable domain');
        return;
    }

    traceViewState.acceptUpdates = true;
    socket.emit('start_nexttrace', { ip: ip, extra: extraSettings });
}

function stopNexttrace() {
    resetTraceView(true);
}

function resetForm() {
    stopNexttrace();
    $('params').value = '';
    initTable();
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
    $('output').querySelector('tbody').innerHTML = mtrAggApi.renderTableHtml(rows);
}

function initTable() {
    $('output').querySelector('tbody').innerHTML = mtrAggApi.TABLE_HEADER_HTML;
}

function handleParamsKeyDown(event) {
    if (event.key === 'Enter') {
        event.preventDefault();
        startNexttrace();
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

    modal.style.display = 'block';
}

function hideSelectionModal(triggerCancel) {
    var modal = $('ipSelector');
    if (modal.style.display !== 'block') {
        modalCancelHandler = null;
        return;
    }
    modal.style.display = 'none';
    $('ip-list').innerHTML = '';

    if (triggerCancel && modalCancelHandler) {
        var cancelHandler = modalCancelHandler;
        modalCancelHandler = null;
        cancelHandler();
        return;
    }

    modalCancelHandler = null;
}

function getValueFromLocalStorage(key) {
    var value = localStorage.getItem(key);
    return value ? value : null;
}

function getFormattedSettings() {
    var settings = {
        ipVersion: getValueFromLocalStorage('ipVersion'),
        protocol: getValueFromLocalStorage('protocol'),
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
        var ipVersion = getValueFromLocalStorage('ipVersion');
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
                console.log('使用 Cloudflare 失败，尝试使用 doh.sb');
                return doResolve('https://doh.sb/dns-query');
            })
            .then(function () {
                if (resolvedAddresses.length > 1) {
                    showSelectionModal('请选择一个 IP 地址:', resolvedAddresses, function (index) {
                        resolve(resolvedAddresses[index]);
                    }, function () {
                        resolve(null);
                    });
                    return;
                }
                resolve(resolvedAddresses[0] || null);
            })
            .catch(function () {
                alert('无法解析域名，请检查你与 DOH 服务器的连接，或切换到 SERVER RESOLVE 模式。');
                var userChoice = confirm('是否切换为 SERVER RESOLVE 模式？');
                if (userChoice) {
                    localStorage.setItem('localResolve', 'false');
                    $('localResolveCheckbox').checked = false;
                } else {
                    alert('RESOLVE 模式稍后可以在 Settings 中修改。');
                }
                resolve(null);
            });
    });
}

function parseDomain(domain) {
    if ((domain.match(/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/)) || (domain.match(/^[a-fA-F0-9:]+$/))) {
        return domain;
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

        var localResolve = getValueFromLocalStorage('localResolve');
        if (localResolve === 'true') {
            resolveDomain(domain).then(resolve);
            return;
        }

        resolve(domain);
    });
}

function deviceValidateInput() {
    var allowedPattern = '^[a-zA-Z]*\\d*$';
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
