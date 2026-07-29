(function (root, factory) {
    var api = factory();
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = api;
    }
    if (root) {
        root.nextTraceI18n = api;
    }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    var DEFAULT_LOCALE = 'en';
    var SUPPORTED_LOCALES = ['en', 'zh'];
    var AUTO_PREFERENCE = 'auto';
    var SUPPORTED_PREFERENCES = [AUTO_PREFERENCE].concat(SUPPORTED_LOCALES);
    var LOCALE_HTML_LANG = {
        en: 'en',
        zh: 'zh-CN'
    };
    var TABLE_HEADER_KEYS = [
        'table.header.hop',
        'table.header.ip',
        'table.header.asn',
        'table.header.location',
        'table.header.owner',
        'table.header.loss',
        'table.header.sent',
        'table.header.last',
        'table.header.avg',
        'table.header.best',
        'table.header.worst',
        'table.header.stdev',
        'table.header.ptr'
    ];
    var ATTRIBUTE_BINDINGS = [
        { attribute: 'placeholder', markup: 'data-i18n-placeholder' },
        { attribute: 'aria-label', markup: 'data-i18n-aria-label' },
        { attribute: 'title', markup: 'data-i18n-title' }
    ];

    var DICTIONARIES = {
        en: {
            'app.title': 'NextTrace Web',

            'header.eyebrow': 'ping.pe inspired traceroute surface',
            'header.tagline': 'Stream hop-by-hop route data with a denser layout, clearer state feedback, and faster repeat workflows.',
            'header.language': 'Interface',
            'language.auto': 'Auto',

            'form.target.label': 'Target',
            'form.target.placeholder': 'IP / domain / URL',
            'form.ipVersion.label': 'IP Version',
            'form.protocol.label': 'Protocol',

            'action.start': 'Start',
            'action.stop': 'Stop',
            'action.reset': 'Reset',
            'action.settings': 'Settings',
            'action.share': 'Copy Share Link',
            'action.shareCopied': 'Link Copied',

            'status.fact.target': 'Target',
            'status.fact.connection': 'Connection',
            'status.fact.resolve': 'Resolve',
            'status.fact.settings': 'Settings',

            'state.idle.label': 'Idle',
            'state.idle.detail': 'Ready for a new trace.',
            'state.resolving.label': 'Resolving',
            'state.resolving.detail': 'Resolving the target before starting the trace.',
            'state.waiting.label': 'Waiting',
            'state.waiting.detail': 'Trace started. Waiting for the first hop.',
            'state.running.label': 'Running',
            'state.running.detail': 'Streaming hop data in real time.',
            'state.complete.label': 'Complete',
            'state.complete.detail': 'Trace finished. Results are retained until you reset.',
            'state.complete.detailEmpty': 'Trace finished without any hop data.',
            'state.error.label': 'Error',
            'state.error.detail': 'The trace ended with an error. Current results are retained.',
            'state.error.detailEmpty': 'The trace could not be started. Adjust the target or settings.',
            'state.disconnected.label': 'Disconnected',
            'state.disconnected.detail': 'Connection lost. Current results stay on screen.',
            'state.disconnected.detailEmpty': 'Connection lost. Reconnect before starting a new trace.',

            'empty.idle.title': 'Ready for a new trace',
            'empty.idle.description': 'Enter an IP, domain, or URL to start streaming hop data.',
            'empty.resolving.title': 'Resolving target',
            'empty.resolving.description': 'Checking the target and resolving DNS before the trace starts.',
            'empty.waiting.title': 'Waiting for first hop',
            'empty.waiting.description': 'The trace is running. Results will appear here as soon as the first hop arrives.',
            'empty.complete.title': 'Trace finished',
            'empty.complete.description': 'The task completed, but no hop data was captured.',
            'empty.error.title': 'Trace failed',
            'empty.error.description': 'Adjust the target or settings, then try again.',
            'empty.disconnected.title': 'Disconnected',
            'empty.disconnected.description': 'The trace service is unreachable. Reconnect and start again when the session returns.',

            'connection.connecting': 'Connecting',
            'connection.connected': 'Connected',
            'connection.disconnected': 'Disconnected',

            'target.notSet': 'Not set',

            'summary.resolve.local': 'Local Resolve',
            'summary.resolve.server': 'Server Resolve',

            'results.eyebrow': 'trace state',
            'table.eyebrow': 'streaming hop view',
            'table.title': 'Trace Output',
            'table.hint': 'Sticky header, horizontal scroll on narrow screens, raw TTL aggregation unchanged.',

            'table.header.hop': 'HOP',
            'table.header.ip': 'IP',
            'table.header.asn': 'ASN',
            'table.header.location': 'LOCATION',
            'table.header.owner': 'OWNER',
            'table.header.loss': 'LOSS%',
            'table.header.sent': 'SENT',
            'table.header.last': 'LAST',
            'table.header.avg': 'AVG',
            'table.header.best': 'BEST',
            'table.header.worst': 'WORST',
            'table.header.stdev': 'STDEV',
            'table.header.ptr': 'PTR',

            'panel.history.eyebrow': 'history',
            'panel.history.title': 'Recent Queries',
            'panel.history.meta': 'stored locally',
            'panel.history.empty': 'Your recent traces will appear here.',
            'panel.examples.eyebrow': 'quick start',
            'panel.examples.title': 'Example Targets',
            'panel.settings.eyebrow': 'effective configuration',
            'panel.settings.title': 'Current Settings',

            'settings.eyebrow': 'runtime settings',
            'settings.title': 'Trace Settings',
            'settings.close': 'Close settings',
            'settings.language.label': 'Geo Data Language',
            'settings.language.zh': 'Chinese',
            'settings.language.en': 'English',
            'settings.resolve.label': 'Resolve Mode',
            'settings.resolve.hint': 'Prefer local DoH resolve before starting the trace',
            'settings.interval.label': 'Probe Interval Seconds',
            'settings.packetSize.label': 'Packet Size',
            'settings.maxHop.label': 'Max Hop',
            'settings.minHop.label': 'Min Hop',
            'settings.port.label': 'Port',
            'settings.device.label': 'Device',
            'settings.device.placeholder': 'Device',
            'settings.device.error': 'Invalid device name.',
            'settings.dataProvider.label': 'Geo Data Provider',
            'settings.dataProvider.placeholder': 'dataProvider',
            'settings.dataProvider.error': 'Invalid data provider.',
            'settings.save': 'Save Settings',

            'modal.ipSelector.eyebrow': 'resolver result',
            'modal.ipSelector.title': 'Choose a resolved IP',
            'modal.close': 'Close selector',

            'notice.connectionRestored': 'Connection restored. Start a new trace when ready.',
            'notice.connectionLost': 'Connection to the trace service was lost. Current results stay on screen.',
            'notice.selectionCancelled': 'Target selection cancelled.',
            'notice.emptyTarget': 'Enter an IP, domain, or URL before starting a trace.',
            'notice.unresolvable': 'Invalid input or unresolvable domain. Adjust the target or switch resolve mode.',
            'notice.stopped': 'Trace stopped. Current results are retained.',
            'notice.shareCopied': 'Share link copied to clipboard.',
            'notice.shareFailed': 'Copy failed. You can still copy the current URL manually.',

            'error.taskFailed': 'The trace task failed.',

            'serverError.invalid_payload': 'The server rejected one of the trace settings. Review the values in the settings drawer.',
            'serverError.invalid_target': 'The server rejected the target address. Check the IP, domain, or URL you entered.',
            'serverError.start_failed': 'The server could not start nexttrace. Check the server configuration.',
            'serverError.trace_capacity_exceeded': 'The server reached its concurrent trace limit. Try again shortly.',
            'serverError.trace_idle_timeout': 'The trace produced no output for too long and was stopped.',
            'serverError.trace_max_duration_reached': 'The trace reached its maximum run time and was stopped.',
            'serverError.trace_not_running': 'There is no running trace to interact with.',
            'serverError.trace_rate_limited': 'Too many requests. Wait a moment and try again.'
        },
        zh: {
            'app.title': 'NextTrace Web',

            'header.eyebrow': '受 ping.pe 启发的路由追踪界面',
            'header.tagline': '以更紧凑的布局、更清晰的状态反馈和更快的重复查询流程，逐跳流式呈现路由数据。',
            'header.language': '界面语言',
            'language.auto': '跟随系统',

            'form.target.label': '目标',
            'form.target.placeholder': 'IP / 域名 / URL',
            'form.ipVersion.label': 'IP 版本',
            'form.protocol.label': '协议',

            'action.start': '开始',
            'action.stop': '停止',
            'action.reset': '重置',
            'action.settings': '设置',
            'action.share': '复制分享链接',
            'action.shareCopied': '已复制链接',

            'status.fact.target': '目标',
            'status.fact.connection': '连接',
            'status.fact.resolve': '解析',
            'status.fact.settings': '设置',

            'state.idle.label': '空闲',
            'state.idle.detail': '已就绪，可以开始新的追踪。',
            'state.resolving.label': '解析中',
            'state.resolving.detail': '正在解析目标，随后开始追踪。',
            'state.waiting.label': '等待中',
            'state.waiting.detail': '追踪已启动，正在等待第一跳。',
            'state.running.label': '运行中',
            'state.running.detail': '正在实时接收逐跳数据。',
            'state.complete.label': '已完成',
            'state.complete.detail': '追踪已结束，结果会保留至你重置。',
            'state.complete.detailEmpty': '追踪已结束，但没有获得任何跳数据。',
            'state.error.label': '出错',
            'state.error.detail': '追踪因错误结束，当前结果已保留。',
            'state.error.detailEmpty': '追踪未能启动，请调整目标或设置。',
            'state.disconnected.label': '已断开',
            'state.disconnected.detail': '连接已断开，当前结果仍保留在页面上。',
            'state.disconnected.detailEmpty': '连接已断开，请重新连接后再开始追踪。',

            'empty.idle.title': '已就绪，可以开始新的追踪',
            'empty.idle.description': '输入 IP、域名或 URL 即可开始接收逐跳数据。',
            'empty.resolving.title': '正在解析目标',
            'empty.resolving.description': '正在校验目标并解析 DNS，随后开始追踪。',
            'empty.waiting.title': '正在等待第一跳',
            'empty.waiting.description': '追踪正在进行，第一跳到达后结果会显示在这里。',
            'empty.complete.title': '追踪已结束',
            'empty.complete.description': '任务已完成，但没有捕获到任何跳数据。',
            'empty.error.title': '追踪失败',
            'empty.error.description': '请调整目标或设置后重试。',
            'empty.disconnected.title': '连接已断开',
            'empty.disconnected.description': '追踪服务当前不可用，连接恢复后请重新开始。',

            'connection.connecting': '连接中',
            'connection.connected': '已连接',
            'connection.disconnected': '已断开',

            'target.notSet': '未设置',

            'summary.resolve.local': '本地解析',
            'summary.resolve.server': '服务端解析',

            'results.eyebrow': '追踪状态',
            'table.eyebrow': '实时逐跳视图',
            'table.title': '追踪结果',
            'table.hint': '表头吸顶，窄屏可横向滚动，原始 TTL 聚合逻辑保持不变。',

            'table.header.hop': '跳数',
            'table.header.ip': 'IP',
            'table.header.asn': 'ASN',
            'table.header.location': '地理位置',
            'table.header.owner': '归属',
            'table.header.loss': '丢包率',
            'table.header.sent': '发送',
            'table.header.last': '最新',
            'table.header.avg': '平均',
            'table.header.best': '最优',
            'table.header.worst': '最差',
            'table.header.stdev': '标准差',
            'table.header.ptr': 'PTR',

            'panel.history.eyebrow': '历史记录',
            'panel.history.title': '最近查询',
            'panel.history.meta': '保存在本地',
            'panel.history.empty': '最近的追踪记录会显示在这里。',
            'panel.examples.eyebrow': '快速开始',
            'panel.examples.title': '示例目标',
            'panel.settings.eyebrow': '当前生效配置',
            'panel.settings.title': '当前设置',

            'settings.eyebrow': '运行参数',
            'settings.title': '追踪设置',
            'settings.close': '关闭设置',
            'settings.language.label': '地理数据语言',
            'settings.language.zh': '中文',
            'settings.language.en': '英文',
            'settings.resolve.label': '解析模式',
            'settings.resolve.hint': '启动追踪前优先使用本地 DoH 解析',
            'settings.interval.label': '探测间隔（秒）',
            'settings.packetSize.label': '数据包大小',
            'settings.maxHop.label': '最大跳数',
            'settings.minHop.label': '最小跳数',
            'settings.port.label': '端口',
            'settings.device.label': '网络接口',
            'settings.device.placeholder': '网络接口',
            'settings.device.error': '网络接口名称无效。',
            'settings.dataProvider.label': 'IP 数据源',
            'settings.dataProvider.placeholder': 'dataProvider',
            'settings.dataProvider.error': 'IP 数据源无效。',
            'settings.save': '保存设置',

            'modal.ipSelector.eyebrow': '解析结果',
            'modal.ipSelector.title': '请选择一个 IP 地址',
            'modal.close': '关闭选择器',

            'notice.connectionRestored': '连接已恢复，可随时开始新的追踪。',
            'notice.connectionLost': '与追踪服务的连接已断开，当前结果仍保留在页面上。',
            'notice.selectionCancelled': '已取消目标选择。',
            'notice.emptyTarget': '请先输入 IP、域名或 URL，然后再开始追踪。',
            'notice.unresolvable': '输入无效或域名无法解析，请调整目标或切换解析模式。',
            'notice.stopped': '追踪已停止，当前结果已保留。',
            'notice.shareCopied': '分享链接已复制到剪贴板。',
            'notice.shareFailed': '复制失败，你仍可手动复制当前地址。',

            'error.taskFailed': '任务执行失败。',

            'serverError.invalid_payload': '服务端拒绝了某项追踪设置，请检查设置面板中的取值。',
            'serverError.invalid_target': '服务端拒绝了目标地址，请检查填写的 IP、域名或 URL。',
            'serverError.start_failed': '服务端启动 nexttrace 失败，请检查服务器配置。',
            'serverError.trace_capacity_exceeded': '当前并发任务已达上限，请稍后再试。',
            'serverError.trace_idle_timeout': '任务长时间无输出，已停止。',
            'serverError.trace_max_duration_reached': '任务达到最大运行时长，已停止。',
            'serverError.trace_not_running': '当前没有正在运行的 trace 任务。',
            'serverError.trace_rate_limited': '操作过于频繁，请稍后再试。'
        }
    };

    function normalizeLocale(value) {
        if (typeof value !== 'string') {
            return null;
        }

        var normalized = value.trim().toLowerCase().replace(/_/g, '-');
        if (normalized === '') {
            return null;
        }
        if (normalized === 'cn' || normalized === 'zh' || normalized.indexOf('zh-') === 0) {
            return 'zh';
        }
        if (normalized === 'en' || normalized.indexOf('en-') === 0) {
            return 'en';
        }
        return null;
    }

    function normalizePreference(value) {
        if (typeof value === 'string' && value.trim().toLowerCase() === AUTO_PREFERENCE) {
            return AUTO_PREFERENCE;
        }
        return normalizeLocale(value) || AUTO_PREFERENCE;
    }

    // An explicit 'en'/'zh' preference wins; 'auto' (the default) falls through to
    // the browser language candidates, then to DEFAULT_LOCALE.
    function detectLocale(storedValue, candidates) {
        var storedLocale = normalizeLocale(storedValue);
        if (storedLocale) {
            return storedLocale;
        }

        var candidateList = Array.isArray(candidates) ? candidates : [candidates];
        for (var index = 0; index < candidateList.length; index += 1) {
            var candidateLocale = normalizeLocale(candidateList[index]);
            if (candidateLocale) {
                return candidateLocale;
            }
        }

        return DEFAULT_LOCALE;
    }

    function getDictionary(locale) {
        return DICTIONARIES[normalizeLocale(locale) || DEFAULT_LOCALE];
    }

    function translate(locale, key) {
        if (typeof key !== 'string' || key === '') {
            return '';
        }

        var dictionary = getDictionary(locale);
        if (Object.prototype.hasOwnProperty.call(dictionary, key)) {
            return dictionary[key];
        }

        var fallbackDictionary = DICTIONARIES[DEFAULT_LOCALE];
        if (Object.prototype.hasOwnProperty.call(fallbackDictionary, key)) {
            return fallbackDictionary[key];
        }

        return key;
    }

    function createTranslator(locale) {
        return function (key) {
            return translate(locale, key);
        };
    }

    function getTableHeaderLabels(locale) {
        return TABLE_HEADER_KEYS.map(function (key) {
            return translate(locale, key);
        });
    }

    function getHtmlLang(locale) {
        var resolvedLocale = normalizeLocale(locale) || DEFAULT_LOCALE;
        return LOCALE_HTML_LANG[resolvedLocale];
    }

    function applyDocumentTranslations(documentRef, locale) {
        if (!documentRef || typeof documentRef.querySelectorAll !== 'function') {
            return 0;
        }

        var appliedCount = 0;

        documentRef.querySelectorAll('[data-i18n]').forEach(function (element) {
            element.textContent = translate(locale, element.getAttribute('data-i18n'));
            appliedCount += 1;
        });

        ATTRIBUTE_BINDINGS.forEach(function (binding) {
            documentRef.querySelectorAll('[' + binding.markup + ']').forEach(function (element) {
                element.setAttribute(binding.attribute, translate(locale, element.getAttribute(binding.markup)));
                appliedCount += 1;
            });
        });

        if (documentRef.documentElement && typeof documentRef.documentElement.setAttribute === 'function') {
            documentRef.documentElement.setAttribute('lang', getHtmlLang(locale));
        }

        return appliedCount;
    }

    function listKeys(locale) {
        return Object.keys(getDictionary(locale));
    }

    return {
        AUTO_PREFERENCE: AUTO_PREFERENCE,
        DEFAULT_LOCALE: DEFAULT_LOCALE,
        SUPPORTED_LOCALES: SUPPORTED_LOCALES,
        SUPPORTED_PREFERENCES: SUPPORTED_PREFERENCES,
        TABLE_HEADER_KEYS: TABLE_HEADER_KEYS,
        applyDocumentTranslations: applyDocumentTranslations,
        createTranslator: createTranslator,
        detectLocale: detectLocale,
        getDictionary: getDictionary,
        getHtmlLang: getHtmlLang,
        getTableHeaderLabels: getTableHeaderLabels,
        listKeys: listKeys,
        normalizeLocale: normalizeLocale,
        normalizePreference: normalizePreference,
        translate: translate
    };
});
