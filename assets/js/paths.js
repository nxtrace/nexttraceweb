(function (root, factory) {
    var api = factory();
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = api;
    }
    if (root) {
        root.nextTracePaths = api;
    }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    function resolveBasePath(pathname) {
        if (typeof pathname !== 'string' || pathname === '') {
            return '/';
        }

        var boundary = pathname.search(/[?#]/);
        var directoryPath = boundary === -1 ? pathname : pathname.slice(0, boundary);

        if (directoryPath.charAt(0) !== '/') {
            directoryPath = '/' + directoryPath;
        }

        return directoryPath.replace(/[^/]*$/, '');
    }

    function joinBasePath(pathname, relativePath) {
        var suffix = typeof relativePath === 'string' ? relativePath.replace(/^\/+/, '') : '';
        return resolveBasePath(pathname) + suffix;
    }

    return {
        joinBasePath: joinBasePath,
        resolveBasePath: resolveBasePath
    };
});
