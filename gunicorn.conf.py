control_socket_disable = True


def _registry(worker):
    app = worker.wsgi
    return getattr(app, 'extensions', {}).get('traces') if app is not None else None


def post_worker_init(worker):
    import signal
    import gevent

    previous = signal.getsignal(signal.SIGTERM)

    def terminate(signum, frame):
        # SSE requests cannot drain until their tasks end. Schedule cleanup
        # before Gunicorn starts waiting for those requests, outside signal context.
        registry = _registry(worker)
        if registry is not None:
            gevent.spawn(registry.shutdown)
        previous(signum, frame)

    signal.signal(signal.SIGTERM, terminate)


def worker_exit(server, worker):
    # Also cover normal exits that did not receive SIGTERM.
    registry = _registry(worker)
    if registry is not None:
        registry.shutdown()
