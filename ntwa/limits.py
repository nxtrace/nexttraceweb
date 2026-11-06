"""Bounded, process-local admission limits for the single-worker service."""
import threading
import time
from .config import PayloadError


class Limits:
    def __init__(self):
        self.lock = threading.RLock()
        self.buckets = {}
        self.connections = {}
        self.pruned_at = 0

    def rates(self, specs):
        """Atomically consume (key, tokens/second, burst) budgets."""
        with self.lock:
            now = time.monotonic()
            if now - self.pruned_at >= 5:
                self.buckets = {key: value for key, value in self.buckets.items() if now - value[1] < 300}
                self.pruned_at = now
            updates = {}
            for key, rate, burst in specs:
                tokens, at = self.buckets.get(key, (burst, now))
                available = min(burst, tokens + max(0, now - at) * rate)
                if available < 1:
                    raise PayloadError('trace_rate_limited', '操作过于频繁', (1 - available) / rate)
                updates[key] = (available - 1, now)
            if len(self.buckets.keys() | updates.keys()) > 4096:
                raise PayloadError('trace_capacity_exceeded', '服务繁忙', 10)
            self.buckets.update(updates)

    def acquire(self, specs):
        """Reserve concurrent slots; return an idempotent release callback."""
        with self.lock:
            if any(self.connections.get(key, 0) >= maximum for key, maximum in specs):
                raise PayloadError('trace_capacity_exceeded', '连接已满', 2)
            for key, _ in specs:
                self.connections[key] = self.connections.get(key, 0) + 1
        released = False

        def release():
            nonlocal released
            with self.lock:
                if released:
                    return
                released = True
                for key, _ in specs:
                    remaining = self.connections[key] - 1
                    if remaining:
                        self.connections[key] = remaining
                    else:
                        del self.connections[key]
        return release
