"""Task ownership and process lifetime are independent of HTTP connections."""
import json
import logging
import os
import subprocess
import threading
import time
import uuid
from nexttrace_mtr import build_mtr_json_command, build_process_env
from .mtr import Aggregator
from .config import PayloadError
from .limits import Limits

TERMINAL = {'completed', 'cancelled', 'failed'}


class Task:
    def __init__(self, owner, params, config):
        self.id = uuid.uuid4().hex
        self.owner = owner
        self.params = params
        self.client = None
        self.probe_rate = 0
        self.config = config
        self.condition = threading.Condition(threading.RLock())
        self.state = 'starting'
        self.seq = 1
        self.aggregate = Aggregator(text_limit=512 if config.get('NTWA_PUBLIC_MODE') else None)
        self.error = None
        self.process = None
        self.created_at = self.last_output_at = self.lease_at = time.monotonic()
        self.finished_at = None
        self.done = threading.Event()
        self.stopping = threading.Event()
        self.stderr = ''

    def snapshot(self):
        with self.condition:
            error = self.error
            if self.config.get('NTWA_PUBLIC_MODE') and error and error.get('code') == 'nexttrace_error':
                error = dict(code='nexttrace_error', message='探测失败')
            return dict(task_id=self.id, target=self.params[0], seq=self.seq, state=self.state, rows=self.aggregate.snapshot(), path_end=self.aggregate.path_end, error=error)

    def change(self, state=None, error=None):
        with self.condition:
            if self.state in TERMINAL:
                return
            if state:
                self.state = state
            if error:
                self.error = error
            if self.state in TERMINAL:
                self.finished_at = time.monotonic()
                self.done.set()
            self.seq += 1
            self.condition.notify_all()

    def start(self):
        threading.Thread(target=self.run, daemon=True).start()
        threading.Thread(target=self.watch, daemon=True).start()

    def request_stop(self, error=None, lease_before=None):
        with self.condition:
            if self.state in TERMINAL or self.stopping.is_set():
                return None
            if lease_before is not None and self.lease_at >= lease_before:
                return None
            self.stopping.set()
            self.change('stopping', error)
            process = self.process
            if process is None:
                self.change('failed' if error else 'cancelled')
        if process is not None:
            try:
                process.terminate()
            except OSError:
                pass
        return process

    def stop(self, error=None, lease_before=None):
        process = self.request_stop(error, lease_before)
        if process is not None:
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            except OSError:
                pass

    def watch(self):
        while not self.done.wait(1):
            now = time.monotonic()
            if now - self.lease_at > 30:
                self.stop(lease_before=now - 30)
                if self.stopping.is_set() or self.done.is_set():
                    return
                continue
            maximum = self.config['NTWA_TRACE_MAX_DURATION_SECONDS']
            idle = self.config['NTWA_TRACE_IDLE_TIMEOUT_SECONDS']
            if maximum and now - self.created_at > maximum:
                self.stop(dict(code='trace_max_duration_reached', message='任务达到最大运行时长'))
                return
            if idle and now - self.last_output_at > idle:
                self.stop(dict(code='trace_idle_timeout', message='任务长时间无输出'))
                return

    def consume_stderr(self, process):
        try:
            for line in iter(lambda: process.stderr.readline(4097), ''):
                if line.strip():
                    self.stderr = line.strip()[-2000:]
        except (OSError, ValueError):
            pass

    def run(self):
        end = None
        last_seq = 0
        started = False
        failure = None
        process = None
        try:
            with self.condition:
                if self.stopping.is_set():
                    self.change('cancelled')
                    return
                process = self.process = subprocess.Popen(build_mtr_json_command(self.config['NTWA_NEXTTRACE_PATH'], self.params, self.config.get('NTWA_NEXTTRACE_FLAVOR', 'nexttrace')), stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, text=True, bufsize=1, env=build_process_env(os.environ, public=self.config.get('NTWA_PUBLIC_MODE', False)))
            stderr_thread = threading.Thread(target=self.consume_stderr, args=(process,), daemon=True)
            stderr_thread.start()
            for line in iter(lambda: process.stdout.readline(65537), ''):
                if len(line) > 65536:
                    raise ValueError('MTR JSON event exceeds size limit')
                if not line.strip():
                    continue
                self.last_output_at = time.monotonic()
                event = json.loads(line)
                seq = event.get('seq')
                if event.get('schema_version') != 1 or not isinstance(seq, int) or seq != last_seq + 1 or end is not None:
                    raise ValueError('Unsupported or invalid MTR JSON stream')
                last_seq = seq
                kind = event.get('type')
                with self.condition:
                    if kind == 'start' and not started and seq == 1:
                        started = True
                        self.change('stopping' if self.stopping.is_set() else 'running')
                    elif not started:
                        raise ValueError('Missing MTR start event')
                    elif kind == 'probe':
                        if self.config.get('NTWA_PUBLIC_MODE'):
                            ttl = event['record'].get('ttl')
                            first = int(self.params[self.params.index('--first') + 1])
                            maximum = int(self.params[self.params.index('--max-hops') + 1])
                            if not isinstance(ttl, int) or not first <= ttl <= maximum:
                                raise ValueError('MTR probe TTL exceeds configured range')
                        self.aggregate.ingest(event['record'])
                        self.change()
                    elif kind == 'path_end':
                        conclusion = event['path_end']
                        if self.config.get('NTWA_PUBLIC_MODE') and conclusion is not None:
                            hop = conclusion.get('hop')
                            if not isinstance(hop, int) or not 1 <= hop <= 255:
                                raise ValueError('Invalid MTR path conclusion')
                            conclusion = dict(reason=str(conclusion.get('reason', ''))[:64], hop=hop)
                        self.aggregate.path(conclusion)
                        self.change()
                    elif kind == 'end':
                        end = event
                    else:
                        raise ValueError('Unknown MTR event')
            code = process.wait(timeout=2)
            stderr_thread.join(timeout=2)
            if not self.stopping.is_set() and (end is None or end.get('end_reason') != 'completed' or code != 0):
                failure = (end or {}).get('error') or dict(message=self.stderr or 'NextTrace MTR JSON stream ended unexpectedly')
        except Exception as exc:
            logging.debug('Trace task %s failed', self.id, exc_info=True)
            failure = dict(message=str(exc))
        finally:
            if process is not None:
                try:
                    if process.poll() is None:
                        try:
                            process.terminate()
                            process.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()
                except OSError as exc:
                    failure = failure or dict(message=str(exc))
                finally:
                    for pipe in (process.stdout, process.stderr):
                        if pipe:
                            try:
                                pipe.close()
                            except (OSError, ValueError) as exc:
                                failure = failure or dict(message=str(exc))
            with self.condition:
                if self.error:
                    self.change('failed')
                elif self.stopping.is_set():
                    self.change('cancelled')
                elif failure:
                    details = failure if isinstance(failure, dict) else dict(message=str(failure)[:2000])
                    self.change('failed', dict(details, code='nexttrace_error'))
                else:
                    self.change('completed')
            if self.config.get('NTWA_PUBLIC_MODE'):
                logging.info('public_trace_finished state=%s reaped=%s', self.state, process is None or process.poll() is not None)


class Registry:
    def __init__(self, config, public=None):
        self.config = config
        self.public = public
        self.limits = Limits()
        self.lock = threading.RLock()
        self.tasks = {}
        self.requests = {}
        self.last_start = {}
        self.closed = False

    def prune(self):
        now = time.monotonic()
        expired = set()
        for key, task in list(self.tasks.items()):
            if task.finished_at is not None and now - task.finished_at > 300:
                expired.add(key)
        if self.public:
            # A count cap complements TTL retention; never evict active tasks.
            terminal = sorted((task for task in self.tasks.values() if task.finished_at is not None and task.id not in expired), key=lambda task: task.finished_at)
            expired.update(task.id for task in terminal[:-256])
        for key in expired:
            del self.tasks[key]
        self.requests = {key: task for key, task in self.requests.items() if task.id in self.tasks}
        self.last_start = {owner: at for owner, at in self.last_start.items() if now - at < 300}

    def create(self, owner, request_id, params, client=None):
        with self.lock:
            if self.closed:
                raise PayloadError('start_failed', '服务正在停止')
            self.prune()
            key = (owner, request_id)
            if key in self.requests:
                task = self.requests[key]
                if task.params != params:
                    raise PayloadError('invalid_payload', 'request_id 已用于其他参数')
                return task
            now = time.monotonic()
            remaining = self.config['NTWA_MIN_START_INTERVAL_SECONDS'] - (now - self.last_start.get(owner, float('-inf')))
            if remaining > 0:
                raise PayloadError('trace_rate_limited', '操作过于频繁', remaining)
            active = [task for task in self.tasks.values() if task.state not in TERMINAL]
            if len(active) >= self.config['NTWA_MAX_ACTIVE_TRACES']:
                raise PayloadError('trace_capacity_exceeded', '当前任务已满', 1)
            rate = self.public.admit(self, owner, client, params, active) if self.public else 0
            task = Task(owner, params, self.config)
            task.client = client
            task.probe_rate = rate
            self.tasks[task.id] = self.requests[key] = task
            self.last_start[owner] = now
            try:
                task.start()
            except RuntimeError:
                pass
            else:
                return task
        # Startup can fail after the runner has already spawned a process.
        # Cancel outside the registry lock so other task controls remain available.
        task.stop(dict(code='start_failed', message='无法启动任务线程'))
        task.done.wait(2)
        raise PayloadError('start_failed', '无法启动任务线程')

    def get(self, owner, task_id):
        with self.lock:
            self.prune()
            task = self.tasks.get(task_id)
            return task if task and task.owner == owner else None

    def shutdown(self):
        with self.lock:
            if self.closed:
                return
            self.closed = True
            tasks = [task for task in self.tasks.values() if task.state not in TERMINAL]
        # Signal all children before waiting: total grace is shared, not per task.
        processes = []
        for task in tasks:
            process = task.request_stop()
            if process is None:
                process = task.process
            if process is not None:
                processes.append(process)
        deadline = time.monotonic() + 2
        for process in processes:
            try:
                process.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                try:
                    process.kill()
                except OSError:
                    pass
            except OSError:
                pass
        for process in processes:
            try:
                process.wait(timeout=2)
            except (subprocess.TimeoutExpired, OSError):
                logging.error('Could not reap NextTrace child during shutdown')
