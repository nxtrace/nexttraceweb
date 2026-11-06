import { joinBasePath } from './transport-paths.js';

export async function request(path, body, signal) {
    const response = await fetch(joinBasePath(location.pathname, path), {
        method: body === undefined ? 'GET' : 'POST',
        headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
        cache: 'no-store', signal
    });
    const value = await response.json();
    if (!response.ok) throw Object.assign(new Error(value.message || value.code), value, {status: response.status});
    return value;
}

export class TraceClient {
    constructor(onSnapshot, onConnection) {
        this.onSnapshot = onSnapshot;
        this.onConnection = onConnection;
        this.id = null;
        this.seq = -1;
        this.stream = null;
        this.lease = null;
        this.generation = 0;
    }
    async submitCreation(payload) {
        try { return await request('api/traces', payload); }
        catch (error) { if (error.status) throw error; return request('api/traces', payload); }
    }
    async create(ip, extra) {
        let payload = { ip, extra, request_id: crypto.randomUUID ? crypto.randomUUID() : Array.from(crypto.getRandomValues(new Uint8Array(16)), x => x.toString(16).padStart(2, '0')).join('') };
        const previous = sessionStorage.getItem('ntwaPendingTrace');
        if (previous && Date.now() - Number(sessionStorage.getItem('ntwaPendingTraceAt')) < 300000) {
            const saved = JSON.parse(previous);
            if (saved.ip === ip && JSON.stringify(saved.extra) === JSON.stringify(extra)) payload = saved;
        }
        const pending = JSON.stringify(payload);
        sessionStorage.setItem('ntwaPendingTrace', pending);
        if (previous !== pending) sessionStorage.setItem('ntwaPendingTraceAt', String(Date.now()));
        try {
            const snapshot = await this.submitCreation(payload);
            if (sessionStorage.getItem('ntwaPendingTrace') === pending) {
                sessionStorage.setItem('ntwaTaskId', snapshot.task_id);
                this.clearPending(pending);
            }
            return snapshot;
        } catch (error) {
            if (error.status) this.clearPending(pending);
            throw error;
        }
    }
    clearPending(pending) {
        if (sessionStorage.getItem('ntwaPendingTrace') === pending) {
            sessionStorage.removeItem('ntwaPendingTrace');
            sessionStorage.removeItem('ntwaPendingTraceAt');
        }
    }
    accept(snapshot) {
        if (snapshot.task_id !== this.id || snapshot.seq <= this.seq) return;
        this.seq = snapshot.seq;
        this.lastSnapshot = snapshot;
        this.onSnapshot(snapshot);
        if (['completed', 'cancelled', 'failed'].includes(snapshot.state)) this.detach();
    }
    attach(snapshot) {
        this.detach();
        this.id = snapshot.task_id;
        this.seq = -1;
        sessionStorage.setItem('ntwaTaskId', this.id);
        this.accept(snapshot);
        if (['completed', 'cancelled', 'failed'].includes(snapshot.state)) return;
        const id = this.id;
        const generation = this.generation;
        const current = () => this.generation === generation && this.id === id;
        let renewing = false;
        const renew = async () => {
            if (renewing || !current()) return;
            renewing = true;
            try {
                const value = await request('api/traces/' + id + '/lease', {});
                if (!current()) return;
                this.onConnection(true);
                this.accept(value);
            } catch (error) {
                if (!current()) return;
                if (error.status === 404) {
                    this.onConnection(true);
                    this.accept({...this.lastSnapshot, seq:this.seq + 1, state:'failed', error:{code:'trace_not_running'}});
                    if (sessionStorage.getItem('ntwaTaskId') === id) sessionStorage.removeItem('ntwaTaskId');
                    this.id = null;
                } else this.onConnection(false);
            } finally { renewing = false; }
        };
        this.lease = setInterval(renew, 10000);
        this.stream = new EventSource(joinBasePath(location.pathname, 'api/traces/' + id + '/events'));
        this.stream.addEventListener('snapshot', event => { if (current()) this.accept(JSON.parse(event.data)); });
        this.stream.onopen = () => { if (current()) this.onConnection(true); };
        this.stream.onerror = () => { if (current()) this.onConnection(false); };
        renew();
    }
    async resume() {
        const pending = sessionStorage.getItem('ntwaPendingTrace');
        const id = sessionStorage.getItem('ntwaTaskId');
        if (pending && Date.now() - Number(sessionStorage.getItem('ntwaPendingTraceAt')) >= 300000) {
            this.clearPending(pending);
            return true;
        }
        if (!id && !pending) return false;
        this.detach();
        const generation = this.generation;
        const current = () => this.generation === generation && (pending
            ? sessionStorage.getItem('ntwaPendingTrace') === pending
            : sessionStorage.getItem('ntwaTaskId') === id);
        try {
            const snapshot = pending ? await this.submitCreation(JSON.parse(pending)) : await request('api/traces/' + id);
            // The original create may have completed during this retry and
            // already replaced its pending record with the accepted task ID.
            if (!current() && !(pending && this.generation === generation && sessionStorage.getItem('ntwaTaskId') === snapshot.task_id)) return false;
            this.attach(snapshot);
            if (pending) this.clearPending(pending);
            return true;
        } catch (error) {
            if (!current()) return false;
            if (pending && error.status) this.clearPending(pending);
            else if (error.status === 404) sessionStorage.removeItem('ntwaTaskId');
            throw error;
        }
    }
    async stop(id = this.id) {
        if (!id) return;
        const generation = this.generation;
        let snapshot = await request('api/traces/' + id + '/stop', {});
        const deadline = Date.now() + 8000;
        while (!['completed', 'cancelled', 'failed'].includes(snapshot.state)) {
            if (Date.now() > deadline) throw new Error('Task is still stopping');
            await new Promise(resolve => setTimeout(resolve, 100));
            snapshot = await request('api/traces/' + id);
        }
        if (generation === this.generation && id === this.id) this.accept(snapshot);
        return snapshot;
    }
    detach() {
        this.generation++;
        this.stream?.close();
        this.stream = null;
        clearInterval(this.lease);
        this.lease = null;
    }
}
