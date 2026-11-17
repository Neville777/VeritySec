/**
 * Shared live-events client. One WebSocket carries every real-time update the server
 * sends (tool installs, approval requests). Pages register handlers by topic instead of polling.
 */
const AppEvents = (() => {
    const handlers = {};
    let socket = null;
    let reconnectTimer = null;
    let delay = 1000;

    function on(topic, fn) {
        (handlers[topic] = handlers[topic] || []).push(fn);
    }

    function dispatch(ev) {
        const list = handlers[ev.topic] || [];
        list.forEach(fn => {
            try { fn(ev.data || {}); } catch (e) { console.error('event handler failed', ev.topic, e); }
        });
    }

    function connect() {
        if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) return;
        if (typeof authToken === 'undefined' || !authToken) return;
        const proto = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
        const s = new WebSocket(`${proto}${window.location.host}/api/events/ws?token=${encodeURIComponent(authToken)}`);
        socket = s;
        s.onopen = () => { delay = 1000; };
        s.onmessage = (msg) => {
            let ev;
            try { ev = JSON.parse(msg.data); } catch (e) { return; }
            dispatch(ev);
        };
        s.onclose = () => {
            socket = null;
            if (!authToken) return; // logged out: stop reconnecting
            clearTimeout(reconnectTimer);
            reconnectTimer = setTimeout(connect, delay);
            delay = Math.min(delay * 2, 30000);
        };
    }

    return { on, connect };
})();

// Approval requests: refresh the approvals list if it is open, and always tell the user.
AppEvents.on('hitl.pending', () => {
    if (typeof refreshHitlPending === 'function') refreshHitlPending();
    if (typeof showNotification === 'function') showNotification('A tool call is waiting for your approval.', 'info');
});
