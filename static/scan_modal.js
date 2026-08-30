/* Scan progress modal + SSE client.
   Shared by the Home scanner form and the per-subdomain scan buttons.
   Exposes window.startScan(target) — any button can trigger a scan. */
(function () {
    let es = null;

    function el(id) { return document.getElementById(id); }

    function setLines(html) {
        const l = el('scan-modal-lines');
        if (l) l.innerHTML = html;
    }
    function addLogLine(text, color) {
        const logEl = el('scan-modal-log');
        if (!logEl) return;
        const div = document.createElement('div');
        div.innerHTML = '<span class="text-cyan-500">$</span> ' + (color ? '<span style="color:' + color + '">' : '') + String(text || '').replace(/</g, '&lt;') + (color ? '</span>' : '');
        logEl.appendChild(div);
        logEl.scrollTop = logEl.scrollHeight;
    }
    function addStage(line) {
        const linesEl = el('scan-modal-lines');
        if (!linesEl) return;
        const placeholder = linesEl.querySelector('.text-slate-400');
        if (placeholder) setLines('');
        const isDone = /(OK|not\w*e|trouv|termine|constat|CVE\(s\)|CVE\(s\) found|\/100|scored|complete)/i.test(line);
        const div = document.createElement('div');
        div.className = 'p-2 bg-slate-950/60 border border-slate-800/80 rounded flex items-center gap-2';
        if (isDone) {
            div.innerHTML = '<i class="fa-solid fa-circle-check text-emerald-400"></i><span class="text-emerald-300">' + String(line || '').replace(/</g, '&lt;') + '</span>';
        } else {
            div.innerHTML = '<i class="fa-solid fa-rotate text-cyan-400 animate-spin"></i><span class="text-slate-200">' + String(line || '').replace(/</g, '&lt;') + '</span>';
        }
        linesEl.appendChild(div);
        linesEl.scrollTop = linesEl.scrollHeight;
    }
    function showModal() {
        const m = el('scan-modal');
        if (!m) return;
        m.classList.remove('hidden');
        m.classList.add('flex');
        document.body.style.overflow = 'hidden';
    }
    function setBadge(state) {
        const badge = el('modal-badge');
        if (!badge) return;
        if (state === 'done') {
            badge.className = 'flex items-center gap-2 text-[10px] font-mono font-bold uppercase tracking-widest text-emerald-400 border border-emerald-500/30 bg-emerald-950/30 rounded px-2 py-1';
            badge.innerHTML = '<i class="fa-solid fa-circle-check"></i> Complete';
        } else if (state === 'error') {
            badge.className = 'flex items-center gap-2 text-[10px] font-mono font-bold uppercase tracking-widest text-red-400 border border-red-500/30 bg-red-950/30 rounded px-2 py-1';
            badge.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i> Failed';
        }
    }
    function showError(msg) {
        // Replace the spinning "Starting/scanning" stages with a clear
        // terminal failure state so the modal never looks stuck.
        const linesEl = el('scan-modal-lines');
        if (linesEl) {
            linesEl.innerHTML = '<div class="p-2 bg-red-950/40 border border-red-800/50 rounded flex items-center gap-2"><i class="fa-solid fa-triangle-exclamation text-red-400"></i><span class="text-red-300">' + String(msg).replace(/</g, '&lt;') + '</span></div>';
        }
        setBadge('error');
        addLogLine('ERROR: ' + msg, '#f87171');
    }
    function closeScanModal() {
        if (es) { es.close(); es = null; }
        const m = el('scan-modal');
        if (m) { m.classList.add('hidden'); m.classList.remove('flex'); }
        document.body.style.overflow = '';
    }

    function startScan(target) {
        if (!target) return;
        const targetEl = el('modal-target');
        const logEl = el('scan-modal-log');
        const badge = el('modal-badge');

        if (targetEl) targetEl.textContent = target;
        setLines('<div class="p-2 bg-slate-950/60 border border-slate-800/80 rounded flex items-center gap-2 text-slate-400"><i class="fa-solid fa-rotate text-cyan-400 animate-spin"></i><span>Starting scan...</span></div>');
        if (logEl) logEl.innerHTML = '<div class="text-slate-600"># Opening intelligence pipeline for ' + target + '...</div>';
        if (badge) {
            badge.className = 'flex items-center gap-2 text-[10px] font-mono font-bold uppercase tracking-widest text-amber-400 border border-amber-500/30 bg-amber-950/30 rounded px-2 py-1';
            badge.innerHTML = '<i class="fa-solid fa-circle text-[8px] animate-pulse"></i> Analyzing';
        }
        showModal();

        const fd = new FormData();
        fd.append('target', target);

        fetch('/scan', {
            method: 'POST',
            body: fd,
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        })
        .then(function (resp) { return resp.json().catch(function () { return {}; }); })
        .then(function (data) {
            if (!data.job_id) throw new Error(data.error || 'Scan could not be started.');
            es = new EventSource('/scan/progress/' + data.job_id + '/stream');
            es.onopen = function () { addLogLine('Connected to intelligence pipeline.'); };
            es.onmessage = function (event) {
                try {
                    const msg = JSON.parse(event.data);
                    addStage(msg.line);
                    addLogLine(msg.line);
                } catch (err) { /* ignore malformed frames */ }
            };
            es.addEventListener('done', function (event) {
                const done = JSON.parse(event.data);
                if (es) { es.close(); es = null; }
                setBadge('done');
                addLogLine('Analysis complete. Loading report...', '#34d399');
                setTimeout(function () { window.location.href = done.url; }, 700);
            });
            es.addEventListener('error', function (event) {
                if (es) { es.close(); es = null; }
                let msg = 'The scan pipeline encountered an unexpected error.';
                if (event.data) {
                    try { msg = JSON.parse(event.data).error || msg; } catch (e) {}
                }
                showError(msg);
            });
        })
        .catch(function (err) {
            showError(err && err.message ? err.message : 'Request failed.');
        });
    }

    document.addEventListener('DOMContentLoaded', function () {
        const form = document.getElementById('scan-form');
        if (form) {
            form.addEventListener('submit', function (e) {
                e.preventDefault();
                const input = document.getElementById('scan-target');
                if (!input) return;
                startScan(input.value.trim());
            });
        }
    });

    window.startScan = startScan;
    window.closeScanModal = closeScanModal;
})();