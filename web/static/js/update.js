// "One-click update" on the console: this page operates on the same installation tree that is currently answering requests.
// Three hard rules, each one a pitfall this repo has already hit once:
//   1) If a check can't be performed, say so. When checkError is set, the page writes out the reason and never renders "already up to date" —
//      painting "check failed" as "no update" means the operator only finds out the tree hasn't moved at the next failure.
//   2) Only report real HTTP results, and only through showNotification, which the platform actually provides; if it's absent, do nothing.
//   3) Every server-supplied string going into HTML goes through escapeHtml; everything going into attributes goes through escapeAttr.
const UPDATE_POLL_INTERVAL_MS = 1500;
// Restart watchdog: the gap between the old process exiting and the new process taking requests; the cadence of page probes and the patience before giving up.
const UPDATE_WATCHDOG_INTERVAL_MS = 2000;
const UPDATE_WATCHDOG_TIMEOUT_MS = 90000;

// withUpdateBusy picks the error-copy prefix per action; all keys must exist in all three languages.
const UPDATE_FAILURE_KEYS = {
    check: 'checkFailed',
    apply: 'applyFailed',
    rollback: 'rollbackFailed',
    load: 'loadFailed',
    source: 'sourceSaveFailed',
    adopt: 'adoptFailed',
    restart: 'restartFailed',
};

let updateConsoleState = null;   // Whole payload of GET /api/system/update: {status, job, canRestart, supervised, needsRestart}
let updateCheck = { done: false, error: '' };
let updateBusy = false;          // Action requests the page itself has in flight (check / start update / rollback / restart)
let updateChecking = false;      // Only affects the wording of the "Check for updates" button
let updatePollTimer = null;
let updateRestartChoice = true;  // The checkbox must remain checked after poll redraws; the default follows supervised
let updateRestartChoiceSet = false; // Once the operator has changed it manually this session, the default no longer overrides their choice
let updateRestartPending = false;   // Restart requested: process exit / new process taking requests is imminent
let updateWatchdogTimer = null;     // The restart watchdog's own timer, independent of the task-progress polling
let updateWatchdogDeadline = 0;
let updateWatchdogSlow = null;      // null = not yet timed out; 'running' = still answered by the old process; 'down' = service did not come back
let updateAutoCheckDone = false; // Only auto-check the remote once per session, so every redraw doesn't bother the operator
let updateSourceDraft = null;    // Repo address of the update source being edited; null = still showing the value saved on the server
let updateSourceError = '';      // Reason for the most recent save/adopt failure, shown in the section
let updateActionError = '';      // Reason for the most recent action (check / update / rollback / restart) failure, shown at the top of the console
let updateAdoptPlan = null;      // Adoption plan returned by preview; cleared after confirmation

function updateT(key, opts) {
    const k = 'update.' + key;
    if (typeof window.t !== 'function') return k;
    // i18next by default also turns / " ' inside interpolations into HTML entities; the console's results either go through escapeHtml (render)
    // or into confirm (plain text), and neither destination needs that pre-escaping — leaving it on would display / in dates and branch names
    // as &#x2F; (verified: devtree/deploy/... displays exactly that way in the confirm dialog).
    const merged = Object.assign({ interpolation: { escapeValue: false } }, opts || {});
    return window.t(k, merged);
}

function updateSourceOf() {
    return (updateConsoleState && updateConsoleState.source) || { repo: '', configured: false, defaultRepo: '' };
}

// Draft takes priority: poll redraws must not overwrite an address being typed; after a successful save the draft is discarded and the server value is used.
function updateSourceRepo() {
    if (typeof updateSourceDraft === 'string') return updateSourceDraft;
    return updateSourceOf().repo || '';
}

function updateSourceRepoChanged(value) {
    updateSourceDraft = String(value == null ? '' : value);
}

// scheduleUpdateAutoCheck answers the question the page exists to answer, without making
// somebody press a button to find out whether the button would do anything.
//
// The constraints are what keep it polite: one check per session, only for a tree that is
// actually a git installation, never while a job is already running, and always after the
// first paint - the page's own claim has to reach the screen before the network does. A
// failure is not retried here: the page says so plainly, and the operator presses Check for updates
// when they want to ask again.
function scheduleUpdateAutoCheck() {
    if (updateAutoCheckDone) return false;
    const status = updateConsoleState && updateConsoleState.status;
    if (!status || !status.installed || isUpdateJobRunning()) return false;
    updateAutoCheckDone = true;
    setTimeout(() => {
        if (!isUpdateConsoleActive()) return;
        checkForUpdates();
    }, 1200);
    return true;
}

function isUpdateConsoleActive() {
    // The console lives in the "One-click update" section of the system settings page: the page being active is not enough; the section must also be the selected one.
    const page = document.getElementById('page-settings');
    const section = document.getElementById('settings-section-update');
    return !!(page && page.classList.contains('active') &&
        section && section.classList.contains('active'));
}

function updateStatusOf() {
    return (updateConsoleState && updateConsoleState.status) || {};
}

function updateJobOf() {
    const job = updateConsoleState && updateConsoleState.job;
    return job && typeof job === 'object' ? job : null;
}

function updateCanRestart() {
    return !!(updateConsoleState && updateConsoleState.canRestart);
}

function isUpdateJobRunning() {
    const job = updateJobOf();
    return !!(job && job.state === 'running');
}

function resetUpdateCheck() {
    // A single GET cannot return behind/updateAvailable (it does not reach the network), so keeping the previous done=true
    // would paint "not checked" as "already up to date".
    updateCheck = { done: false, error: '' };
}

// ---------------------------------------------------------------------------
// Request layer
// ---------------------------------------------------------------------------

// Every call must receive both the status code and the parsed body: the 409 from apply/rollback carries the job currently running,
// throwing it away would discard "a run is already in progress, here is its progress".
// ok is not the same as the status code: in the half-finished case where "source code reverted but the binary did not", rollback answers with 202 and carries an
// error field (statusForError in the handler maps no_toolchain to 202); trusting only resp.ok would report a half-done rollback as a success.
// would report a half-finished rollback as success.
async function runUpdateRequest(method, url, body) {
    const resp = await apiFetch(url, {
        method: method,
        headers: { 'Content-Type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
    });
    const data = await resp.json().catch(() => ({}));
    const refused = !!(data && typeof data.error === 'string' && data.error);
    return {
        ok: !!resp.ok && !refused,
        status: resp.status,
        data: data || {},
        error: refused ? data.error : ('HTTP ' + resp.status),
    };
}

async function fetchUpdateStatus() {
    const r = await runUpdateRequest('GET', '/api/system/update');
    if (!r.ok) throw new Error(r.error);
    updateConsoleState = {
        status: r.data.status || {},
        job: r.data.job || null,
        canRestart: !!r.data.canRestart,
        supervised: !!r.data.supervised,
        needsRestart: !!r.data.needsRestart,
        binaryBuiltAt: r.data.binaryBuiltAt || '',
        source: r.data.source || { repo: '', configured: false, defaultRepo: '' },
    };
    noteRestartDefault();
    return updateConsoleState;
}

// Default for the checkbox: check it by default only if there is a supervisor (the startup marker of launchd/systemd) — with no supervisor, checking it by default
// would be "one click stops the service". Once the operator changes the checkbox themselves, the server value no longer overrides their choice.
function noteRestartDefault() {
    if (updateRestartChoiceSet) return;
    updateRestartChoice = !!(updateConsoleState && updateConsoleState.supervised);
}

// notify acts only when the platform really loaded showNotification. It must never become the reason an operation "looks failed":
// the request has already succeeded; calling a function that doesn't exist on the page just to announce it would turn success into failure.
function notify(message, type) {
    if (typeof showNotification === 'function') {
        try {
            showNotification(message, type);
        } catch (e) {
            console.warn('notify', e);
        }
    }
}

// Redraws during an action must be symmetric at start and end. While busy, draw "occupied" (buttons get disabled); when idle, draw it back —
// this page's check flow (including the automatic check after opening the page) redraws during the busy period; if it doesn't redraw at the end,
// that disabled state stays in the DOM and permanently freezes the button: measured, after the page-open auto-check once, the "Save update source" button
// kept disabled + data-state-disabled, so clicking it again never responded and no request could even be sent.
// The banner is now state (updateActionError) rendered by renderUpdateConsole, so leaving a redraw won't wipe it; when the restart watchdog takes over the screen
// (updateRestartPending), never redraw, so the self-recovery view isn't painted over with the console again.
async function withUpdateBusy(fn, label) {
    if (updateBusy) return;
    updateBusy = true;
    updateActionError = '';
    if (!updateRestartPending) renderUpdateConsole();
    try {
        await fn();
    } catch (err) {
        const reason = err && err.message ? err.message : String(err);
        // If the request blows up midway, the screen is still showing a state like "Checking update source…" that no longer holds;
        // a red line alone is not enough: the banner redraws with the state, and the screen itself is also redrawn to match the current state.
        updateActionError = updateT(UPDATE_FAILURE_KEYS[label] || 'loadFailed', { reason: reason });
        if (!updateRestartPending) renderUpdateConsole();
        // The inline banner is wiped by the redraw that starts the next action; the toast is the copy that persists.
        notify(updateActionError, 'error');
    } finally {
        updateBusy = false;
        if (!updateRestartPending) renderUpdateConsole();
    }
}

// ---------------------------------------------------------------------------
// Entry point and polling
// ---------------------------------------------------------------------------

async function loadUpdateConsole() {
    stopUpdatePolling();
    // Restart already initiated: the console yields to the self-recovery view and no longer reads a service that is exiting.
    if (updateRestartPending) {
        startUpdateWatchdog();
        return;
    }
    resetUpdateCheck();
    updateRestartChoiceSet = false;
    updateRestartChoice = true; // Afterwards noteRestartDefault corrects it according to supervised
    updateActionError = '';     // Re-entering the page = a clean screen; the red text from the last action doesn't carry over
    const el = document.getElementById('update-console');
    if (!el) return;
    el.innerHTML = '<div class="empty-state">' + escapeHtml(updateT('loading')) + '</div>';
    try {
        await fetchUpdateStatus();
    } catch (err) {
        el.innerHTML = '<div class="empty-state">' +
            escapeHtml(updateT(UPDATE_FAILURE_KEYS.load, { reason: err.message })) + '</div>';
        return;
    }
    renderUpdateConsole();
    // An update is already running when the page opens (e.g. started from another tab): keep watching it so people don't think nothing is happening.
    if (isUpdateJobRunning()) startUpdatePolling();
    scheduleUpdateAutoCheck();
}

// Only one timer: not clearing it before re-arming is how "two polling loops writing to the same log after the page is opened twice" happens.
function startUpdatePolling() {
    stopUpdatePolling();
    updatePollTimer = setInterval(pollUpdateJob, UPDATE_POLL_INTERVAL_MS);
}

function stopUpdatePolling() {
    if (updatePollTimer) clearInterval(updatePollTimer);
    updatePollTimer = null;
}

// ---------------------------------------------------------------------------
// Restart watchdog: after a restart is requested, watch whether the new process has taken requests; once it has, refresh the whole page
// ---------------------------------------------------------------------------

// Only accept one fact: a new process has answered. The session only lives in the old process's memory; the new process would only return 401 for the old token.
// 200 means we're still talking to the old process (it hasn't exited yet); connection refused / 502 means it's exiting or not yet started — keep waiting in both cases.
// Leaving the console stops the timer silently: don't drag a user who has already moved on back to the update page from another page.
let updateWatchdogProbing = false;

async function watchdogProbe() {
    if (!isUpdateConsoleActive()) {
        stopUpdateWatchdog();
        return;
    }
    if (updateWatchdogProbing) return;
    updateWatchdogProbing = true;
    let status = 0;
    try {
        const resp = await fetch((typeof getApiBase==='function'?getApiBase():'') + '/api/system/update', {
            method: 'GET',
            credentials: 'same-origin',
            cache: 'no-store',
            headers: { Accept: 'application/json' },
        });
        status = resp.status;
    } catch (err) {
        status = 0;
    } finally {
        updateWatchdogProbing = false;
    }
    if (status === 401) {
        // The new process has taken requests and doesn't recognize our session: a full-page refresh lands on the new version, returning to this page with the hash.
        // Stop the timer first: the page is about to be replaced entirely, so the timer should not trigger a second action.
        stopUpdateWatchdog();
        location.replace(location.pathname + '?restarted=' + Date.now() + '#system-update');
        return;
    }
    if (updateWatchdogSlow === null && Date.now() > updateWatchdogDeadline) {
        updateWatchdogSlow = status === 200 ? 'running' : 'down';
        renderUpdateWatchdog();
    }
}

function startUpdateWatchdog() {
    if (updateWatchdogTimer) return;
    updateRestartPending = true;
    updateWatchdogSlow = null;
    updateWatchdogDeadline = Date.now() + UPDATE_WATCHDOG_TIMEOUT_MS;
    renderUpdateWatchdog();
    updateWatchdogTimer = setInterval(watchdogProbe, UPDATE_WATCHDOG_INTERVAL_MS);
}

function stopUpdateWatchdog() {
    if (updateWatchdogTimer) clearInterval(updateWatchdogTimer);
    updateWatchdogTimer = null;
}

async function pollUpdateJob() {
    if (!isUpdateConsoleActive()) {
        // The page has already switched away. router.js only calls initPage on entry and nobody calls out on exit,
        // so stop here and don't leave a stray timer behind.
        stopUpdatePolling();
        return;
    }
    // Transport-layer death (connection refused, process already exited) is a reject, not a response carrying a status code: both are normalized here —
    // during a restart it simply means "the process exited"; otherwise it is a read failure to report.
    let r;
    try {
        r = await runUpdateRequest('GET', '/api/system/update/job');
    } catch (err) {
        r = { ok: false, error: err && err.message ? err.message : String(err) };
    }
    if (!r.ok) {
        stopUpdatePolling();
        if (updateRestartPending) {
            // The process exited as requested: this is not "failed to read progress", it's the restart moving to the next act.
            startUpdateWatchdog();
            return;
        }
        notify(updateT('jobPollFailed', { reason: r.error }), 'error');
        return;
    }
    const job = r.data && r.data.job ? r.data.job : null;
    if (updateConsoleState) updateConsoleState.job = job;
    renderUpdateConsole();
    if (job && job.state !== 'running') {
        stopUpdatePolling();
        if (job.state === 'succeeded' && job.restartRequested) {
            // The process is about to hand over to the new binary: report the conclusion first, then enter the self-recovery view; don't go back
            // to read a service that's about to disappear (reportFinishedJob would read it, so skip it here).
            notify(updateDoneToast(job.result || null), 'success');
            startUpdateWatchdog();
            return;
        }
        updateRestartPending = false;
        reportFinishedJob(job);
    }
}

// The completion message here only quotes the conclusion the server wrote, but a build-completion and a normal update are different completions: commits=0 with a swapped binary
// reading "a1b2c3d → a1b2c3d" says nothing; it has to say "build completed".
function updateDoneToast(result) {
    if (result && result.binaryBuilt && result.fromCommit && result.fromCommit === result.toCommit) {
        return updateT('buildDoneToast');
    }
    const tail = result && result.toCommit ? ' ' + result.fromCommit + ' → ' + result.toCommit : '';
    return updateT('jobDoneToast') + tail;
}

// The announcement only quotes what the server wrote: on success it quotes the two commit IDs in result, on failure it quotes failure.message;
// the page itself does not compose an "update complete" message here.
function reportFinishedJob(job) {
    const result = job.result || null;
    if (job.state === 'succeeded') {
        notify(updateDoneToast(result), 'success');
        if (result && result.needsRestart) notify(updateT('needsRestartToast'), 'info');
    } else {
        const reason = (job.failure && job.failure.message) ? job.failure.message : updateT('failureNoMessage');
        notify(updateT('jobFailedToast') + ': ' + reason, 'error');
    }
    resetUpdateCheck();
    // The binary was swapped, so the local state must be re-read; if it can't be read, say so plainly.
    fetchUpdateStatus().then(renderUpdateConsole).catch(err => {
        notify(updateT(UPDATE_FAILURE_KEYS.load, { reason: err.message }), 'error');
    });
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

async function checkForUpdates() {
    await withUpdateBusy(async () => {
        updateChecking = true;
        renderUpdateConsole();
        let r;
        try {
            r = await runUpdateRequest('POST', '/api/system/update/check');
        } finally {
            // Even if the request itself blows up (401, network down), "Checking" must be cleared, otherwise the button stays grayed out forever.
            updateChecking = false;
        }
        if (!r.ok) {
            // An HTTP-layer failure is also "cannot check", and must not leave a page that looks like "no update available".
            updateCheck = { done: false, error: r.error };
            renderUpdateConsole();
            notify(updateT(UPDATE_FAILURE_KEYS.check, { reason: r.error }), 'error');
            return;
        }
        const status = r.data.status || {};
        if (updateConsoleState) updateConsoleState.status = status;
        updateCheck = { done: true, error: status.checkError || '' };
        renderUpdateConsole();
        if (updateCheck.error) {
            notify(updateT(UPDATE_FAILURE_KEYS.check, { reason: updateCheck.error }), 'error');
        } else if (status.updateAvailable) {
            notify(updateT('behindCount', { n: updateBehindCount(status) }), 'info');
        } else {
            notify(updateT('upToDate', { commit: status.commit || '-' }), 'success');
        }
    }, 'check');
}

function updateBehindCount(status) {
    const listed = (status.incoming || []).length;
    const total = status.incomingTotal || status.behind || 0;
    return total > 0 ? total : listed;
}

// Explain why a button can't be clicked; "grayed out" is not an explanation.
function updateApplyBlockers(status, job) {
    const blockers = [];
    if (status.rollbackPending) blockers.push(updateT('rollbackPendingHint'));
    if (!status.installed) blockers.push(updateT('blockedNotGitTree'));
    if (job && job.state === 'running') blockers.push(updateT('blockedJobRunning'));
    if ((status.blockingChanges || []).length) {
        blockers.push(updateT('blockedLocalEdits', { n: status.blockingChanges.length }));
    }
    if (status.diverged) {
        blockers.push(updateT('blockedDiverged', {
            ahead: status.ahead || 0,
            behind: status.behind || 0,
        }));
    }
    if (!status.updateAvailable && !status.buildPending) blockers.push(updateT('blockedNoUpdate'));
    return blockers;
}

function updateRestartChoiceChanged(checked) {
    updateRestartChoice = !!checked;
    updateRestartChoiceSet = true; // Once the operator has decided it themselves, the server default no longer overrides them
    renderUpdateConsole();
}

// The checkbox is the only source of truth; the copy in the module is just memory for poll redraws.
function updateRestartRequested() {
    const box = document.getElementById('update-restart-choice');
    if (box && typeof box.checked === 'boolean') return box.checked;
    return updateRestartChoice;
}

function updateConfirmText(status, restart) {
    // Build-completion and "update N commits" are two different things: a confirm dialog saying "0 new commits" would make people think the click was wasted.
    const base = (!status.updateAvailable && status.buildPending)
        ? updateT('confirmBuildPending', { commit: status.commit || '-' })
        : updateT('confirmApply', {
            repo: status.repo || '-',
            target: status.remoteCommit || '-',
            commit: status.commit || '-',
            n: updateBehindCount(status),
        });
    return base + ' ' + (restart ? updateT('confirmRestartYes') : updateT('confirmRestartNo'));
}

async function startUpdateApply() {
    if (updateBusy) return;
    const status = updateStatusOf();
    const blockers = updateApplyBlockers(status, updateJobOf());
    if (blockers.length) {
        // The browser does not deliver clicks on disabled buttons to this point; reaching here means the state no longer matches the screen,
        // so say plainly why it can't be clicked; silence would look like it's broken.
        notify(blockers[0], 'error');
        return;
    }
    const restart = updateRestartRequested();
    if (!window.confirm(updateConfirmText(status, restart))) return;

    await withUpdateBusy(async () => {
        const r = await runUpdateRequest('POST', '/api/system/update/apply', { restart: restart });
        if (r.status === 409 && r.data.job) {
            // Another update really is running: take over its progress and keep watching it — that is the "current state".
            if (updateConsoleState) updateConsoleState.job = r.data.job;
            renderUpdateConsole();
            startUpdatePolling();
        }
        if (!r.ok) throw new Error(r.error);
        resetUpdateCheck();
        if (restart) updateRestartPending = true;
        startUpdatePolling();
        notify(updateT('applyAccepted', { id: r.data.job_id || '-' }), 'success');
        await pollUpdateJob();
    }, 'apply');
}

// "Restart service now": turns the binary that has already been swapped on disk into the one answering requests. The server only allows this
// when there is actually a pending version to apply — if there is nothing to apply, pressing stop-service isn't a restart.
async function startRestartNow() {
    if (updateBusy) return;
    if (!window.confirm(updateT('restartNowConfirm'))) return;

    await withUpdateBusy(async () => {
        const r = await runUpdateRequest('POST', '/api/system/update/restart');
        if (!r.ok) throw new Error(r.error);
        stopUpdatePolling();
        notify(updateT('restartRequestedToast'), 'info');
        startUpdateWatchdog();
    }, 'restart');
}

async function rollbackUpdate() {
    if (updateBusy) return;
    const status = updateStatusOf();
    if (!status.hasRollback) return;
    if (isUpdateJobRunning()) {
        notify(updateT('blockedJobRunning'), 'error');
        return;
    }
    if (!window.confirm(updateT('confirmRollback', { commit: status.rollbackTo || '-' }))) return;

    await withUpdateBusy(async () => {
        const r = await runUpdateRequest('POST', '/api/system/update/rollback');
        if (!r.ok) {
            // The server gives even "which files were not rolled back"; don't just report a single failure line.
            const items = r.data && r.data.items && r.data.items.length
                ? ' · ' + updateT('rollbackItems') + ': ' + r.data.items.join(', ')
                : '';
            throw new Error(r.error + items);
        }
        const to = (r.data.result && r.data.result.toCommit) || status.rollbackTo || '-';
        resetUpdateCheck();
        updateRestartChoice = false;
        await fetchUpdateStatus();
        renderUpdateConsole();
        notify(updateT('rollbackDone', { commit: to }), 'success');
    }, 'rollback');
}

// Update source: the server handles validation and writing (single repo field in the update section of config.yaml); this layer only moves data and explains.
// Submitting empty = back to the official repo, the same state as "never configured".
async function saveUpdateSource() {
    if (updateBusy) return;
    const body = {
        repo: updateSourceRepo().trim(),
    };
    updateSourceError = '';
    await withUpdateBusy(async () => {
        const r = await runUpdateRequest('POST', '/api/system/update/source', body);
        if (!r.ok) {
            // The server's rejection copy (address invalid…) is the sentence to show; don't compose a new one here.
            updateSourceError = updateT('sourceSaveFailed', { reason: r.error });
            renderUpdateConsole();
            notify(updateSourceError, 'error');
            return;
        }
        updateSourceDraft = null;
        if (updateConsoleState) updateConsoleState.source = r.data.source || updateConsoleState.source;
        resetUpdateCheck();
        await fetchUpdateStatus();
        renderUpdateConsole();
        notify(updateT('sourceSaveOk'), 'success');
    }, 'source');
}

// Preview has no side effects (the server fetches in a temporary repo), so you can click it first and review the list before deciding.
async function previewAdoptSource() {
    if (updateBusy) return;
    updateSourceError = '';
    await withUpdateBusy(async () => {
        const r = await runUpdateRequest('POST', '/api/system/update/adopt', { confirm: false });
        if (!r.ok) {
            updateSourceError = updateT('adoptFailed', { reason: r.error });
            renderUpdateConsole();
            notify(updateSourceError, 'error');
            return;
        }
        updateAdoptPlan = r.data.plan || null;
        renderUpdateConsole();
    }, 'adopt');
}

async function confirmAdoptSource() {
    if (updateBusy || !updateAdoptPlan) return;
    const restart = updateRestartRequested();
    const text = updateT('adoptConfirmText', {
        incoming: updateAdoptPlan.incoming,
        overwritten: updateAdoptPlan.overwrittenTotal,
        protectedFiles: updateAdoptPlan.protectedTotal,
    });
    if (!window.confirm(text)) return;

    await withUpdateBusy(async () => {
        const r = await runUpdateRequest('POST', '/api/system/update/adopt', { confirm: true, restart: restart });
        if (!r.ok) throw new Error(r.error);
        updateAdoptPlan = null;
        resetUpdateCheck();
        if (restart) updateRestartPending = true;
        startUpdatePolling();
        notify(updateT('adoptAccepted', { id: r.data.job_id || '-' }), 'success');
        await pollUpdateJob();
    }, 'adopt');
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

function updateSection(title, body) {
    return '<section class="update-section"><h3 class="update-section-title">' +
        escapeHtml(title) + '</h3>' + body + '</section>';
}

// The value goes both into text and into title (long paths need title to see in full), so the attribute copy must go through escapeAttr.
function updateFact(label, value) {
    const text = value == null || value === '' ? '-' : String(value);
    return '<div class="update-fact"><span>' + escapeHtml(label) + '</span>' +
        '<code title="' + escapeAttr(text) + '">' + escapeHtml(text) + '</code></div>';
}

function updateMark(ok, yesKey, noKey, reason) {
    const cls = ok ? 'update-chip update-chip-ok' : 'update-chip update-chip-warn';
    if (!reason) {
        return '<span class="' + cls + '">' + escapeHtml(ok ? updateT(yesKey) : updateT(noKey)) + '</span>';
    }
    return '<span class="' + cls + '" title="' + escapeAttr(String(reason)) + '">' +
        escapeHtml(ok ? updateT(yesKey) : updateT(noKey)) + '</span>';
}

function renderUpdateSourceBody(status) {
    const src = updateSourceOf();
    const defaultRepo = src.defaultRepo || '';
    const parts = [];
    parts.push('<div class="update-hint">' + escapeHtml(src.configured ? updateT('sourceFromConfig') : updateT('sourceIsDefault', { repo: defaultRepo })) + '</div>');
    if (status.repo) {
        parts.push('<div class="update-facts">' + updateFact(updateT('sourceUrl'), status.repo) + '</div>');
    }
    // Manually typed errors are the page's own state; redraws (polling) must not wipe them.
    const disabled = updateBusy ? ' disabled data-state-disabled="true"' : '';
    parts.push('<div class="update-source-form">' +
        '<label>' + escapeHtml(updateT('sourceUrlLabel')) +
        '<input type="text" class="update-source-input update-source-url" value="' + escapeAttr(updateSourceRepo()) +
        '" placeholder="' + escapeAttr(defaultRepo) + '" oninput="updateSourceRepoChanged(this.value)"></label>' +
        '<div class="update-hint">' + escapeHtml(updateT('sourceRepoHint', { repo: defaultRepo })) + '</div>' +
        '<div class="update-actions"><button class="btn-secondary update-source-save-btn"' + disabled +
        ' data-require-permission="update:apply" onclick="saveUpdateSource()">' +
        escapeHtml(updateT('sourceSaveBtn')) + '</button></div></div>');
    if (updateSourceError) {
        parts.push('<div class="update-error">' + escapeHtml(updateSourceError) + '</div>');
    }
    if (!status.installed) {
        parts.push(renderAdoptBody());
    }
    return parts.join('');
}

function renderAdoptBody() {
    const parts = [];
    parts.push('<div class="update-hint">' + escapeHtml(updateT('adoptHint')) + '</div>');
    const disabled = updateBusy ? ' disabled data-state-disabled="true"' : '';
    if (!updateAdoptPlan) {
        parts.push('<div class="update-actions"><button class="btn-primary update-adopt-preview-btn"' + disabled +
            ' data-require-permission="update:apply" onclick="previewAdoptSource()">' +
            escapeHtml(updateT('adoptPreviewBtn')) + '</button></div>');
        return parts.join('');
    }
    const plan = updateAdoptPlan;
    parts.push('<div class="update-facts">' +
        updateFact(updateT('adoptIncoming'), plan.incoming) +
        updateFact(updateT('adoptOverwrittenTotal'), plan.overwrittenTotal) +
        updateFact(updateT('adoptProtectedTotal'), plan.protectedTotal) +
        updateFact(updateT('sourceBranch'), plan.branch) +
        updateFact(updateT('adoptCommit'), plan.commit) + '</div>');
    const list = (items, title) => items && items.length
        ? '<h4 class="update-sub-title">' + escapeHtml(title) + '</h4><ul class="update-commit-list">' +
          items.map(p => '<li><code title="' + escapeAttr(String(p)) + '">' + escapeHtml(String(p)) + '</code></li>').join('') + '</ul>'
        : '';
    parts.push(list(plan.overwritten, updateT('adoptOverwrittenTitle')));
    parts.push(list(plan.protected, updateT('adoptProtectedTitle')));
    parts.push('<div class="update-hint">' + escapeHtml(updateT('adoptBackupNote')) + '</div>');
    parts.push(renderUpdateRestartChoice());
    parts.push('<div class="update-actions"><button class="btn-primary update-adopt-confirm-btn"' + disabled +
        ' data-require-permission="update:apply" onclick="confirmAdoptSource()">' +
        escapeHtml(updateT('adoptConfirmBtn')) + '</button></div>');
    return parts.join('');
}

function renderUpdateInstallBody(status) {
    const facts = [
        updateFact(updateT('root'), status.root),
        updateFact(updateT('branch'), status.branch),
        updateFact(updateT('commit'), status.commit),
        updateFact(updateT('committedAt'), status.committedAt),
        updateFact(updateT('subject'), status.subject),
    ].join('');
    const marks = [
        updateMark(!!status.installed, 'gitTree', 'notGitTree'),
        updateMark(!!status.canBuild, 'toolchainFound', 'toolchainMissing',
            status.canBuild ? (status.goToolchain || '') : (status.goToolchain || updateT('toolchainMissingHint'))),
        updateMark(!!status.hasBinary, 'binaryPresent', 'binaryMissing'),
        updateMark(!!status.hasRollback, 'rollbackPresent', 'rollbackMissing'),
    ];
    if (updateConsoleState && updateConsoleState.needsRestart) {
        marks.push('<span class="update-chip update-chip-warn">' + escapeHtml(updateT('restartNeeded')) + '</span>');
    }
    return '<div class="update-facts">' + facts + '</div><div class="update-marks">' + marks.join('') + '</div>';
}

function renderUpdateRemoteBody(status) {
    const failure = updateCheck.error || status.checkError || '';
    const parts = [];
    if (failure) {
        // This branch is where "don't lie" lands: if there is a reason, write only the reason and don't mention "already up to date".
        parts.push('<div class="update-error update-check-failed">' +
            escapeHtml(updateT('checkFailed', { reason: failure })) + '</div>');
    } else if (!updateCheck.done) {
        parts.push('<div class="update-hint">' + escapeHtml(updateT('notChecked')) + '</div>');
    } else if (status.updateAvailable) {
        parts.push('<div class="update-behind">' +
            escapeHtml(updateT('behindCount', { n: updateBehindCount(status) })) + '</div>');
    } else {
        parts.push('<div class="update-ok">' +
            escapeHtml(updateT('upToDate', { commit: status.commit || '-' })) + '</div>');
    }

    if (status.ahead > 0) {
        parts.push('<div class="update-warn">' + escapeHtml(updateT('aheadCount', { n: status.ahead })) + '</div>');
    }
    if (status.targetBranch || status.remoteCommit) {
        parts.push('<div class="update-facts">' +
            updateFact(updateT('sourceBranch'), status.targetBranch) +
            updateFact(updateT('remoteHead'), status.remoteCommit) +
            updateFact(updateT('remoteSubject'), status.remoteSubject) + '</div>');
    }

    const incoming = status.incoming || [];
    if (incoming.length) {
        // incoming is a truncated list; incomingTotal is the real count, so both must be stated.
        const total = status.incomingTotal || incoming.length;
        parts.push('<h4 class="update-sub-title">' + escapeHtml(updateT('incomingTitle')) + '</h4>');
        if (total > incoming.length) {
            parts.push('<div class="update-hint">' +
                escapeHtml(updateT('incomingTruncated', { total: total, shown: incoming.length })) + '</div>');
        }
        parts.push('<ul class="update-commit-list">' + incoming.map(c =>
            '<li><code title="' + escapeAttr(String(c.commit || '-')) + '">' + escapeHtml(String(c.commit || '-')) +
            '</code> <span class="update-commit-subject">' + escapeHtml(String(c.subject || '')) + '</span></li>'
        ).join('') + '</ul>');
    }
    return parts.join('');
}

function renderUpdateChangesTable(list) {
    // Row background color is the division of whether this file would be overwritten by an update: local content green, product source code red.
    const rows = (list || []).map(c => '<tr class="' + (c.protected ? 'update-row-kept' : 'update-row-blocking') + '">' +
        '<td><code title="' + escapeAttr(String(c.path || '')) + '">' + escapeHtml(String(c.path || '-')) + '</code></td>' +
        '<td>' + escapeHtml(String(c.status || '-')) + '</td>' +
        '<td>' + escapeHtml(c.protected ? updateT('keptFile') : updateT('productSource')) + '</td></tr>').join('');
    return '<table class="update-table"><thead><tr>' +
        '<th>' + escapeHtml(updateT('colPath')) + '</th>' +
        '<th>' + escapeHtml(updateT('colChangeStatus')) + '</th>' +
        '<th>' + escapeHtml(updateT('colOwner')) + '</th>' +
        '</tr></thead><tbody>' + rows + '</tbody></table>';
}

function renderUpdateRestartChoice() {
    if (!updateCanRestart()) {
        // The backend provides no restart hook, so the checkbox should not appear: checking an option that won't be honored is deceptive.
        return '<div class="update-hint">' + escapeHtml(updateT('restartNotWired')) + '</div>';
    }
    const preview = updateRestartChoice ? updateT('confirmRestartYes') : updateT('confirmRestartNo');
    return '<label class="update-restart-choice">' +
        '<input type="checkbox" id="update-restart-choice"' +
        (updateRestartChoice ? ' checked' : '') +
        ' onchange="updateRestartChoiceChanged(this.checked)">' +
        '<span>' + escapeHtml(updateT('restartChoiceLabel')) + '</span></label>' +
        '<div class="update-hint update-restart-preview">' + escapeHtml(preview) + '</div>';
}

function renderUpdateApplyBody(status, job) {
    const blockers = updateApplyBlockers(status, job);
    const blocked = blockers.length > 0;
    const parts = [];

    if (job && job.state === 'running') {
        parts.push('<div class="update-warn">' + escapeHtml(updateT('jobRunningHint')) + '</div>');
    }
    if (!status.canBuild && status.installed) {
        parts.push('<div class="update-warn">' + escapeHtml(updateT('noToolchainWarn')) + '</div>');
    }
    // The source is already at the tip of the update source and only needs one build: this is not "no update available"; the button must remain clickable, and
    // it must clearly say that clicking it will rebuild — otherwise the "click update again" sentence in no_toolchain has no place to land on the page.
    if (status.rollbackPending) {
        parts.push('<div class="update-warn">' + escapeHtml(updateT('rollbackPendingHint')) + '</div>');
    }
    if (status.buildPending && status.installed) {
        parts.push('<div class="update-warn">' + escapeHtml(updateT('buildPendingHint')) + '</div>');
    }

    // Both halves matter: `disabled` for the browser, `data-state-disabled` so the platform's
    // permission gate (which writes el.disabled for every [data-require-permission] element)
    // does not re-enable the button for a user who holds update:apply. In a real browser that
    // write produced an enabled One-click update directly under "53 product source files have local changes".
    const stateDisabled = blocked ? ' disabled data-state-disabled="true"' : '';
    const checkingDisabled = updateChecking ? ' disabled data-state-disabled="true"' : '';
    parts.push('<div class="update-actions">' +
        '<button class="btn-primary update-apply-btn"' + stateDisabled +
        ' data-require-permission="update:apply" onclick="startUpdateApply()">' +
        escapeHtml(updateT('applyBtn')) + '</button>' +
        '<button class="btn-secondary update-check-btn"' + checkingDisabled +
        ' data-require-permission="update:apply" onclick="checkForUpdates()">' +
        escapeHtml(updateChecking ? updateT('checking') : updateT('checkBtn')) + '</button>' +
        '</div>');

    parts.push(renderUpdateRestartChoice());

    if (blocked) {
        parts.push('<ul class="update-blocker-list">' + blockers.map(b =>
            '<li class="update-error">' + escapeHtml(b) + '</li>').join('') + '</ul>');
    }

    const local = status.localChanges || [];
    const blocking = status.blockingChanges || [];
    // localChanges is usually a superset of blockingChanges, but if the two ever disagree, files that block the update must never be omitted because of that
    // — the "N files have local changes" sentence above names exactly those files the person must deal with.
    const seenPaths = Object.create(null);
    const listed = local.concat(blocking).filter(c => {
        const p = String((c && c.path) || '');
        if (!p || seenPaths[p]) return false;
        seenPaths[p] = true;
        return true;
    });
    if (listed.length) {
        parts.push('<h4 class="update-sub-title">' + escapeHtml(updateT('localChangesTitle')) + '</h4>');
        parts.push('<div class="update-hint">' + escapeHtml(updateT('localChangesHint')) + '</div>');
        parts.push(renderUpdateChangesTable(listed));
    } else {
        parts.push('<div class="update-hint">' + escapeHtml(updateT('noLocalChanges')) + '</div>');
    }
    return parts.join('');
}

function updateStateChip(state) {
    const known = { running: 'update-chip-running', succeeded: 'update-chip-ok', failed: 'update-chip-danger' };
    const cls = known[state] || 'update-chip';
    const label = state === 'running' ? updateT('stateRunning')
        : state === 'succeeded' ? updateT('stateSucceeded')
            : state === 'failed' ? updateT('stateFailed') : updateT('stateUnknown');
    return '<span class="' + cls + '">' + escapeHtml(label) + '</span>';
}

function renderUpdateStep(step) {
    return '<li class="update-step">' +
        '<code class="update-step-phase">' + escapeHtml(String(step.phase || '-')) + '</code>' +
        '<span class="update-step-message">' + escapeHtml(String(step.message || '')) + '</span>' +
        '<span class="update-step-at">' + escapeHtml(String(step.at || '')) + '</span></li>';
}

function renderUpdateResult(result) {
    if (!result) return '';
    const kept = result.keptContent || [];
    const facts = [
        updateFact(updateT('resultFrom'), result.fromCommit),
        updateFact(updateT('resultTo'), result.toCommit),
        updateFact(updateT('resultCommits'), result.commits),
        updateFact(updateT('resultFiles'), result.filesTouched),
        updateFact(updateT('resultDuration'), result.duration),
        updateFact(updateT('resultBackup'), result.backupDir),
    ].join('');
    const marks = [
        updateMark(!!result.binaryBuilt, 'binarySwapped', 'binaryNotSwapped', result.binaryPath || ''),
        updateMark(!!result.needsRestart, 'restartNeeded', 'restartNotNeeded'),
    ].join('');
    const keptList = kept.length
        ? '<ul class="update-kept-list">' + kept.map(p =>
            '<li><code title="' + escapeAttr(String(p)) + '">' + escapeHtml(String(p)) + '</code></li>').join('') + '</ul>'
        : '<div class="update-hint">' + escapeHtml(updateT('nothingKept')) + '</div>';
    const replaced = result.overwritten || [];
    const replacedList = replaced.length
        ? '<h4 class="update-sub-title">' + escapeHtml(updateT('resultOverwrittenTitle')) + '</h4>' +
          '<ul class="update-kept-list">' + replaced.map(p =>
              '<li><code title="' + escapeAttr(String(p)) + '">' + escapeHtml(String(p)) + '</code></li>').join('') + '</ul>'
        : '';
    const adoptedNote = result.adopted
        ? '<div class="update-hint">' + escapeHtml(updateT('adoptedNoPreviousCommit')) + '</div>'
        : '';
    return '<div class="update-result">' +
        '<h4 class="update-sub-title">' + escapeHtml(updateT('resultTitle')) + '</h4>' +
        '<div class="update-facts">' + facts + '</div><div class="update-marks">' + marks + '</div>' +
        adoptedNote + replacedList +
        '<h4 class="update-sub-title">' + escapeHtml(updateT('keptTitle')) + '</h4>' + keptList +
        '</div>';
}

function renderUpdateFailure(failure) {
    if (!failure) return '';
    const items = failure.items || [];
    const reason = failure.reason ? '（' + escapeHtml(String(failure.reason)) + '）' : '';
    return '<div class="update-error update-failure">' +
        '<div class="update-failure-title">' + escapeHtml(updateT('failureTitle')) + reason + '</div>' +
        '<div class="update-failure-message">' +
        escapeHtml(String(failure.message || updateT('failureNoMessage'))) + '</div>' +
        (items.length
            ? '<ul class="update-item-list">' + items.map(i =>
                '<li><code title="' + escapeAttr(String(i)) + '">' + escapeHtml(String(i)) + '</code></li>').join('') + '</ul>'
            : '') +
        '</div>';
}

function renderUpdateJobBody(job) {
    if (!job) return '<div class="empty-state">' + escapeHtml(updateT('noJob')) + '</div>';
    const parts = ['<div class="update-job-head">' + updateStateChip(job.state) +
        '<code title="' + escapeAttr(String(job.id || '-')) + '">' + escapeHtml(String(job.id || '-')) + '</code>' +
        (job.started ? '<span class="update-job-time">' + escapeHtml(String(job.started)) + '</span>' : '') +
        (job.restartRequested ? '<span class="update-chip">' + escapeHtml(updateT('restartRequested')) + '</span>' : '') +
        '</div>'];
    const steps = job.steps || [];
    parts.push(steps.length
        ? '<ol class="update-step-list">' + steps.map(renderUpdateStep).join('') + '</ol>'
        : '<div class="empty-state">' + escapeHtml(updateT('noSteps')) + '</div>');
    if (job.state === 'running') {
        parts.push('<div class="update-hint">' +
            escapeHtml(updateT('pollingHint', { sec: UPDATE_POLL_INTERVAL_MS / 1000 })) + '</div>');
    }
    if (job.result) parts.push(renderUpdateResult(job.result));
    if (job.failure) parts.push(renderUpdateFailure(job.failure));
    return parts.join('');
}

function renderUpdateRollbackBody(status) {
    if (!status.hasRollback) {
        return '<div class="empty-state">' + escapeHtml(updateT('noRollback')) + '</div>';
    }
    const running = isUpdateJobRunning();
    return '<p class="update-hint">' +
        escapeHtml(updateT('rollbackTarget', { commit: status.rollbackTo || '-' })) + '</p>' +
        '<div class="update-actions"><button class="btn-secondary update-rollback-btn"' +
        (running ? ' disabled data-state-disabled="true"' : '') + ' data-require-permission="update:apply" ' +
        'onclick="rollbackUpdate()">' + escapeHtml(updateT('rollbackBtn')) + '</button></div>';
}

// Pending-apply banner: the binary on disk is no longer this process's (an update/rollback ran but no restart happened, or the CLI swapped it); here
// is an exit for "make it take effect now" — otherwise, after forgetting to tick once, only the command-line route remains.
function formatBinaryBuiltAt() {
    const raw = (updateConsoleState && updateConsoleState.binaryBuiltAt) || '';
    if (!raw) return '-';
    const d = new Date(raw);
    return isNaN(d.getTime()) ? raw : d.toLocaleString();
}

function renderRestartBanner() {
    const status = updateStatusOf();
    const commit = status.commit || '';
    const text = updateT(commit ? 'restartBanner' : 'restartBannerNoCommit', {
        commit: commit || '-',
        builtAt: formatBinaryBuiltAt(),
    });
    return '<div class="update-restart-banner">' +
        '<div class="update-restart-banner-text">' + escapeHtml(text) + '</div>' +
        '<button class="btn-primary update-restart-btn" data-require-permission="update:apply" onclick="startRestartNow()">' +
        escapeHtml(updateT('restartNowBtn')) + '</button></div>';
}

// Self-recovery view: after a restart request is sent, the console draws this until the new process answers and triggers a full-page refresh.
function renderUpdateWatchdog() {
    const el = document.getElementById('update-console');
    if (!el) return;
    const parts = ['<div class="update-overlay">',
        '<div class="update-overlay-spinner" aria-hidden="true"></div>',
        '<div class="update-overlay-title">' + escapeHtml(updateT('restartOverlayTitle')) + '</div>',
        '<div class="update-overlay-body">' + escapeHtml(updateT('restartOverlayBody')) + '</div>'];
    if (updateWatchdogSlow) {
        parts.push('<div class="update-overlay-slow">' + escapeHtml(updateT(
            updateWatchdogSlow === 'running' ? 'restartOverlaySlowRunning' : 'restartOverlaySlowDown')) + '</div>');
    }
    parts.push('<div class="update-overlay-actions">' +
        '<button class="btn-secondary" type="button" onclick="refreshUpdatePage()">' +
        escapeHtml(updateT('restartOverlayRefresh')) + '</button></div>');
    parts.push('</div>');
    el.innerHTML = parts.join('');
}

function refreshUpdatePage() {
    location.reload();
}

function renderUpdateConsole() {
    const el = document.getElementById('update-console');
    if (!el || !updateConsoleState) return;
    const status = updateStatusOf();
    const job = updateJobOf();

    const parts = [];
    // Red text for a failed action is state, not a one-time injection: redraws (polling, the one that exits the busy state) must not wipe it.
    if (updateActionError) {
        parts.push('<div class="update-error">' + escapeHtml(updateActionError) + '</div>');
    }
    if (updateConsoleState.needsRestart) parts.push(renderRestartBanner());
    parts.push(updateSection(updateT('installTitle'), renderUpdateInstallBody(status)));
    parts.push(updateSection(updateT('sourceTitle'), renderUpdateSourceBody(status)));
    parts.push(updateSection(updateT('remoteTitle'), renderUpdateRemoteBody(status)));
    parts.push(updateSection(updateT('applyTitle'), renderUpdateApplyBody(status, job)));
    parts.push(updateSection(updateT('jobTitle'), renderUpdateJobBody(job)));
    parts.push(updateSection(updateT('rollbackTitle'), renderUpdateRollbackBody(status)));

    el.innerHTML = parts.join('');
    if (typeof window.applyRBACToUI === 'function') {
        window.applyRBACToUI(el);
    }
}

window.loadUpdateConsole = loadUpdateConsole;
window.checkForUpdates = checkForUpdates;
window.startUpdateApply = startUpdateApply;
window.startRestartNow = startRestartNow;
window.refreshUpdatePage = refreshUpdatePage;
window.rollbackUpdate = rollbackUpdate;
window.updateRestartChoiceChanged = updateRestartChoiceChanged;
window.stopUpdatePolling = stopUpdatePolling;
window.renderUpdateConsole = renderUpdateConsole;
window.saveUpdateSource = saveUpdateSource;
window.previewAdoptSource = previewAdoptSource;
window.confirmAdoptSource = confirmAdoptSource;
window.updateSourceRepoChanged = updateSourceRepoChanged;
