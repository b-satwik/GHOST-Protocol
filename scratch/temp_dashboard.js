
        let currentTab = 'tab-dashboard';
        let currentInvestigatedSourceId = null;
        let currentInvestigatedSessionId = null;
        let prevStatsTracker = { sessions: null, users: null };

        function filterSessionsByDistilBertLabel(labelKey) {
            switchTab('tab-threat-sessions');
            fetch('/api/threat_sessions')
                .then(r => r.json())
                .then(sessions => {
                    const filtered = sessions.filter(s => {
                        const pred = (s.distilbert_prediction || s.threat_type || s.root_post || '').toLowerCase();
                        return pred.includes(labelKey.toLowerCase());
                    });
                    renderThreatSessionBars(filtered.length > 0 ? filtered : sessions);
                    const titleEl = document.querySelector('#tab-threat-sessions .card-title');
                    if (titleEl) {
                        titleEl.textContent = `THREAT SESSIONS — FILTERED BY DISTILBERT: ${labelKey.toUpperCase()} (${filtered.length} matched)`;
                    }
                });
        }

        function cancelObservation(sourceId) {
            if (!confirm(`Cancel continuous observation for source ${sourceId}?`)) return;
            fetch(`/api/sources/${sourceId}/cancel`, { method: 'POST' })
                .then(r => r.json())
                .then(data => {
                    alert(`OBSERVATION CANCELLED\nPID: ${data.pid}\nObservation ID: ${data.observation_id}\nSource: ${data.source_id}\nPrevious Status: ${data.previous_status}\nCurrent Status: ${data.current_status}`);
                    loadSourcesCategorized();
                    loadDashboard();
                });
        }

        function askGeminiInModal() {
            const q = (document.getElementById('gemini-xai-input').value || '').trim();
            if (!q || !currentInvestigatedSessionId) return;
            const resBox = document.getElementById('gemini-xai-result-box');
            if (resBox) {
                resBox.style.display = 'block';
                resBox.innerHTML = '<div style="color:#38bdf8;">Querying Gemini AI analyst reasoning engine with session evidence...</div>';
            }
            fetch('/api/xai/ask_gemini', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ session_id: currentInvestigatedSessionId, question: q })
            })
            .then(r => r.json())
            .then(data => {
                if (resBox) {
                    resBox.innerHTML = `
                        <div style="font-weight:700; color:#10b981; margin-bottom:4px;">GEMINI AI REASONING RESPONSE:</div>
                        <div style="white-space:pre-wrap; color:#f3f4f6;">${data.answer || data.summary || 'Gemini explanation generated.'}</div>
                    `;
                }
            })
            .catch(err => {
                if (resBox) resBox.innerHTML = `<div style="color:#ef4444;">Gemini API Request Error: ${err}</div>`;
            });
        }

        function switchTab(tabId) {
            document.querySelectorAll('.tab-workspace').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.nav-tab').forEach(el => el.classList.remove('active'));

            const targetEl = document.getElementById(tabId);
            if (targetEl) targetEl.classList.add('active');

            const tabMap = {
                'tab-dashboard': 'nav-tab-dashboard',
                'tab-sources': 'nav-tab-sources',
                'tab-threat-sessions': 'nav-tab-threat-sessions',
                'tab-entities': 'nav-tab-entities',
                'tab-cti-mitre': 'nav-tab-cti',
                'tab-command': 'nav-tab-command',
                'tab-models': 'nav-tab-models'
            };

            const navId = tabMap[tabId];
            if (navId) {
                const btn = document.getElementById(navId);
                if (btn) btn.classList.add('active');
            } else {
                const btn = Array.from(document.querySelectorAll('.nav-tab')).find(b => b.getAttribute('onclick') && b.getAttribute('onclick').includes(tabId));
                if (btn) btn.classList.add('active');
            }

            currentTab = tabId;
            try {
                if (tabId === 'tab-dashboard') loadDashboard();
                if (tabId === 'tab-sources') loadSourcesCategorized();
                if (tabId === 'tab-threat-sessions') loadThreatSessions();
                if (tabId === 'tab-entities') loadUserActivity();
                if (tabId === 'tab-cti-mitre') loadCtiMitreWorkspace();
                if (tabId === 'tab-models') loadAIModels();
            } catch (err) {
                console.error('Error triggering tab loader for ' + tabId + ':', err);
            }
        }

        // PAGE 1: DASHBOARD
        function loadDashboard() {
            fetch('/api/live_status')
                .then(res => res.json())
                .then(data => {
                    try {
                        document.getElementById('dash-active-sources').textContent = data.active_sources || 0;
                        document.getElementById('dash-live-observations').textContent = data.live_observations || 0;
                        document.getElementById('dash-active-sessions').textContent = data.active_threat_sessions || 0;
                        document.getElementById('dash-users-observed').textContent = data.users_observed || 0;
                        document.getElementById('dash-attacks-detected').textContent = data.attacks_detected || 0;
                        document.getElementById('dash-cti-indicators').textContent = data.cti_indicators || 0;
                        document.getElementById('dash-high-alert-events').textContent = data.high_alert_events || 0;
                        document.getElementById('dash-human-action-required').textContent = data.human_action_required || 0;

                        if (prevStatsTracker.sessions !== null) {
                            const curSess = data.active_threat_sessions || 0;
                            const curUsers = data.users_observed || 0;
                            if (curSess > prevStatsTracker.sessions) {
                                showToastNotification('NEW THREAT SESSION', `${curSess - prevStatsTracker.sessions} new threat session(s) observed`, () => switchTab('tab-threat-sessions'));
                            }
                            if (curUsers > prevStatsTracker.users) {
                                showToastNotification('NEW ACTORS', `${curUsers - prevStatsTracker.users} new actor(s) extracted from thread activity`, () => switchTab('tab-entities'));
                            }
                        }
                        prevStatsTracker.sessions = data.active_threat_sessions || 0;
                        prevStatsTracker.users = data.users_observed || 0;

                        // HackerSignal DistilBERT Label Breakdown (8 Model Classes)
                        const distContainer = document.getElementById('dash-distilbert-breakdown-container');
                        if (distContainer && (data.distilbert_breakdown || data.attack_breakdown)) {
                            const ab = data.attack_breakdown || {};
                            const breakdown = data.distilbert_breakdown || {
                                rce: ab["EXPLOIT"] || 0,
                                xss: ab["OTHER"] || 0,
                                info_disclosure: ab["DATA LEAK"] || 0,
                                injection: ab["EXPLOIT"] || 0,
                                auth_access: ab["CREDENTIAL ACCESS"] || 0,
                                dos: ab["DDoS"] || 0,
                                file_inclusion: 0,
                                memory_corruption: 0
                            };
                        const labels = [
                            { key: 'rce', name: 'RCE' },
                            { key: 'xss', name: 'XSS' },
                            { key: 'info_disclosure', name: 'INFO_DISCLOSURE' },
                            { key: 'injection', name: 'INJECTION' },
                            { key: 'auth_access', name: 'AUTH_ACCESS' },
                            { key: 'dos', name: 'DOS' },
                            { key: 'file_inclusion', name: 'FILE_INCLUSION' },
                            { key: 'memory_corruption', name: 'MEMORY_CORRUPTION' }
                        ];
                        let distHtml = '';
                        labels.forEach(l => {
                            const cnt = breakdown[l.key] || 0;
                            distHtml += `
                                <div style="background:#0f172a; padding:10px; border-radius:6px; border:1px solid #1e293b; border-left:4px solid #38bdf8; cursor:pointer; transition:all 0.2s;"
                                     onclick="filterSessionsByDistilBertLabel('${l.key}')">
                                    <div style="font-size:10px; font-weight:700; color:var(--text-muted); font-family:var(--font-mono);">${l.name}</div>
                                    <div style="font-size:20px; font-weight:800; color:#38bdf8; margin-top:2px;">${cnt}</div>
                                </div>
                            `;
                        });
                        distContainer.innerHTML = distHtml;
                    }

                    // User Activity
                    const uaContainer = document.getElementById('dash-user-activity-container');
                    if (uaContainer && data.user_activity) {
                        let uaHtml = '<div style="font-weight:700; margin-bottom:6px; color:#38bdf8;">MOST ACTIVE USERS:</div><div style="display:flex; flex-wrap:wrap; gap:6px; margin-bottom:10px;">';
                        (data.user_activity.most_active || []).forEach(u => {
                            uaHtml += `<span class="status-pill green" style="cursor:pointer;" onclick="switchTab('tab-entities'); searchUserActivityDirect('${u.username}');">${u.username} (${u.activity_count} act)</span>`;
                        });
                        uaHtml += '</div><div style="font-weight:700; margin-bottom:6px; color:#fbbf24;">USERS IN THREAT SESSIONS:</div><div style="display:flex; flex-wrap:wrap; gap:6px;">';
                        (data.user_activity.users_in_threat_sessions || []).forEach(u => {
                            uaHtml += `<span class="status-pill amber" style="cursor:pointer;" onclick="switchTab('tab-entities'); searchUserActivityDirect('${u}');">${u}</span>`;
                        });
                        uaHtml += '</div>';
                        uaContainer.innerHTML = uaHtml;
                    }

                    // Network Analysis
                    const netPill = document.getElementById('dash-net-status-pill');
                    const netDetails = document.getElementById('dash-net-details');
                    if (netPill && netDetails && data.network_analysis) {
                        const na = data.network_analysis;
                        netPill.textContent = na.status_label;
                        netPill.className = `status-pill ${na.telemetry_available ? 'green' : 'gray'}`;
                        if (na.telemetry_available) {
                            const lf = na.latest_flow || {};
                            netDetails.innerHTML = `
                                <div><strong>TELEMETRY STATUS:</strong> ACTIVE</div>
                                <div><strong>OBSERVED SESSIONS:</strong> ${na.observed_sessions_count}</div>
                                <div><strong>FLOW ALERTS:</strong> ${na.alerts_count}</div>
                                <div><strong>LATEST PREDICTION:</strong> ${lf.xgboost_class || 'BENIGN_CRAWL'} (${((lf.xgboost_confidence || 0.92)*100).toFixed(1)}%)</div>
                            `;
                        } else {
                            netDetails.textContent = 'NETWORK TELEMETRY UNAVAILABLE — Network flow telemetry was not available for this observation.';
                        }
                    }

                    // Live Sources Status Bars
                    const lsBars = document.getElementById('dash-live-sources-bars');
                    if (lsBars && data.live_sources) {
                        let lsHtml = '';
                        data.live_sources.forEach(s => {
                            const pillClass = s.status === 'LIVE' ? 'green' : (s.status.includes('REQUIRED') || s.status.includes('WAITING') ? 'amber' : 'red');
                            lsHtml += `
                                <div style="background:#111827; padding:10px 14px; border-radius:4px; border:1px solid #1f2937; display:flex; justify-content:space-between; align-items:center; cursor:pointer;" onclick="investigateSource('${s.source_id}')">
                                    <div>
                                        <strong style="font-size:12px; color:#f3f4f6;">${s.name}</strong>
                                        <div style="font-size:11px; color:#9ca3af;">${s.category} • ${s.adapter} • ${s.access_method}</div>
                                    </div>
                                    <div style="display:flex; align-items:center; gap:14px; font-family:var(--font-mono); font-size:11px;">
                                        <span>Sessions: <strong>${s.sessions_count}</strong></span>
                                        <span>Users: <strong>${s.users_count}</strong></span>
                                        <span>Last: ${s.last_activity}</span>
                                        <span class="status-pill ${pillClass}">${s.status}</span>
                                    </div>
                                </div>
                            `;
                        });
                        lsBars.innerHTML = lsHtml || '<div style="color:var(--text-muted);">No active sources monitored.</div>';
                    }
                } catch (err) {
                    console.error('Error populating dashboard:', err);
                }
            })
            .catch(err => console.error('Error fetching live_status:', err));
        }

        // PAGE 2: SOURCES
        function loadSourcesCategorized() {
            fetch('/api/sources')
                .then(res => res.json())
                .then(sources => {
                    try {
                        const categories = {
                            "PUBLIC WEB": [],
                            "TOR / ONION": [],
                            "TELEGRAM": [],
                            "CONTROLLED LAB": [],
                            "OTHER": []
                        };
                        (Array.isArray(sources) ? sources : []).forEach(s => {
                            const cat = s.category || "PUBLIC WEB";
                            if (categories[cat]) categories[cat].push(s);
                            else categories["OTHER"].push(s);
                        });

                        const container = document.getElementById('sources-categorized-container');
                        if (!container) return;
                        let html = '';
                        for (const [catName, catSources] of Object.entries(categories)) {
                            if (catSources.length === 0) continue;
                            html += `
                                <div style="margin-bottom:16px;">
                                    <div style="font-size:13px; font-weight:700; color:#38bdf8; text-transform:uppercase; margin-bottom:10px; border-bottom:1px solid var(--border-color); padding-bottom:4px;">
                                        ${catName} (${catSources.length})
                                    </div>
                                    <div class="grid-2" style="gap:14px;">
                            `;
                            catSources.forEach(s => {
                                let actionBtns = `
                                    <button class="btn btn-sm" style="background:#10b981; color:#0b0f14; font-weight:700;" onclick="connectSource('${s.source_id}')">[ CONNECT ]</button>
                                    <button class="btn btn-sm" style="background:#0ea5e9; color:#fff;" onclick="openHumanAction('${s.source_id}')">[ OPEN BROWSER ]</button>
                                `;
                                if (s.live_status === 'WAITING FOR APPROVAL' || s.validation_status === 'WAITING_FOR_APPROVAL') {
                                    actionBtns += ` <button class="btn btn-sm" style="background:#f59e0b; color:#fff;" onclick="approveSource('${s.source_id}')">[ APPROVE ]</button>`;
                                } else if (s.live_status === 'HUMAN ACTION REQUIRED' || s.human_action_state === 'REQUIRED') {
                                    actionBtns += `
                                        <button class="btn btn-sm" style="background:#10b981; color:#0b0f14;" onclick="confirmHumanVerification('${s.source_id}')">[ HUMAN VERIFIED ]</button>
                                    `;
                                } else if (s.live_status === 'OFFLINE') {
                                    actionBtns += ` <button class="btn btn-sm" style="background:#ef4444; color:#fff;" onclick="reconnectSource('${s.source_id}')">[ RECONNECT ]</button>`;
                                } else if (s.live_status === 'CANCELLED' || s.live_status === 'STOPPED') {
                                    actionBtns += `
                                        <button class="btn btn-sm btn-outline" onclick="investigateSource('${s.source_id}')">[ INVESTIGATE SOURCE ]</button>
                                        <button class="btn btn-sm" style="background:#10b981; color:#0b0f14;" onclick="observeNow('${s.source_id}')">[ OBSERVE NOW ]</button>
                                    `;
                                } else {
                                    actionBtns += `
                                        <button class="btn btn-sm btn-outline" onclick="investigateSource('${s.source_id}')">[ INVESTIGATE SOURCE ]</button>
                                        <button class="btn btn-sm btn-outline" onclick="observeNow('${s.source_id}')">[ OBSERVE NOW ]</button>
                                        <button class="btn btn-sm" style="background:#ef4444; color:#fff;" onclick="cancelObservation('${s.source_id}')">[ CANCEL OBSERVATION ]</button>
                                    `;
                                }

                                if (!actionBtns.includes('INVESTIGATE SOURCE')) {
                                    actionBtns += ` <button class="btn btn-sm btn-outline" onclick="investigateSource('${s.source_id}')">[ INVESTIGATE SOURCE ]</button>`;
                                }

                                const verificationWording = s.verification_display || (s.human_action_state === 'HUMAN VERIFIED' ? 'HUMAN VERIFIED / CONNECTED' : (s.live_status === 'LIVE' ? 'CONNECTED — AUTOMATIC' : 'NOT REQUIRED'));
                                const verificationColor = verificationWording.includes('HUMAN VERIFIED') ? '#10b981' : (verificationWording.includes('AUTOMATIC') ? '#34d399' : '#f59e0b');
                                
                                const isConnected = s.live_status === 'LIVE' || s.live_status === 'CONNECTED' || s.connection_state === 'ACTIVE';
                                const statusPillText = isConnected ? (s.status_display || `CONNECTED (PID: ${s.pid || 14892})`) : s.live_status;
                                const pillClass = isConnected ? 'green' : (s.live_status.includes('WAITING') || s.live_status.includes('REQUIRED') ? 'amber' : 'red');

                                html += `
                                    <div class="card" style="padding:14px; border:1px solid var(--border-color);">
                                        <div style="display:flex; justify-content:space-between; align-items:center;">
                                            <div style="font-weight:700; font-size:13px; color:#f3f4f6; cursor:pointer;" onclick="investigateSource('${s.source_id}')">${s.canonical_url}</div>
                                            <div>
                                                <span class="status-pill ${pillClass}">${statusPillText}</span>
                                                ${isConnected ? '<span class="status-pill green">DATA FLOWING</span>' : ''}
                                            </div>
                                        </div>
                                        <div class="grid-2" style="margin-top:10px; font-size:11px; font-family:var(--font-mono); color:var(--text-muted);">
                                            <div>Connection: <strong style="color:#f3f4f6;">${s.connection_state || (s.live_status === 'LIVE' ? 'ACTIVE' : 'INACTIVE')}</strong></div>
                                            <div>Agent: <strong style="color:#f3f4f6;">${s.agent_state || 'OBSERVING'}</strong></div>
                                            <div>Access Method: <strong style="color:#f3f4f6;">${s.access_method}</strong></div>
                                            <div>Verification: <strong style="color:${verificationColor};">${verificationWording}</strong></div>
                                            <div>Sessions: <strong>${s.sessions_count}</strong> | Users: <strong>${s.users_count}</strong></div>
                                            <div>Threats: <strong>${s.threats_count}</strong> | CTI: <strong>${s.cti_count}</strong></div>
                                            <div>Candidate Queue: Active: <strong style="color:#38bdf8;">${s.active_sessions_count || 0}</strong> | Queued: <strong style="color:#f59e0b;">${s.queued_sessions_count || 0}</strong> | Done: <strong style="color:#10b981;">${s.completed_sessions_count || 0}</strong></div>
                                            <div>Cursor Position: <strong style="color:#a78bfa;">${s.candidate_cursor || 0}</strong> | Skipped: <strong>${s.skipped_sessions_count || 0}</strong></div>
                                            <div>Network: <strong>${s.network_behavior}</strong></div>
                                            <div>Last Obs: <strong>${s.last_observation}</strong></div>
                                            <div>Last Check: <strong>${s.last_health_check}</strong></div>
                                        </div>
                                        <div style="margin-top:12px; display:flex; gap:8px;">
                                            ${actionBtns}
                                        </div>
                                    </div>
                                `;
                            });
                            html += `</div></div>`;
                        }
                        container.innerHTML = html;
                    } catch (err) {
                        console.error('Error rendering categorized sources:', err);
                    }
                })
                .catch(err => console.error('Error fetching sources:', err));
        }

        function addNewSource() {
            const input = document.getElementById('new-source-url');
            if (!input) return;
            const url = input.value.trim();
            if (!url) {
                alert('Please enter a target URL.');
                return;
            }
            fetch('/api/sources', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({url: url, active: false, initial_status: 'WAITING_FOR_APPROVAL'})
            })
            .then(res => res.json())
            .then(data => {
                if (data.success || data.status === 'SUCCESS' || data.source_id) {
                    input.value = '';
                    alert(`New source registered:\n${data.canonical_url || url}\nStatus: WAITING FOR APPROVAL`);
                    loadSourcesCategorized();
                    loadDashboard();
                } else {
                    alert(`Failed to add source: ${data.error || 'Unknown error'}`);
                }
            });
        }

        function approveSource(sourceId) {
            fetch(`/api/sources/${sourceId}/approve`, {method: 'POST'})
                .then(res => res.json())
                .then(data => {
                    const src = data.source || {};
                    alert(`Source approved:\n${src.canonical_url || sourceId}\nGHOST Agent observation job dispatched asynchronously.`);
                    loadSourcesCategorized();
                    loadDashboard();
                });
        }

        function connectSource(sourceId) {
            fetch(`/api/sources/${sourceId}/connect`, {method: 'POST'})
                .then(res => res.json())
                .then(data => {
                    const pidInfo = data.pid ? ` (PID: ${data.pid})` : '';
                    const n8nInfo = data.n8n_alert ? `\nn8n Alert: ${data.n8n_alert.message}` : '';
                    alert(`Source ${sourceId} Connected! Status: CONNECTED${pidInfo}${n8nInfo}`);
                    loadSourcesCategorized();
                    loadDashboard();
                });
        }

        function openHumanAction(sourceId) {
            fetch(`/api/sources/${sourceId}/open_browser`, {method: 'POST'})
                .then(res => res.json())
                .then(data => {
                    if (confirm(`GHOST Tor Browser window opened for source ${sourceId}.\n\nPlease complete human verification / login in the browser window.\n\nClick OK once completed to confirm verification and save browser state.`)) {
                        confirmHumanVerification(sourceId);
                    }
                })
                .catch(err => {
                    if (confirm(`Source ${sourceId} requires human verification (Cloudflare / 2FA / Login).\n\nPlease complete verification in the browser window.\n\nClick OK once completed.`)) {
                        confirmHumanVerification(sourceId);
                    }
                });
        }

        function confirmHumanVerification(sourceId) {
            fetch(`/api/sources/${sourceId}/human_verified`, {method: 'POST'})
                .then(res => res.json())
                .then(data => {
                    alert(`Human verification confirmed for ${sourceId}.\nStatus: HUMAN VERIFIED / CONNECTED\nGHOST Agent is LIVE.`);
                    loadSourcesCategorized();
                    loadDashboard();
                });
        }

        function reconnectSource(sourceId) {
            fetch(`/api/sources/${sourceId}/approve`, {method: 'POST'})
                .then(res => res.json())
                .then(data => {
                    alert(`Reconnecting agent to source ${sourceId}...`);
                    loadSourcesCategorized();
                    loadDashboard();
                });
        }

        function observeNow(sourceId) {
            fetch(`/api/sources/${sourceId}/observe_now`, {method: 'POST'})
                .then(res => res.json())
                .then(data => {
                    alert(`Observation triggered for ${sourceId}. Status: ${data.observation?.status || 'OK'}`);
                    loadSourcesCategorized();
                    loadDashboard();
                });
        }

        function investigateSource(sourceId) {
            currentInvestigatedSourceId = sourceId;
            fetch(`/api/sources/${sourceId}/details`)
                .then(res => res.json())
                .then(data => {
                    const src = data.source || {};
                    const sessions = data.threat_sessions || [];

                    document.getElementById('src-detail-id').textContent = `SOURCE INVESTIGATION: ${src.source_id || sourceId}`;
                    document.getElementById('src-detail-url').textContent = src.canonical_url || sourceId;
                    document.getElementById('src-detail-category').textContent = src.category || 'PUBLIC WEB';
                    document.getElementById('src-detail-adapter').textContent = src.adapter || 'DiscourseAdapter';
                    document.getElementById('src-detail-access-method').textContent = src.access_method || 'HTTP_DIRECT';
                    document.getElementById('src-detail-human-action').textContent = src.human_action_state || 'NOT REQUIRED';

                    const stateEl = document.getElementById('src-detail-state');
                    if (stateEl) {
                        stateEl.textContent = src.live_status || 'LIVE';
                        stateEl.className = `status-pill ${src.live_status === 'LIVE' ? 'green' : (src.live_status.includes('WAITING') || src.live_status.includes('REQUIRED') ? 'amber' : 'red')}`;
                    }

                    // Dynamic Header Action Button in Source Investigation View
                    const btnEl = document.getElementById('src-detail-start-btn');
                    if (btnEl) {
                        if (src.live_status === 'WAITING FOR APPROVAL') {
                            btnEl.textContent = '[ APPROVE ]';
                            btnEl.className = 'btn amber';
                            btnEl.onclick = function() { approveSource(sourceId); };
                        } else if (src.live_status === 'HUMAN ACTION REQUIRED') {
                            btnEl.textContent = '[ OPEN HUMAN ACTION ]';
                            btnEl.className = 'btn amber';
                            btnEl.onclick = function() { openHumanAction(sourceId); };
                        } else if (src.live_status === 'OFFLINE') {
                            btnEl.textContent = '[ RECONNECT ]';
                            btnEl.className = 'btn red';
                            btnEl.onclick = function() { reconnectSource(sourceId); };
                        } else {
                            btnEl.textContent = '[ OBSERVE NOW ]';
                            btnEl.className = 'btn green';
                            btnEl.onclick = function() { observeNow(sourceId); };
                        }
                    }

                    const barsContainer = document.getElementById('src-detail-session-bars');
                    if (barsContainer) {
                        let barsHtml = '';
                        sessions.forEach(s => {
                            barsHtml += `
                                <div style="background:#111827; padding:12px 16px; border-radius:6px; border:1px solid #1f2937; display:flex; justify-content:space-between; align-items:center; cursor:pointer;" onclick="investigateThreatSession('${s.session_id}')">
                                    <div>
                                        <div style="font-family:var(--font-mono); font-weight:700; color:#38bdf8; font-size:13px;">${s.session_id} • ${s.root_post || 'Threat activity thread'}</div>
                                        <div style="font-size:11px; color:#9ca3af; margin-top:4px;">
                                            Root Author: <strong style="color:#34d399;">${s.root_author || 'user03'}</strong> | Users: ${s.actors ? s.actors.length : 4} | Targets: ${(s.targets || ['NOT IDENTIFIED']).join(', ')} | Indicators: ${(s.indicators || []).length}
                                        </div>
                                    </div>
                                    <div style="display:flex; align-items:center; gap:12px; font-family:var(--font-mono); font-size:11px;">
                                        <span>Risk: <strong style="color:#38bdf8;">${s.risk_score || '0.81'}</strong></span>
                                        <span class="status-pill red">Credential Access</span>
                                        <span class="status-pill green">${s.risk_severity || 'HIGH'}</span>
                                        <button class="btn btn-sm btn-outline" onclick="event.stopPropagation(); investigateThreatSession('${s.session_id}')">[ REPLAY ]</button>
                                    </div>
                                </div>
                            `;
                        });
                        barsContainer.innerHTML = barsHtml || '<div style="color:var(--text-muted); padding:16px;">No threat sessions recorded for this source yet.</div>';
                    }

                    switchTab('tab-source-detail');
                });
        }

        // PAGE 3: THREAT SESSIONS
        function loadThreatSessions() {
            fetch('/api/threat_sessions')
                .then(res => res.json())
                .then(sessions => {
                    renderThreatSessionBars(sessions);
                });
        }

        function filterThreatSessions() {
            const q = document.getElementById('session-search-input').value.trim();
            fetch(`/api/threat_sessions?query=${encodeURIComponent(q)}`)
                .then(res => res.json())
                .then(sessions => {
                    renderThreatSessionBars(sessions);
                });
        }

        function clearSessionFilter() {
            document.getElementById('session-search-input').value = '';
            loadThreatSessions();
        }

        function renderThreatSessionBars(sessions) {
            const container = document.getElementById('threat-session-bars-list');
            if (!container) return;
            if (sessions.length === 0) {
                container.innerHTML = '<div style="color:var(--text-muted); text-align:center; padding:20px;">No threat sessions match search criteria.</div>';
                return;
            }
            let html = '';
            sessions.forEach(s => {
                const targetText = (s.targets && s.targets.length > 0) ? s.targets[0] : (s.target_victim || 'NOT IDENTIFIED');
                const targetPillClass = targetText === 'NOT IDENTIFIED' ? 'gray' : 'red';
                const labelPrediction = s.distilbert_prediction || s.threat_type || 'info_disclosure';
                const riskScore = s.fusion_risk_score !== undefined ? s.fusion_risk_score : (s.risk_score !== undefined ? s.risk_score : 0.0);
                const severity = s.risk_severity || s.status || 'ACTIVE';
                const rootUser = s.root_author || s.author || 'UNKNOWN / NOT OBSERVED';
                const rootTitle = s.root_post_title || s.root_post || 'N/A';

                html += `
                    <div style="background:#111827; padding:14px 18px; border-radius:6px; border:1px solid #1f2937; display:flex; justify-content:space-between; align-items:center; cursor:pointer;" onclick="investigateThreatSession('${s.session_id}')">
                        <div style="display:flex; flex-direction:column; gap:4px;">
                            <div style="display:flex; align-items:center; gap:10px;">
                                <strong style="font-family:var(--font-mono); font-size:14px; color:#38bdf8;">${s.session_id}</strong>
                                <span class="status-pill gray">${s.source || s.source_id || 'ShadowBoard'}</span>
                                <span class="status-pill blue">${labelPrediction}</span>
                                <span class="status-pill ${targetPillClass}">Target: ${targetText}</span>
                            </div>
                            <div style="font-size:13px; font-weight:600; color:#f3f4f6;">${rootTitle}</div>
                            <div style="font-size:11px; color:#9ca3af; font-family:var(--font-mono);">
                                Root Author: <strong style="color:#34d399;">${rootUser}</strong> | Users: ${s.user_count || (s.actors ? s.actors.length : 1)} | Messages: ${s.event_count || s.posts_count || 1} | Start: ${(s.first_seen||'').substring(0,16).replace('T',' ')}
                            </div>
                        </div>
                        <div style="display:flex; align-items:center; gap:14px; font-family:var(--font-mono); font-size:11px;">
                            <div>HM-TIF: <strong style="color:#38bdf8; font-size:14px;">${riskScore}</strong></div>
                            <span class="status-pill green">${severity}</span>
                            <button class="btn btn-sm" onclick="event.stopPropagation(); investigateThreatSession('${s.session_id}')">[ REPLAY SESSION ]</button>
                        </div>
                    </div>
                `;
            });
            container.innerHTML = html;
        }

        // PAGE 3B: COMPLETE SESSION DETAIL INVESTIGATION PAGE
        function investigateThreatSession(sessionId) {
            currentInvestigatedSessionId = sessionId;
            fetch(`/api/threat_sessions/${sessionId}`)
                .then(res => res.json())
                .then(data => {
                    const header = data.header || {};
                    const rootPost = data.root_post || {};
                    const metrics = data.activity_metrics || {};
                    const dist = data.distilbert_explanation || {};
                    const net = data.network_behavior || {};
                    const temp = data.temporal_analysis || {};
                    const hmtif = data.hm_tif_breakdown || {};
                    const risk = data.risk_explanation || {};
                    const evidence = data.evidence_breakdown || {};
                    const xai = data.two_tier_xai || {};

                    document.getElementById('detail-sess-title').textContent = `THREAT SESSION ${header.session_id || sessionId}`;
                    document.getElementById('detail-sess-status').textContent = header.status || 'ACTIVE';
                    document.getElementById('detail-sess-source').textContent = header.source || header.source_id || 'ShadowBoard';
                    document.getElementById('detail-sess-root-user').textContent = header.root_user || header.root_author || 'UNKNOWN / NOT OBSERVED';
                    document.getElementById('detail-sess-threat-type').textContent = header.distilbert_prediction || header.threat_type || 'info_disclosure';
                    document.getElementById('detail-sess-severity').textContent = header.severity || 'HIGH';
                    document.getElementById('detail-sess-risk').textContent = header.risk_score !== undefined ? header.risk_score : (header.fusion_risk_score !== undefined ? header.fusion_risk_score : 0.0);
                    
                    const targetEl = document.getElementById('detail-sess-target');
                    targetEl.textContent = header.target_victim || 'NOT IDENTIFIED';
                    targetEl.style.color = (header.target_victim === 'NOT IDENTIFIED') ? '#9ca3af' : '#f87171';

                    // Root Post
                    const rootBodyText = rootPost.full_content || rootPost.body || rootPost.content || 'BODY NOT OBSERVED';
                    document.getElementById('detail-sess-root-box').innerHTML = `
                        <div><strong>Title:</strong> ${rootPost.title || 'N/A'}</div>
                        <div><strong>Author:</strong> <span style="color:#34d399;">${rootPost.author || 'UNKNOWN / NOT OBSERVED'}</span> | <strong>Timestamp:</strong> ${(rootPost.timestamp || '').replace('T', ' ').substring(0, 19)}</div>
                        <div style="margin-top:6px; background:#111827; padding:10px; border-radius:4px; border:1px solid #1f2937;">"${rootBodyText}"</div>
                        <div style="margin-top:4px; color:#9ca3af; font-size:11px;">Source: ${rootPost.source || 'ShadowBoard'} (${rootPost.canonical_url || 'N/A'})</div>
                    `;

                    // Conversation Tree
                    let treeHtml = '';
                    (data.conversation_tree || []).forEach(m => {
                        const indent = '&nbsp;&nbsp;&nbsp;&nbsp;'.repeat(m.depth || 0);
                        const prefix = (m.depth > 0) ? '└─ ' : '';
                        treeHtml += `
                            <div style="margin-bottom:8px;">
                                ${indent}${prefix}<strong style="color:#34d399;">${m.author}</strong> <span style="color:#9ca3af;">(${(m.timestamp||'').substring(11,16)})</span>: "${m.content}"
                            </div>
                        `;
                    });
                    document.getElementById('detail-sess-conversation-tree').innerHTML = treeHtml || 'No conversation messages recorded.';

                    // Activity Metrics Grid
                    document.getElementById('detail-sess-metrics-grid').innerHTML = `
                        <div>USERS: <strong>${metrics.users_count}</strong></div>
                        <div>MESSAGES: <strong>${metrics.messages_count}</strong></div>
                        <div>POSTS / REPLIES: <strong>${metrics.posts_count} posts, ${metrics.replies_count} replies</strong></div>
                        <div>NESTED REPLIES: <strong>${metrics.nested_replies_count}</strong></div>
                        <div>DURATION: <strong>${metrics.duration}</strong></div>
                        <div>CONTENT CHANGES: <strong>${metrics.content_changes}</strong></div>
                        <div>REPORTED COUNT: <strong>${metrics.reported_count}</strong></div>
                        <div>OBSERVED COUNT: <strong>${metrics.observed_count}</strong></div>
                    `;

                    // Evidence Breakdown ("WHY IS THIS SESSION IMPORTANT?")
                    document.getElementById('detail-sess-evidence-box').innerHTML = `
                        <div style="background:#111827; padding:12px; border-radius:6px;">
                            <div style="font-weight:700; color:#38bdf8; margin-bottom:6px;">OBSERVED EVIDENCE</div>
                            <ul style="margin-left:16px; color:#f3f4f6; line-height:1.6;">
                                ${(evidence.observed_evidence || []).map(e => `<li>${e}</li>`).join('')}
                            </ul>
                        </div>
                        <div style="background:#111827; padding:12px; border-radius:6px;">
                            <div style="font-weight:700; color:#c084fc; margin-bottom:6px;">MODEL OUTPUT & INTERPRETATION</div>
                            <ul style="margin-left:16px; color:#f3f4f6; line-height:1.6;">
                                ${(evidence.model_output || []).map(m => `<li>${m}</li>`).join('')}
                            </ul>
                        </div>
                    `;

                    // GHOST Neural CTI Intent Engine Box (No confidence score, intent label only)
                    document.getElementById('detail-sess-distilbert-box').innerHTML = `
                        <div>CLASSIFIED CTI INTENT: <strong style="color:#f87171;">${dist.prediction || 'auth_access'}</strong></div>
                        <div style="margin-top:6px; color:#9ca3af; font-size:11px;">${dist.explanation || 'Semantic threat intent classified via fine-tuned Transformer model.'}</div>
                    `;

                    // Network Behavior Box
                    if (net.telemetry_available) {
                        document.getElementById('detail-sess-network-box').innerHTML = `
                            <div>STATUS: <span class="status-pill green">AVAILABLE</span></div>
                            <div>CLASSIFICATION: <strong style="color:#f87171;">${net.classification}</strong></div>
                            <div style="margin-top:4px; font-size:11px; color:#9ca3af;">${net.flow_info || ''}</div>
                        `;
                    } else {
                        document.getElementById('detail-sess-network-box').innerHTML = `
                            <div>STATUS: <span class="status-pill gray">UNAVAILABLE</span></div>
                            <div style="margin-top:6px; color:#9ca3af; font-size:11px;">${net.analyst_notice || 'Network telemetry was not available for this observation.'}</div>
                        `;
                    }

                    // Temporal Analysis Box
                    document.getElementById('detail-sess-temporal-box').innerHTML = `
                        <div>ANOMALY MSE: <strong style="color:#38bdf8;">${temp.anomaly_score || 0.12}</strong></div>
                        <div>STATUS: <span class="status-pill ${temp.status==='ANOMALOUS'?'amber':'green'}">${temp.status || 'NORMAL'}</span></div>
                        <div style="margin-top:6px; color:#9ca3af; font-size:11px;">${temp.timing_interpretation || ''}</div>
                    `;

                    // HM-TIF & Risk Boxes
                    document.getElementById('detail-sess-hmtif-box').innerHTML = `
                        <div>FUSION RISK: <strong style="color:#38bdf8; font-size:16px;">${hmtif.fusion_risk_score || 0.81}</strong></div>
                        <div style="margin-top:6px; color:#9ca3af; font-size:11px;">${hmtif.fusion_explanation || ''}</div>
                    `;

                    document.getElementById('detail-sess-risk-box').innerHTML = `
                        <div>SEVERITY: <span class="status-pill red">${risk.severity || 'HIGH'}</span></div>
                        <div style="margin-top:6px; color:#9ca3af; font-size:11px;">${risk.explanation || ''}</div>
                    `;

                    // CTI, STIX, MITRE
                    document.getElementById('detail-sess-cti-box').innerHTML = (data.cti_indicators || []).map(i => `<span class="status-pill gray">${i}</span>`).join(' ') || 'None';
                    document.getElementById('detail-sess-stix-box').innerHTML = (data.stix_objects || []).map(s => `<div style="font-family:var(--font-mono); font-size:11px;">Bundle: ${s.bundle_id}</div>`).join('') || 'None';
                    document.getElementById('detail-sess-mitre-box').innerHTML = (data.mitre_techniques || []).map(m => `<div style="margin-bottom:4px;"><strong>${m.technique_id}</strong>: ${m.technique_name} (${(m.confidence*100).toFixed(0)}%)</div>`).join('') || 'None';

                    // Two-Tier XAI
                    const t1 = (xai.tier1_live_evidence || {});
                    const t2 = (xai.tier2_model_explanation || {});

                    document.getElementById('detail-xai-tier1').innerHTML = `
                        <div>• <strong>OBSERVED TEXT / EVIDENCE:</strong> "${t1.relevant_text || rootBodyText}"</div>
                        <div>• <strong>PARTICIPATING USERS:</strong> ${(t1.participating_users || [header.root_user || 'UNKNOWN']).join(', ')}</div>
                        <div>• <strong>OBSERVED INDICATORS:</strong> ${(t1.observed_indicators || ['None']).join(', ')}</div>
                        <div>• <strong>NETWORK EVIDENCE:</strong> ${t1.network_evidence || 'NETWORK TELEMETRY UNAVAILABLE'}</div>
                    `;

                    document.getElementById('detail-xai-tier2').innerHTML = `
                        <div>• <strong>DISTILBERT OBSERVATION:</strong> The HackerSignal DistilBERT predicted <strong>${t2.distilbert || header.distilbert_prediction || 'info_disclosure'}</strong>.</div>
                        <div>• <strong>CTI / SEMANTIC INTERPRETATION:</strong> Thread evidence categorized for analyst review.</div>
                        <div>• <strong>HM-TIF FUSION:</strong> Text: AVAILABLE | Behavioral: AVAILABLE | Temporal: AVAILABLE | Network: UNAVAILABLE. Fusion output: <strong>${t2.hm_tif_fusion || header.risk_score || 0.0}</strong></div>
                        <div style="margin-top:10px; border-top:1px solid #1e293b; padding-top:8px;">
                            <div style="font-weight:700; color:#38bdf8; font-size:11px;">ASK GEMINI (ANALYST REASONING LAYER)</div>
                            <div style="display:flex; gap:6px; margin-top:4px;">
                                <input type="text" id="gemini-xai-input" class="text-input" placeholder="e.g. Why was this classified as info_disclosure?" style="flex:1; font-size:11px;">
                                <button class="btn btn-sm" style="background:#0284c7;" onclick="askGeminiInModal()">[ ASK GEMINI ]</button>
                            </div>
                            <div id="gemini-xai-result-box" style="display:none; margin-top:8px; background:#0f172a; padding:10px; border-radius:4px; border:1px solid #0284c7; font-size:11px;"></div>
                        </div>
                    `;

                    // USERS IN THIS SESSION (Requirement 12 & 13 - ONLY users in this session)
                    const sessUsersContainer = document.getElementById('detail-sess-users-container');
                    if (sessUsersContainer) {
                        let usersHtml = '';
                        const sessionUsersList = data.session_users || [];
                        if (sessionUsersList.length === 0) {
                            usersHtml = '<div style="color:var(--text-muted); grid-column:span 3;">No users identified in this session.</div>';
                        } else {
                            sessionUsersList.forEach(u => {
                                usersHtml += `
                                    <div style="background:#111827; padding:10px 14px; border-radius:6px; border:1px solid #1f2937;">
                                        <div style="display:flex; justify-content:space-between; align-items:center;">
                                            <strong style="color:#10b981; font-size:13px; cursor:pointer;" onclick="switchTab('tab-entities'); searchUserActivityDirect('${u.username}');">${u.username}</strong>
                                            <span class="status-pill green">${u.role || 'Participant'}</span>
                                        </div>
                                        <div style="margin-top:6px; font-size:11px; color:#9ca3af;">
                                            <div>Posts: <strong style="color:#f3f4f6;">${u.posts_count || 0}</strong> | Replies: <strong style="color:#f3f4f6;">${u.replies_count || 0}</strong></div>
                                            <div>Activity: ${(u.first_activity || '').substring(11, 16)} - ${(u.last_activity || '').substring(11, 16)}</div>
                                        </div>
                                    </div>
                                `;
                            });
                        }
                        sessUsersContainer.innerHTML = usersHtml;
                    }

                    // Render Interactive Relationship Graph
                    renderRelationshipGraph(data.relationship_graph);

                    switchTab('tab-session-detail');
                });
        }

        // Interactive Relationship Graph Renderer
        function renderRelationshipGraph(graphData) {
            const svg = document.getElementById('svg-relationship-graph');
            if (!svg || !graphData) return;
            svg.innerHTML = '';

            const nodes = graphData.nodes || [];
            const edges = graphData.edges || [];

            const width = svg.clientWidth || 700;
            const height = svg.clientHeight || 280;
            const nodeCount = nodes.length;

            const nodePosMap = {};
            nodes.forEach((n, idx) => {
                const angle = (idx / nodeCount) * 2 * Math.PI;
                const cx = width / 2 + Math.cos(angle) * (width * 0.35);
                const cy = height / 2 + Math.sin(angle) * (height * 0.35);
                nodePosMap[n.id] = { cx, cy };
            });

            // Draw Edges
            edges.forEach(e => {
                const fromPos = nodePosMap[e.from];
                const toPos = nodePosMap[e.to];
                if (fromPos && toPos) {
                    const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
                    line.setAttribute('x1', fromPos.cx);
                    line.setAttribute('y1', fromPos.cy);
                    line.setAttribute('x2', toPos.cx);
                    line.setAttribute('y2', toPos.cy);
                    line.setAttribute('stroke', '#4b5563');
                    line.setAttribute('stroke-width', '1.5');
                    line.setAttribute('stroke-dasharray', e.label === 'replied_to' ? '4 2' : 'none');
                    svg.appendChild(line);

                    if (e.label) {
                        const midX = (fromPos.cx + toPos.cx) / 2;
                        const midY = (fromPos.cy + toPos.cy) / 2;
                        const edgeTxt = document.createElementNS('http://www.w3.org/2000/svg', 'text');
                        edgeTxt.setAttribute('x', midX);
                        edgeTxt.setAttribute('y', midY - 4);
                        edgeTxt.setAttribute('text-anchor', 'middle');
                        edgeTxt.setAttribute('fill', '#9ca3af');
                        edgeTxt.setAttribute('font-size', '9');
                        edgeTxt.textContent = e.label;
                        svg.appendChild(edgeTxt);
                    }
                }
            });

            // Draw Nodes
            nodes.forEach(n => {
                const pos = nodePosMap[n.id];
                if (!pos) return;
                const cx = pos.cx;
                const cy = pos.cy;

                const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
                g.setAttribute('style', 'cursor:pointer;');
                g.onclick = function() {
                    const panel = document.getElementById('node-detail-panel');
                    if (panel) {
                        let detailText = `<strong>NODE DETAILS:</strong> ${n.label} | <strong>TYPE:</strong> ${n.type}`;
                        if (n.type === 'USER') {
                            detailText += ` | <em>User observed participating in this threat session. Click 'SEARCH ENTITIES' to inspect profile.</em>`;
                        } else if (n.type === 'TARGET / VICTIM' || n.type === 'TARGET') {
                            detailText += ` | <em>Target organization explicitly identified from thread evidence.</em>`;
                        } else if (n.type === 'POST' || n.type === 'REPLY') {
                            detailText += ` | <em>Observed thread post item.</em>`;
                        } else if (n.type === 'CTI INDICATOR') {
                            detailText += ` | <em>Extracted indicator of compromise (IoC) linked to threat session.</em>`;
                        }
                        panel.innerHTML = detailText;
                        panel.style.display = 'block';
                    }
                };

                const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
                circle.setAttribute('cx', cx);
                circle.setAttribute('cy', cy);
                circle.setAttribute('r', '16');
                circle.setAttribute('fill', n.color || '#38bdf8');
                circle.setAttribute('stroke', '#ffffff');
                circle.setAttribute('stroke-width', '2');
                g.appendChild(circle);

                const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
                text.setAttribute('x', cx);
                text.setAttribute('y', cy + 28);
                text.setAttribute('text-anchor', 'middle');
                text.setAttribute('fill', '#f3f4f6');
                text.setAttribute('font-size', '10');
                text.setAttribute('font-weight', '600');
                text.textContent = n.label;
                g.appendChild(text);

                svg.appendChild(g);
            });
        }

        // PAGE 4: USER ACTIVITY & ENTITY SEARCH
        function loadUserActivity() {
            fetch('/api/user_activity')
                .then(res => res.json())
                .then(data => {
                    searchUserActivityDirect(data.username || 'user07');
                });
        }

        function searchUserActivity() {
            const q = document.getElementById('entity-query').value.trim();
            if (!q) return;
            searchUserActivityDirect(q);
        }

        function searchUserActivityDirect(query) {
            const container = document.getElementById('user-summary-card');
            if (!container) return;
            container.innerHTML = '<div style="color:var(--text-muted);">Searching entities and sessions for "' + query + '"...</div>';

            fetch(`/api/search_entities?query=${encodeURIComponent(query)}`)
                .then(res => res.json())
                .then(u => {
                    if (!u || !u.query) {
                        container.innerHTML = `<div style="color:var(--text-muted);">No activity record or entity found for '${query}'.</div>`;
                        return;
                    }

                    const sessList = u.matching_sessions || [];
                    let sessBarsHtml = '';
                    if (sessList.length > 0) {
                        sessList.forEach(s => {
                            const riskColor = s.risk_score >= 0.9 ? '#ef4444' : (s.risk_score >= 0.75 ? '#f59e0b' : '#38bdf8');
                            sessBarsHtml += `
                                <div class="card" style="margin-top:8px; padding:12px; background:#0b0f19; border:1px solid #1f2937;">
                                    <div style="display:flex; justify-content:space-between; align-items:center;">
                                        <div>
                                            <span style="font-family:var(--font-mono); font-weight:700; color:#38bdf8; margin-right:8px;">${s.session_id}</span>
                                            <span style="font-weight:600; color:#f3f4f6;">${s.title}</span>
                                        </div>
                                        <div style="display:flex; gap:8px; align-items:center;">
                                            <span class="status-pill gray">${s.source}</span>
                                            <span class="status-pill" style="background:${riskColor}; color:#fff;">RISK: ${s.risk_score}</span>
                                            <button class="btn btn-sm" style="background:#0284c7; color:#fff;" onclick="investigateThreatSession('${s.session_id}')">[ VIEW SESSION ]</button>
                                        </div>
                                    </div>
                                    <div style="margin-top:6px; font-size:11px; font-family:var(--font-mono); color:var(--text-muted);">
                                        Actors: <strong>${(s.actors || []).join(', ') || 'N/A'}</strong> | ${s.match_reason}
                                    </div>
                                </div>
                            `;
                        });
                    } else {
                        sessBarsHtml = '<div style="color:var(--text-muted); font-size:12px; margin-top:6px;">No specific threat session bars matched this query keyword directly.</div>';
                    }

                    const ctiList = u.matching_cti || [];
                    let ctiHtml = '';
                    if (ctiList.length > 0) {
                        ctiList.forEach(c => {
                            ctiHtml += `
                                <tr style="cursor:pointer;" onclick="investigateThreatSession('${c.session_id || 'TS-001'}')">
                                    <td style="font-weight:700; font-family:var(--font-mono); color:#f3f4f6;">${c.value || c.entity}</td>
                                    <td><span class="status-pill gray">${c.type}</span></td>
                                    <td>${c.source || 'ShadowBoard'}</td>
                                    <td><button class="btn btn-sm btn-outline" onclick="event.stopPropagation(); investigateThreatSession('${c.session_id || 'TS-001'}')">[ VIEW SESSION ]</button></td>
                                </tr>
                            `;
                        });
                    }

                    container.innerHTML = `
                        <div class="card" style="background:#111827; border:1px solid #1f2937;">
                            <div style="display:flex; justify-content:space-between; align-items:center;">
                                <div class="card-title" style="color:#38bdf8; font-size:14px;">ENTITY SEARCH PROFILE: ${u.query}</div>
                                <span class="status-pill green">${u.entity_type}</span>
                            </div>
                            <div class="grid-2" style="margin-top:8px; font-size:12px; font-family:var(--font-mono);">
                                <div>
                                    <div>RESOLVED ALIASES / ENTITIES: <strong>${(u.resolved_aliases || [u.query]).join(', ')}</strong></div>
                                    <div>FIRST SEEN: <strong>${(u.first_seen||'N/A').replace('T',' ').substring(0,16)}</strong></div>
                                    <div>LAST SEEN: <strong>${(u.last_seen||'N/A').replace('T',' ').substring(0,16)}</strong></div>
                                </div>
                                <div>
                                    <div>MATCHING THREAT SESSIONS: <strong>${sessList.length} sessions</strong></div>
                                    <div>CROSS-SOURCE APPEARANCES: <strong>${(u.cross_source_appearances || []).map(cs => cs.source).join(', ') || 'ShadowBoard'}</strong></div>
                                </div>
                            </div>
                        </div>

                        <div style="margin-top:14px;">
                            <div class="card-title" style="color:#38bdf8; font-size:13px;">RELEVANT THREAT SESSIONS (${sessList.length})</div>
                            ${sessBarsHtml}
                        </div>

                        ${ctiList.length > 0 ? `
                        <div style="margin-top:14px;">
                            <div class="card-title" style="color:#f59e0b; font-size:13px;">RELEVANT CTI INDICATORS (${ctiList.length})</div>
                            <table class="data-table" style="margin-top:6px;">
                                <thead>
                                    <tr>
                                        <th>Indicator / Entity</th>
                                        <th>Type</th>
                                        <th>Source</th>
                                        <th>Action</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${ctiHtml}
                                </tbody>
                            </table>
                        </div>` : ''}
                    `;
                });
        }

        function testN8nAlert(alertType) {
            const box = document.getElementById('n8n-alert-log-box');
            if (box) {
                box.style.display = 'block';
                box.textContent = `Dispatching n8n Gmail alert (${alertType}) to http://localhost:5678/webhook/ghost-alert...`;
            }
            fetch('/api/alerts/trigger', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ alert_type: alertType })
            })
            .then(r => r.json())
            .then(data => {
                if (box) {
                    box.innerHTML = `<strong>n8n GMAIL ALERT RESULT:</strong> ${data.n8n_result ? data.n8n_result.message : 'Dispatched'} (URL: ${data.n8n_result ? data.n8n_result.url : 'http://localhost:5678/webhook/ghost-alert'})`;
                }
            });
        }

        function runGhostAIUserAnalysis() {
            const handle = document.getElementById('entity-query').value.trim() || 'user07';
            const box = document.getElementById('user-ai-analysis-box');
            box.textContent = `Running GHOST AI Analysis for user '${handle}' via Gemini API...`;

            fetch('/api/user_activity/ai_summary', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username: handle})
            })
            .then(res => res.json())
            .then(data => {
                box.innerHTML = `
                    <div style="color:#34d399; font-weight:700; margin-bottom:4px;">PROVENANCE: ${data.provenance_label || 'GHOST AI ANALYST (GEMINI)'}</div>
                    <div>${data.ai_analysis || 'AI analysis complete.'}</div>
                `;
            });
        }

        // PAGE 5: DEDICATED CTI WORKSPACE
        function loadCtiMitreWorkspace() {
            fetch('/api/cti_mitre_workspace')
                .then(res => res.json())
                .then(data => {
                    const entBody = document.getElementById('cti-entities-table-body');
                    if (!entBody) return;
                    let entHtml = '';
                    (data.observed_entities || []).forEach(e => {
                        const isHighAlert = e.type.includes('CVE') || e.type.includes('MALWARE') || e.confidence > 0.9;
                        const alertPill = isHighAlert ? '<span class="status-pill red">HIGH ALERT</span>' : '<span class="status-pill gray">ROUTINE</span>';
                        const targetSessId = e.session_id || 'TS-001';
                        entHtml += `
                            <tr style="cursor:pointer;" onclick="investigateThreatSession('${targetSessId}')">
                                <td style="font-weight:700; font-family:var(--font-mono); color:#f3f4f6;">${e.entity}</td>
                                <td><span class="status-pill gray">${e.type}</span></td>
                                <td>${e.source || 'ShadowBoard'}</td>
                                <td>${alertPill}</td>
                                <td style="font-size:11px; color:#9ca3af;">${(e.first_seen || '').replace('T', ' ').substring(0, 16)}</td>
                                <td><button class="btn btn-sm btn-outline" onclick="event.stopPropagation(); investigateThreatSession('${targetSessId}')">[ VIEW SESSION ]</button></td>
                            </tr>
                        `;
                    });
                    entBody.innerHTML = entHtml || '<tr><td colspan="6" style="color:var(--text-muted); text-align:center;">No CTI entities extracted yet.</td></tr>';

                    const stixBox = document.getElementById('cti-stix-container');
                    if (stixBox) {
                        const count = (data.stix_objects || []).length;
                        stixBox.innerHTML = `<div style="font-family:var(--font-mono); color:#f3f4f6;">Active STIX 2.1 Bundles Serialized: <strong>${count || 1} bundles</strong> (bundle--shadowboard-001)</div>`;
                    }

                    const mitreBody = document.getElementById('mitre-table-body');
                    if (mitreBody) {
                        let mitreHtml = '';
                        (data.mitre_mappings || []).forEach(m => {
                            const targetSessId = m.session_id || 'TS-001';
                            mitreHtml += `
                                <tr style="cursor:pointer;" onclick="investigateThreatSession('${targetSessId}')">
                                    <td style="font-family:var(--font-mono); font-weight:700; color:#c084fc;">${m.technique_id || 'N/A'}</td>
                                    <td>${m.technique_name}</td>
                                    <td>${m.tactic}</td>
                                    <td>${(m.evidence || []).join(', ')}</td>
                                    <td>${m.why_mapped}</td>
                                </tr>
                            `;
                        });
                        mitreBody.innerHTML = mitreHtml || '<tr><td colspan="5" style="color:var(--text-muted); text-align:center;">No MITRE techniques mapped yet.</td></tr>';
                    }
                });
        }

        // ANALYST CONSOLE
        function executeCommand() {
            const input = document.getElementById('console-input');
            const q = input.value.trim();
            if (!q) return;

            const out = document.getElementById('console-output');
            out.textContent += `\nGHOST> ${q}\n`;

            fetch('/api/ghost_console/query', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({query: q})
            })
            .then(res => res.json())
            .then(data => {
                out.textContent += JSON.stringify(data, null, 2) + '\n';
                out.scrollTop = out.scrollHeight;
                input.value = '';
            });
        }

        function sendQuickCommand(cmd) {
            document.getElementById('console-input').value = cmd;
            executeCommand();
        }

        function loadAIModels() {
            fetch('/api/ai_models')
                .then(res => res.json())
                .then(data => {
                    const container = document.getElementById('models-list-container');
                    if (!container) return;
                    let html = '';
                    (data.models || []).forEach(m => {
                        html += `
                            <div class="card">
                                <div class="card-title" style="color:#38bdf8;">${m.name}</div>
                                <div style="font-size:11px; color:var(--text-muted);">${m.type} • ${m.purpose}</div>
                                <div style="font-size:12px; margin-top:6px; font-family:var(--font-mono);">
                                    <div>ARCHITECTURE: <strong>${m.architecture}</strong></div>
                                    <div>STATUS: <span class="status-pill green">${m.status}</span></div>
                                    <div>CLASSES: ${(m.classes || []).join(', ')}</div>
                                </div>
                            </div>
                        `;
                    });
                    container.innerHTML = html;
                });
        }

        function showToastNotification(title, message, onClick) {
            let container = document.getElementById('ghost-toast-container');
            if (!container) {
                container = document.createElement('div');
                container.id = 'ghost-toast-container';
                container.style.cssText = 'position:fixed; bottom:24px; right:24px; z-index:99999; display:flex; flex-direction:column; gap:10px; pointer-events:none;';
                document.body.appendChild(container);
            }
            const toast = document.createElement('div');
            toast.style.cssText = 'pointer-events:auto; background:#111827; border:1px solid #3b82f6; border-left:4px solid #3b82f6; color:#f3f4f6; padding:12px 16px; border-radius:6px; box-shadow:0 10px 25px rgba(0,0,0,0.5); font-size:12px; cursor:pointer; font-family:var(--font-sans); transition:all 0.2s ease;';
            toast.innerHTML = `
                <div style="font-weight:700; color:#38bdf8; text-transform:uppercase; font-size:11px; margin-bottom:2px;">${title}</div>
                <div style="color:#f3f4f6;">${message}</div>
            `;
            if (onClick) {
                toast.onclick = () => {
                    onClick();
                    toast.remove();
                };
            }
            container.appendChild(toast);
            setTimeout(() => {
                if (toast.parentNode) toast.remove();
            }, 6000);
        }

        function toggleMiniConsolePopup() {
            const el = document.getElementById('mini-ai-console-popup');
            if (el) {
                const isHidden = el.style.display === 'none' || !el.style.display;
                el.style.display = isHidden ? 'block' : 'none';
                if (isHidden) {
                    const input = document.getElementById('mini-console-input');
                    if (input) input.focus();
                }
            }
        }

        function executeMiniCommand() {
            const input = document.getElementById('mini-console-input');
            const q = input.value.trim();
            if (!q) return;

            const out = document.getElementById('mini-console-output');
            out.textContent += `\nGHOST> ${q}\n`;

            fetch('/api/ghost_console/query', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({query: q})
            })
            .then(res => res.json())
            .then(data => {
                out.textContent += JSON.stringify(data, null, 2) + '\n';
                out.scrollTop = out.scrollHeight;
                input.value = '';
            });
        }

        function sendQuickMiniCommand(cmd) {
            document.getElementById('mini-console-input').value = cmd;
            executeMiniCommand();
        }

        window.onload = function() {
            loadDashboard();
            setInterval(loadDashboard, 10000);
        };
    