/**
 * Garena RoV Academy Auto-Solver v3.0 - Frontend Engine
 * Modern Vanilla JavaScript (Zero External Frameworks)
 * Strict Contract:
 *  - Initial State: GET /api/jobs/active
 *  - Actions: POST /api/jobs/start, POST /api/jobs/stop
 *  - WebSocket: ws://localhost:8000/ws/status
 */

const App = (function () {
  'use strict';

  // Config & Endpoints
  const getApiBase = () => {
    if (typeof window !== 'undefined' && (window.location.protocol === 'file:' || !window.location.host)) {
      return 'http://localhost:8000';
    }
    return '';
  };

  const CONFIG = {
    apiActiveJob: `${getApiBase()}/api/jobs/active`,
    apiStartJob: `${getApiBase()}/api/jobs/start`,
    apiStopJob: `${getApiBase()}/api/jobs/stop`,
    wsUrl: (function () {
      const isFile = typeof window !== 'undefined' && (window.location.protocol === 'file:' || !window.location.host);
      const proto = (typeof window !== 'undefined' && window.location.protocol === 'https:') ? 'wss:' : 'ws:';
      const host = isFile ? 'localhost:8000' : (window.location.host || 'localhost:8000');
      return `${proto}//${host}/ws/status`;
    })(),
    reconnectIntervalMs: 3000,
    maxReconnectIntervalMs: 15000,
  };

  // State Store
  const state = {
    currentStep: 1,
    ws: null,
    wsConnected: false,
    reconnectTimer: null,
    reconnectAttempts: 0,
    activeJobId: null,
    jobStatus: 'idle', // idle, queued, running, stopped, completed, failed
    accountData: {
      garenaId: '',
      token: '',
      hasPassword: false,
      gold: 0,
      silver: 0,
      completedChapters: 0,
    },
    botConfig: {
      autoRedeem: true,
      preferredRewards: ['skin', 'crystal', 'ticket'],
      proxy: '',
    },
    telemetry: {
      percent: 0,
      chapter: '',
      questionIndex: 'ข้อที่ 0/0',
      questionText: 'รอคำสั่งเริ่มงานจากผู้ใช้...',
      choices: [],
      wafBlocked: false,
      wafMessage: '',
      passedChapters: 0,
      totalQuestions: 0,
      goldEarned: 0,
      silverEarned: 0,
      redeemedRewards: [],
    },
  };

  // DOM Elements Cache
  const dom = {};

  function initDomElements() {
    // Stepper & Panels
    dom.stepTabs = [1, 2, 3, 4].map((n) => document.getElementById(`stepTab${n}`));
    dom.stepPanels = [1, 2, 3, 4].map((n) => document.getElementById(`step${n}Panel`));

    // WS Status
    dom.wsBadge = document.getElementById('wsBadge');
    dom.wsDot = document.getElementById('wsDot');
    dom.wsText = document.getElementById('wsText');

    // Step 1: Auth
    dom.authRawToken = document.getElementById('authRawToken');
    dom.authGarenaId = document.getElementById('authGarenaId');
    dom.authGarenaPw = document.getElementById('authGarenaPw');
    dom.accountStatusPill = document.getElementById('accountStatusPill');
    dom.previewGarenaId = document.getElementById('previewGarenaId');
    dom.previewDetails = document.getElementById('previewDetails');
    dom.vaultFileInput = document.getElementById('vaultFileInput');
    dom.dropzone = document.getElementById('dropzone');

    // Step 2: Config
    dom.cfgAutoRedeem = document.getElementById('cfgAutoRedeem');
    dom.rwSkin = document.getElementById('rwSkin');
    dom.rwCrystal = document.getElementById('rwCrystal');
    dom.rwTicket = document.getElementById('rwTicket');
    dom.cfgProxy = document.getElementById('cfgProxy');

    // Step 3: Live Dashboard
    dom.wafAlertBanner = document.getElementById('wafAlertBanner');
    dom.wafAlertMsg = document.getElementById('wafAlertMsg');
    dom.jobRefBadge = document.getElementById('jobRefBadge');
    dom.jobStatusHeader = document.getElementById('jobStatusHeader');
    dom.btnStartJob = document.getElementById('btnStartJob');
    dom.btnStopJob = document.getElementById('btnStopJob');
    dom.progressBar = document.getElementById('progressBar');
    dom.progressLabel = document.getElementById('progressLabel');
    dom.progressPercent = document.getElementById('progressPercent');
    dom.currentChapterTitle = document.getElementById('currentChapterTitle');
    dom.currentQuestionIndex = document.getElementById('currentQuestionIndex');
    dom.currentQuestionText = document.getElementById('currentQuestionText');
    dom.currentChoicesContainer = document.getElementById('currentChoicesContainer');
    dom.liveLogBox = document.getElementById('liveLogBox');

    // Step 4: Results
    dom.finalJobStatusBadge = document.getElementById('finalJobStatusBadge');
    dom.sumPassedChapters = document.getElementById('sumPassedChapters');
    dom.sumTotalQuestions = document.getElementById('sumTotalQuestions');
    dom.sumGoldEarned = document.getElementById('sumGoldEarned');
    dom.sumRedeemedCount = document.getElementById('sumRedeemedCount');
    dom.redeemedItemsList = document.getElementById('redeemedItemsList');
    dom.toastContainer = document.getElementById('toastContainer');
  }

  // =========================================================================
  // TOAST NOTIFICATIONS
  // =========================================================================

  function showToast(message, type = 'info') {
    if (!dom.toastContainer) return;
    const toast = document.createElement('div');
    const colorClasses = {
      success: 'bg-emerald-950 border-emerald-700 text-emerald-200',
      error: 'bg-rose-950 border-rose-700 text-rose-200',
      warning: 'bg-amber-950 border-amber-700 text-amber-200',
      info: 'bg-slate-900 border-slate-700 text-cyan-200',
    }[type] || 'bg-slate-900 border-slate-700 text-slate-200';

    toast.className = `toast-msg px-4 py-3 rounded-xl border text-xs shadow-xl flex items-center gap-2 pointer-events-auto ${colorClasses}`;
    toast.innerHTML = `
      <span>${type === 'success' ? '✅' : type === 'error' ? '❌' : type === 'warning' ? '⚠️' : 'ℹ️'}</span>
      <span>${escapeHtml(message)}</span>
    `;

    dom.toastContainer.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transition = 'opacity 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }

  function escapeHtml(str) {
    return String(str || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  // =========================================================================
  // STEPPER & TAB NAVIGATION
  // =========================================================================

  function goToStep(stepNumber) {
    if (stepNumber < 1 || stepNumber > 4) return;
    state.currentStep = stepNumber;

    // Update Step Indicators
    dom.stepTabs.forEach((tab, idx) => {
      if (!tab) return;
      const num = idx + 1;
      tab.classList.remove('active', 'completed');
      const numSpan = tab.querySelector('.step-num');

      if (num === stepNumber) {
        tab.classList.add('active');
        if (numSpan) {
          numSpan.className = 'step-num flex items-center justify-center w-8 h-8 rounded-lg bg-cyan-500 text-slate-950 font-bold text-sm';
        }
      } else if (num < stepNumber) {
        tab.classList.add('completed');
        if (numSpan) {
          numSpan.className = 'step-num flex items-center justify-center w-8 h-8 rounded-lg bg-emerald-500 text-slate-950 font-bold text-sm';
        }
      } else {
        if (numSpan) {
          numSpan.className = 'step-num flex items-center justify-center w-8 h-8 rounded-lg bg-slate-800 text-slate-400 font-bold text-sm';
        }
      }
    });

    // Update Panels
    dom.stepPanels.forEach((panel, idx) => {
      if (!panel) return;
      if (idx + 1 === stepNumber) {
        panel.classList.remove('hidden');
      } else {
        panel.classList.add('hidden');
      }
    });

    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  function validateAndProceedToStep2() {
    const rawToken = dom.authRawToken ? dom.authRawToken.value.trim() : '';
    const garenaId = dom.authGarenaId ? dom.authGarenaId.value.trim() : '';
    const garenaPw = dom.authGarenaPw ? dom.authGarenaPw.value.trim() : '';

    if (!rawToken && !garenaId && !state.accountData.token && !state.accountData.garenaId) {
      showToast('กรุณากรอก Token หรือระบุ Garena ID ก่อนดำเนินการต่อ', 'warning');
      return;
    }

    if (rawToken) {
      state.accountData.token = rawToken;
      state.accountData.garenaId = garenaId || 'Active User (Token)';
    } else if (garenaId) {
      state.accountData.garenaId = garenaId;
      state.accountData.hasPassword = Boolean(garenaPw);
    }

    updateAccountPreview();
    goToStep(2);
  }

  function updateAccountPreview() {
    if (!dom.previewGarenaId) return;
    const gid = state.accountData.garenaId || 'ยังไม่ระบุ';
    dom.previewGarenaId.textContent = gid;

    if (state.accountData.token || state.accountData.hasPassword) {
      dom.accountStatusPill.className = 'text-[11px] px-2 py-0.5 rounded font-mono bg-cyan-950 text-cyan-400 border border-cyan-800';
      dom.accountStatusPill.textContent = state.accountData.token ? 'พร้อมทำงาน (Token)' : 'พร้อมทำงาน (SSO)';
    } else {
      dom.accountStatusPill.className = 'text-[11px] px-2 py-0.5 rounded font-mono bg-slate-800 text-slate-400';
      dom.accountStatusPill.textContent = 'ยังไม่ได้ยืนยัน';
    }

    dom.previewDetails.textContent = `Gold: ${state.accountData.gold} · Silver: ${state.accountData.silver} · บทที่ผ่าน: ${state.accountData.completedChapters}/40`;
  }

  // =========================================================================
  // VAULT FILE UPLOAD HANDLER
  // =========================================================================

  function handleVaultUpload(event) {
    const file = event.target.files && event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function (e) {
      try {
        const json = JSON.parse(e.target.result);
        const accounts = Array.isArray(json.accounts) ? json.accounts : [];
        if (accounts.length === 0) {
          showToast('ไม่พบข้อมูลบัญชีในไฟล์ accounts_vault.json', 'warning');
          return;
        }

        const primary = accounts.find((a) => a.selected) || accounts[0];
        state.accountData.garenaId = primary.garena_id || primary.account || 'Vault User';
        state.accountData.token = primary.jwt_token || primary.token || '';
        state.accountData.gold = primary.gold || 0;
        state.accountData.silver = primary.silver || 0;
        state.accountData.completedChapters = primary.completed_chapters || 0;

        if (dom.authRawToken && state.accountData.token) {
          dom.authRawToken.value = state.accountData.token;
        }
        if (dom.authGarenaId) {
          dom.authGarenaId.value = state.accountData.garenaId;
        }

        updateAccountPreview();
        showToast(`นำเข้าบัญชีจาก Vault สำเร็จ (${accounts.length} บัญชี)`, 'success');
      } catch (err) {
        showToast('ไฟล์ JSON ไม่ถูกต้อง กรุณาตรวจสอบไฟล์ Vault', 'error');
      }
    };
    reader.readAsText(file);
  }

  // =========================================================================
  // WEBSOCKET INTEGRATION (ws://localhost:8000/ws/status)
  // =========================================================================

  function initWebSocket() {
    if (state.ws && (state.ws.readyState === WebSocket.OPEN || state.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }

    updateWsStatus('connecting');
    try {
      state.ws = new WebSocket(CONFIG.wsUrl);
    } catch (err) {
      console.warn('[WS] Connection init error:', err);
      scheduleWsReconnect();
      return;
    }

    state.ws.onopen = function () {
      state.wsConnected = true;
      state.reconnectAttempts = 0;
      updateWsStatus('connected');
      appendLog('[WS] เชื่อมต่อ WebSocket สำเร็จ (เรียลไทม์พร้อมทำงาน)', 'success');
    };

    state.ws.onmessage = function (event) {
      handleWebSocketMessage(event.data);
    };

    state.ws.onerror = function (err) {
      console.warn('[WS] Error:', err);
    };

    state.ws.onclose = function () {
      state.wsConnected = false;
      updateWsStatus('disconnected');
      scheduleWsReconnect();
    };
  }

  function scheduleWsReconnect() {
    if (state.reconnectTimer) return;
    state.reconnectAttempts++;
    const delay = Math.min(
      CONFIG.reconnectIntervalMs * Math.pow(1.5, state.reconnectAttempts - 1),
      CONFIG.maxReconnectIntervalMs
    );
    state.reconnectTimer = setTimeout(() => {
      state.reconnectTimer = null;
      initWebSocket();
    }, delay);
  }

  function updateWsStatus(status) {
    if (!dom.wsBadge || !dom.wsDot || !dom.wsText) return;
    if (status === 'connected') {
      dom.wsBadge.className = 'flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-mono bg-cyan-950/80 border border-cyan-800 text-cyan-300';
      dom.wsDot.className = 'w-2 h-2 rounded-full bg-cyan-400 pulse-active';
      dom.wsText.textContent = 'WS: ออนไลน์';
    } else if (status === 'connecting') {
      dom.wsBadge.className = 'flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-mono bg-amber-950/80 border border-amber-800 text-amber-300';
      dom.wsDot.className = 'w-2 h-2 rounded-full bg-amber-400';
      dom.wsText.textContent = 'WS: กำลังเชื่อมต่อ...';
    } else {
      dom.wsBadge.className = 'flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-mono bg-slate-900 border border-slate-700 text-slate-400';
      dom.wsDot.className = 'w-2 h-2 rounded-full bg-slate-500';
      dom.wsText.textContent = 'WS: ขาดการเชื่อมต่อ';
    }
  }

  /**
   * Parse incoming WebSocket JSON payloads
   * Examples:
   *  { "status": "running", "message": "Answering Q1...", "percent": 45, "chapter": "บทที่ 5", ... }
   */
  function handleWebSocketMessage(rawData) {
    let payload;
    try {
      payload = typeof rawData === 'string' ? JSON.parse(rawData) : rawData;
    } catch (e) {
      appendLog(`[WS RAW] ${rawData}`);
      return;
    }

    console.log('[WS Message]', payload);

    // 1. Status Update
    if (payload.status) {
      setJobStatus(payload.status);
    }

    // 2. Log Message
    if (payload.message) {
      appendLog(payload.message, payload.status === 'failed' ? 'error' : 'info');
    }

    // 3. Progress percentage & chapter
    if (typeof payload.percent === 'number') {
      updateProgress(payload.percent, payload.progress_label || payload.message || '');
    }

    // 4. Chapter & Question
    if (payload.chapter || payload.current_chapter) {
      const chName = payload.chapter || payload.current_chapter;
      dom.currentChapterTitle.textContent = `บทที่กำลังทำ: ${chName}`;
    }

    if (payload.question || payload.current_question) {
      const qText = payload.question || payload.current_question;
      dom.currentQuestionText.textContent = qText;
    }

    if (payload.question_index || payload.q_index) {
      dom.currentQuestionIndex.textContent = payload.question_index || payload.q_index;
    }

    // Choices update
    if (Array.isArray(payload.choices) || Array.isArray(payload.options)) {
      renderChoices(payload.choices || payload.options, payload.selected_choice);
    }

    // 5. WAF Alert detection
    if (payload.waf_blocked || payload.blocked_by_waf || payload.status_code === 403) {
      showWafAlert(payload.waf_message || payload.message || 'ระบบความปลอดภัยของ Garena บล็อกการเข้าถึงอัตโนมัติ');
    } else if (payload.waf_blocked === false) {
      hideWafAlert();
    }

    // 6. Summary / Completion data
    if (payload.summary || payload.results || payload.status === 'completed') {
      const s = payload.summary || payload.results || payload;
      updateResultsSummary(s);
      if (payload.status === 'completed' && state.currentStep === 3) {
        showToast('การทำงานเสร็จสิ้นสมบูรณ์! กำลังเปิดหน้าสรุปผล...', 'success');
        setTimeout(() => goToStep(4), 1200);
      }
    }
  }

  function renderChoices(choices, selectedChoice) {
    if (!dom.currentChoicesContainer) return;
    dom.currentChoicesContainer.innerHTML = '';
    choices.forEach((choice, idx) => {
      const text = typeof choice === 'object' ? choice.text || choice.name || JSON.stringify(choice) : String(choice);
      const isSelected = selectedChoice && (selectedChoice === text || selectedChoice === idx);

      const div = document.createElement('div');
      div.className = `choice-pill p-2 rounded-lg border border-slate-800 bg-slate-900/40 text-slate-300 flex items-center gap-2 ${
        isSelected ? 'selected' : ''
      }`;
      div.innerHTML = `
        <span class="w-4 h-4 rounded-full border border-slate-600 flex items-center justify-center text-[9px] font-mono">${idx + 1}</span>
        <span class="truncate">${escapeHtml(text)}</span>
      `;
      dom.currentChoicesContainer.appendChild(div);
    });
  }

  function showWafAlert(msg) {
    if (!dom.wafAlertBanner || !dom.wafAlertMsg) return;
    dom.wafAlertMsg.textContent = msg;
    dom.wafAlertBanner.classList.remove('hidden');
    appendLog(`[🚨 WAF] ${msg}`, 'error');
  }

  function hideWafAlert() {
    if (!dom.wafAlertBanner) return;
    dom.wafAlertBanner.classList.add('hidden');
  }

  function updateProgress(percent, label) {
    state.telemetry.percent = Math.min(100, Math.max(0, percent));
    if (dom.progressBar) {
      dom.progressBar.style.width = `${state.telemetry.percent}%`;
      if (state.telemetry.percent > 0 && state.telemetry.percent < 100) {
        dom.progressBar.classList.add('shimmer-active');
      } else {
        dom.progressBar.classList.remove('shimmer-active');
      }
    }
    if (dom.progressPercent) {
      dom.progressPercent.textContent = `${state.telemetry.percent}%`;
    }
    if (dom.progressLabel && label) {
      dom.progressLabel.textContent = label;
    }
  }

  function setJobStatus(status) {
    state.jobStatus = status;
    const isRunning = status === 'running' || status === 'queued';

    if (dom.btnStartJob && dom.btnStopJob) {
      if (isRunning) {
        dom.btnStartJob.disabled = true;
        dom.btnStartJob.classList.add('opacity-40', 'cursor-not-allowed');
        dom.btnStopJob.disabled = false;
        dom.btnStopJob.classList.remove('opacity-40', 'cursor-not-allowed');
      } else {
        dom.btnStartJob.disabled = false;
        dom.btnStartJob.classList.remove('opacity-40', 'cursor-not-allowed');
        dom.btnStopJob.disabled = true;
        dom.btnStopJob.classList.add('opacity-40', 'cursor-not-allowed');
      }
    }

    if (dom.jobStatusHeader) {
      const statusMap = {
        idle: 'สถานะ: พร้อมเริ่มงาน',
        queued: 'สถานะ: รอคิวประมวลผล...',
        running: 'สถานะ: กำลังทำงาน...',
        stopped: 'สถานะ: หยุดการทำงานแล้ว',
        cancelled: 'สถานะ: ยกเลิกการทำงานแล้ว',
        completed: 'สถานะ: เสร็จสมบูรณ์ (100%)',
        failed: 'สถานะ: เกิดข้อผิดพลาด',
      };
      dom.jobStatusHeader.textContent = statusMap[status] || `สถานะ: ${status}`;
    }
  }

  function appendLog(text, level = 'info') {
    if (!dom.liveLogBox) return;
    const line = document.createElement('div');
    const time = new Date().toLocaleTimeString('th-TH', { hour12: false });
    const colorClass = {
      error: 'text-rose-400 font-semibold',
      success: 'text-emerald-400',
      warning: 'text-amber-400',
      info: 'text-slate-300',
    }[level] || 'text-slate-300';

    line.className = `${colorClass} leading-relaxed`;
    line.textContent = `[${time}] ${text}`;
    dom.liveLogBox.appendChild(line);
    dom.liveLogBox.scrollTop = dom.liveLogBox.scrollHeight;
  }

  function clearLogs() {
    if (dom.liveLogBox) {
      dom.liveLogBox.innerHTML = '<div class="text-slate-500">[SYSTEM] บันทึกถูกล้างเรียบร้อย</div>';
    }
  }

  // =========================================================================
  // BACKEND API INTEGRATION (FETCH API)
  //  - GET /api/jobs/active
  //  - POST /api/jobs/start
  //  - POST /api/jobs/stop
  // =========================================================================

  async function fetchActiveJobState() {
    try {
      const resp = await fetch(CONFIG.apiActiveJob, {
        method: 'GET',
        headers: { Accept: 'application/json' },
      });

      if (!resp.ok) {
        console.log(`[API] GET /api/jobs/active returned status ${resp.status}`);
        return;
      }

      const data = await resp.json();
      console.log('[API Initial Active Job]', data);

      if (data && data.job) {
        const job = data.job;
        state.activeJobId = job.job_id || null;
        if (dom.jobRefBadge && job.ref_code) {
          dom.jobRefBadge.textContent = job.ref_code;
        }
        setJobStatus(job.status || 'idle');
        updateProgress(job.percent || 0, job.progress_label || '');

        if (Array.isArray(job.logs)) {
          job.logs.forEach((logStr) => appendLog(logStr));
        }

        if (job.summary) {
          updateResultsSummary(job.summary);
        }

        // If job is already running, switch view directly to Step 3
        if (job.status === 'running' || job.status === 'queued') {
          goToStep(3);
        }
      }
    } catch (err) {
      console.warn('[API] Could not fetch active job:', err);
    }
  }

  async function startJob() {
    // Read Step 2 Config
    const autoRedeem = dom.cfgAutoRedeem ? dom.cfgAutoRedeem.checked : true;
    const proxy = dom.cfgProxy ? dom.cfgProxy.value.trim() : '';

    const payload = {
      garena_id: state.accountData.garenaId || (dom.authGarenaId ? dom.authGarenaId.value.trim() : ''),
      token_or_url: state.accountData.token || (dom.authRawToken ? dom.authRawToken.value.trim() : ''),
      auto_redeem: autoRedeem,
      proxy: proxy,
    };

    setJobStatus('queued');
    appendLog('กำลังส่งคำสั่งเริ่มงานไปยังเซิร์ฟเวอร์ (POST /api/jobs/start)...', 'info');

    try {
      const resp = await fetch(CONFIG.apiStartJob, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify(payload),
      });

      const result = await resp.json();
      console.log('[API Start Result]', result);

      if (!resp.ok) {
        const errMessage = result.message || result.detail || 'เกิดข้อผิดพลาดในการเริ่มงาน';
        showToast(errMessage, 'error');
        appendLog(`❌ เกิดข้อผิดพลาด: ${errMessage}`, 'error');
        setJobStatus('idle');
        return;
      }

      showToast('เริ่มงานบอทส่งคำตอบเรียบร้อยแล้ว!', 'success');
      appendLog('🚀 เซิร์ฟเวอร์รับคำสั่งเริ่มงานเรียบร้อย (Running)', 'success');
      setJobStatus('running');

      if (result.job && result.job.ref_code && dom.jobRefBadge) {
        dom.jobRefBadge.textContent = result.job.ref_code;
      }
    } catch (err) {
      console.error('[API Start Error]', err);
      showToast('ไม่สามารถเชื่อมต่อเซิร์ฟเวอร์เพื่อเริ่มงานได้', 'error');
      appendLog(`❌ เชื่อมต่อผิดพลาด: ${err.message}`, 'error');
      setJobStatus('idle');
    }
  }

  async function stopJob() {
    if (state.jobStatus !== 'running' && state.jobStatus !== 'queued') return;

    appendLog('กำลังส่งคำสั่งหยุดงาน (POST /api/jobs/stop)...', 'warning');

    try {
      const resp = await fetch(CONFIG.apiStopJob, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify({ job_id: state.activeJobId }),
      });

      const result = await resp.json();
      console.log('[API Stop Result]', result);

      if (!resp.ok) {
        const errMessage = result.message || result.detail || 'ไม่สามารถหยุดงานได้';
        showToast(errMessage, 'error');
        return;
      }

      showToast('ส่งคำสั่งหยุดงานเรียบร้อยแล้ว', 'info');
      appendLog('⏹️ ได้รับการยืนยันการหยุดงานจากเซิร์ฟเวอร์', 'warning');
      setJobStatus('stopped');
    } catch (err) {
      console.error('[API Stop Error]', err);
      showToast('เกิดข้อผิดพลาดในการส่งคำสั่งหยุดงาน', 'error');
    }
  }

  // =========================================================================
  // STEP 4: RESULTS DISPLAY
  // =========================================================================

  function updateResultsSummary(summary) {
    if (!summary) return;
    const passed = summary.chapters_passed || summary.passed_chapters || 0;
    const totalQ = summary.questions_added || summary.questions_answered || summary.total_questions || 0;
    const gold = summary.gold_earned || 0;
    const items = summary.redeemed_items || summary.redeemed_rewards || [];

    if (dom.sumPassedChapters) dom.sumPassedChapters.textContent = `${passed} / 40`;
    if (dom.sumTotalQuestions) dom.sumTotalQuestions.textContent = String(totalQ);
    if (dom.sumGoldEarned) dom.sumGoldEarned.textContent = `+${gold.toLocaleString()}`;
    if (dom.sumRedeemedCount) dom.sumRedeemedCount.textContent = String(items.length);

    if (dom.redeemedItemsList) {
      if (items.length === 0) {
        dom.redeemedItemsList.innerHTML = `
          <div class="p-4 rounded-xl bg-slate-900/40 border border-slate-800 text-center text-xs text-slate-500">
            ยังไม่มีรายการของรางวัลที่แลกในรอบนี้
          </div>
        `;
      } else {
        dom.redeemedItemsList.innerHTML = '';
        items.forEach((item, idx) => {
          const title = item.title || item.name || `Reward #${item.id || idx + 1}`;
          const gCost = item.gold_cost || item.gold || 0;
          const sCost = item.silver_cost || item.silver || 0;

          const row = document.createElement('div');
          row.className = 'p-3 rounded-xl bg-slate-900/70 border border-slate-800 flex items-center justify-between text-xs';
          row.innerHTML = `
            <div class="flex items-center gap-2.5">
              <span class="w-7 h-7 rounded-lg bg-emerald-950 border border-emerald-800 flex items-center justify-center text-sm">🎁</span>
              <div>
                <p class="font-bold text-white">${escapeHtml(title)}</p>
                <p class="text-[11px] text-slate-400">แลกสำเร็จอัตโนมัติ</p>
              </div>
            </div>
            <div class="text-right font-mono text-[11px]">
              <span class="text-arena-gold">-${gCost} Gold</span>
              ${sCost ? `<span class="text-slate-400 ml-1">-${sCost} Silver</span>` : ''}
            </div>
          `;
          dom.redeemedItemsList.appendChild(row);
        });
      }
    }
  }

  // =========================================================================
  // INITIALIZATION
  // =========================================================================

  function init() {
    initDomElements();
    initWebSocket();
    fetchActiveJobState();

    // Drag and Drop events for accounts_vault.json
    if (dom.dropzone) {
      ['dragenter', 'dragover'].forEach((evName) => {
        dom.dropzone.addEventListener(evName, (e) => {
          e.preventDefault();
          e.stopPropagation();
          dom.dropzone.classList.add('border-cyan-500');
        });
      });

      ['dragleave', 'drop'].forEach((evName) => {
        dom.dropzone.addEventListener(evName, (e) => {
          e.preventDefault();
          e.stopPropagation();
          dom.dropzone.classList.remove('border-cyan-500');
        });
      });

      dom.dropzone.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const files = dt && dt.files;
        if (files && files.length > 0) {
          handleVaultUpload({ target: { files } });
        }
      });
    }

    console.log('[RoV Frontend v3.0] Initialized successfully.');
  }

  // Expose public methods
  return {
    init,
    goToStep,
    validateAndProceedToStep2,
    handleVaultUpload,
    startJob,
    stopJob,
    clearLogs,
  };
})();

// Boot on DOM ready
document.addEventListener('DOMContentLoaded', App.init);
