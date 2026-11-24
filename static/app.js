(() => {
  "use strict";

  const JWT_EXTRACT_RE = /(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})/;

  const tabBtnRun = document.getElementById("tabBtnRun");
  const tabBtnVault = document.getElementById("tabBtnVault");
  const tabPanelRun = document.getElementById("tabPanelRun");
  const tabPanelVault = document.getElementById("tabPanelVault");

  const vaultCountBadge = document.getElementById("vaultCountBadge");
  const sessionHeaderBadge = document.getElementById("sessionHeaderBadge");
  const savedSessionBanner = document.getElementById("savedSessionBanner");
  const savedAccountName = document.getElementById("savedAccountName");
  const savedSessionMeta = document.getElementById("savedSessionMeta");
  const clearSessionBtn = document.getElementById("clearSessionBtn");

  const solverForm = document.getElementById("solverForm");
  const garenaIdInput = document.getElementById("garenaIdInput");
  const garenaPasswordInput = document.getElementById("garenaPasswordInput");
  const togglePwBtn = document.getElementById("togglePwBtn");
  const savedAccountsWrap = document.getElementById("savedAccountsWrap");
  const savedAccountsList = document.getElementById("savedAccountsList");

  const jwtTokenInput = document.getElementById("jwtTokenInput");
  const pasteTokenBtn = document.getElementById("pasteTokenBtn");
  const tokenCheckChip = document.getElementById("tokenCheckChip");
  const alertBanner = document.getElementById("alertBanner");
  const runSolverBtn = document.getElementById("runSolverBtn");
  const runBtnIcon = document.getElementById("runBtnIcon");
  const runBtnText = document.getElementById("runBtnText");

  const liveRunBadge = document.getElementById("liveRunBadge");
  const statGold = document.getElementById("statGold");
  const statTotalGold = document.getElementById("statTotalGold");
  const statSilver = document.getElementById("statSilver");
  const statTotalSilver = document.getElementById("statTotalSilver");
  const statPassed = document.getElementById("statPassed");
  const statBreakdown = document.getElementById("statBreakdown");

  const pipelineSteps = document.getElementById("pipelineSteps");
  const progressStatusText = document.getElementById("progressStatusText");
  const progressPercentText = document.getElementById("progressPercentText");
  const progressBarFill = document.getElementById("progressBarFill");

  const solvedFeedCount = document.getElementById("solvedFeedCount");
  const liveChapterList = document.getElementById("liveChapterList");
  const consoleBox = document.getElementById("consoleBox");
  const clearLogBtn = document.getElementById("clearLogBtn");

  const historyList = document.getElementById("historyList");
  const refreshHistoryBtn = document.getElementById("refreshHistoryBtn");
  const vaultSearchInput = document.getElementById("vaultSearchInput");
  const vaultList = document.getElementById("vaultList");

  let activeWs = null;
  let pollTimer = null;
  let vaultDataCache = [];
  let solvedChaptersCount = 0;

  function extractCleanJwt(raw) {
    if (!raw || typeof raw !== "string") return "";
    const m = raw.trim().match(JWT_EXTRACT_RE);
    return m ? m[1] : raw.trim();
  }

  function showAlert(msg, type = "error") {
    if (!msg) {
      alertBanner.classList.add("hidden");
      return;
    }
    alertBanner.textContent = msg;
    alertBanner.className = `alert-banner ${type}`;
  }

  function switchTab(tabName) {
    const isRun = tabName === "run";
    tabBtnRun.classList.toggle("active", isRun);
    tabBtnRun.setAttribute("aria-selected", String(isRun));
    tabBtnVault.classList.toggle("active", !isRun);
    tabBtnVault.setAttribute("aria-selected", String(!isRun));

    tabPanelRun.classList.toggle("hidden", !isRun);
    tabPanelVault.classList.toggle("hidden", isRun);

    if (!isRun) {
      loadHistoryAndVault();
    }
  }

  tabBtnRun.addEventListener("click", () => switchTab("run"));
  tabBtnVault.addEventListener("click", () => switchTab("vault"));

  togglePwBtn.addEventListener("click", () => {
    const isPw = garenaPasswordInput.type === "password";
    garenaPasswordInput.type = isPw ? "text" : "password";
    togglePwBtn.textContent = isPw ? "🙈" : "👁️";
  });

  function appendLog(message, level = "info") {
    const row = document.createElement("div");
    row.className = `log-row log-${level}`;
    const ts = new Date().toLocaleTimeString("th-TH", { hour12: false });
    row.textContent = `[${ts}] ${message}`;
    consoleBox.appendChild(row);
    consoleBox.scrollTop = consoleBox.scrollHeight;
  }

  clearLogBtn.addEventListener("click", () => {
    consoleBox.innerHTML = "";
    appendLog("ล้างหน้าต่างบันทึกเรียบร้อยแล้ว", "info");
  });

  function setPipelinePhase(phase) {
    const order = ["auth", "info", "answer", "completed"];
    const normPhase = phase === "chapters" || phase === "quiz" ? "answer" : phase;
    const curIdx = order.indexOf(normPhase);
    const steps = pipelineSteps.querySelectorAll(".pipe-step");
    steps.forEach((el, idx) => {
      el.classList.remove("active", "done");
      if (normPhase === "completed" || idx < curIdx) {
        el.classList.add("done");
      } else if (idx === curIdx) {
        el.classList.add("active");
      }
    });
  }

  function addChapterToFeed(ch) {
    if (!ch || !ch.chapter_id) return;
    if (solvedChaptersCount === 0) {
      liveChapterList.innerHTML = "";
    }
    solvedChaptersCount += 1;
    solvedFeedCount.textContent = `${solvedChaptersCount} บท`;

    const item = document.createElement("div");
    item.className = "chapter-item";
    item.innerHTML = `
      <div>
        <div class="chapter-item-title">✅ บทที่ ${ch.chapter_id}: ${ch.title}</div>
        <div class="chapter-item-sub">${ch.method || "คลังเฉลย 100%"} · ${ch.questions_count || 0} ข้อ</div>
      </div>
      <span class="chapter-reward-pill">+${ch.gold || 0} Gold · +${ch.silver || 0} Silver</span>
    `;
    liveChapterList.prepend(item);
  }

  function updateProgressUI(stats) {
    if (!stats) return;
    const total = stats.total || 40;
    const doneTotal = (stats.already_done || 0) + (stats.passed || 0);
    const pct = total > 0 ? Math.min(100, Math.round((doneTotal / total) * 100)) : 0;

    statGold.textContent = `+${stats.gold_earned || 0}`;
    statTotalGold.textContent = String(stats.user_gold || 0);
    statSilver.textContent = `+${stats.silver_earned || 0}`;
    statTotalSilver.textContent = String(stats.user_silver || 0);
    statPassed.textContent = `${doneTotal} / ${total}`;
    statBreakdown.textContent = `ผ่านเพิ่ม ${stats.passed || 0} · เคยผ่านแล้ว ${stats.already_done || 0}`;

    progressBarFill.style.width = `${pct}%`;
    progressPercentText.textContent = `${pct}%`;
    if (stats.current_chapter) {
      progressStatusText.textContent = stats.current_chapter;
    }
    if (stats.phase) {
      setPipelinePhase(stats.phase);
    }
    if (stats.latest_chapter) {
      addChapterToFeed(stats.latest_chapter);
    }
  }

  async function refreshSessionStatus() {
    try {
      const resp = await fetch("/api/session");
      if (!resp.ok) return;
      const data = await resp.json();

      if (data.verified_chapters_count) {
        vaultCountBadge.textContent = `⚡ คลังเฉลย ${data.verified_chapters_count}/40 บทพร้อมใช้งาน`;
      }

      if (data.has_session) {
        const mins = data.remaining_seconds ? Math.max(1, Math.round(data.remaining_seconds / 60)) : null;
        const accLabel = data.garena_id || "บัญชีที่ล็อกอินไว้";
        sessionHeaderBadge.textContent = `🟢 เซสชันพร้อม (${accLabel})`;
        sessionHeaderBadge.classList.add("online");

        savedSessionBanner.classList.remove("hidden");
        savedAccountName.textContent = accLabel;
        savedSessionMeta.textContent = mins
          ? `Token ยังใช้ได้อีกประมาณ ${mins} นาที — กดปุ่มด้านล่างเพื่อส่งคำตอบครบ 40 บทได้ทันที`
          : "เซสชันพร้อมใช้งาน — กดปุ่มด้านล่างเพื่อส่งคำตอบครบ 40 บทได้ทันที";

        if (!garenaIdInput.value && data.garena_id && data.garena_id !== "saved_session") {
          garenaIdInput.value = data.garena_id;
        }
      } else {
        sessionHeaderBadge.textContent = "🔒 รอเข้าสู่ระบบ";
        sessionHeaderBadge.classList.remove("online");
        savedSessionBanner.classList.add("hidden");
      }

      const accounts = data.saved_accounts || [];
      if (accounts.length > 0) {
        savedAccountsWrap.classList.remove("hidden");
        savedAccountsList.innerHTML = "";
        accounts.forEach((acc) => {
          const chip = document.createElement("button");
          chip.type = "button";
          chip.className = "acc-chip";
          chip.textContent = `👤 ${acc.garena_id}`;
          chip.addEventListener("click", () => {
            garenaIdInput.value = acc.garena_id;
            showAlert(`เลือกเซสชันของบัญชี '${acc.garena_id}' แล้ว กดปุ่มเริ่มทำงานได้เลย!`, "success");
          });
          savedAccountsList.appendChild(chip);
        });
      } else {
        savedAccountsWrap.classList.add("hidden");
      }
    } catch (_) {}
  }

  clearSessionBtn.addEventListener("click", async () => {
    try {
      await fetch("/api/session", { method: "DELETE" });
      jwtTokenInput.value = "";
      tokenCheckChip.textContent = "ไม่บังคับ";
      tokenCheckChip.classList.remove("valid");
      await refreshSessionStatus();
      appendLog("ล้างเซสชันที่บันทึกไว้เรียบร้อยแล้ว", "info");
    } catch (_) {}
  });

  async function inspectTokenInput() {
    const cleaned = extractCleanJwt(jwtTokenInput.value);
    if (!cleaned) {
      tokenCheckChip.textContent = "ไม่บังคับ";
      tokenCheckChip.classList.remove("valid");
      return;
    }
    if (cleaned !== jwtTokenInput.value.trim()) {
      jwtTokenInput.value = cleaned;
    }
    try {
      const resp = await fetch("/api/inspect-jwt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: cleaned }),
      });
      const info = await resp.json();
      if (info.valid_structure && !info.is_expired) {
        tokenCheckChip.textContent = "✅ Token พร้อมใช้";
        tokenCheckChip.classList.add("valid");
        showAlert("", "success");
      } else if (info.is_expired) {
        tokenCheckChip.textContent = "⚠️ หมดอายุ";
        tokenCheckChip.classList.remove("valid");
      } else {
        tokenCheckChip.textContent = "❌ รูปแบบไม่ถูก";
        tokenCheckChip.classList.remove("valid");
      }
    } catch (_) {}
  }

  jwtTokenInput.addEventListener("input", inspectTokenInput);

  pasteTokenBtn.addEventListener("click", async () => {
    try {
      const clip = await navigator.clipboard.readText();
      if (clip) {
        jwtTokenInput.value = extractCleanJwt(clip);
        await inspectTokenInput();
      }
    } catch (_) {
      jwtTokenInput.focus();
    }
  });

  function setRunningState(isRunning) {
    runSolverBtn.disabled = isRunning;
    if (isRunning) {
      runBtnIcon.textContent = "⏳";
      runBtnText.textContent = "กำลังล็อกอิน & ส่งคำตอบทั้ง 40 บท...";
      liveRunBadge.textContent = "⚡ กำลังทำงานสด";
      liveRunBadge.className = "live-indicator running";
    } else {
      runBtnIcon.textContent = "🚀";
      runBtnText.textContent = "ล็อกอิน & ส่งคำตอบครบ 40 บททันที";
    }
  }

  function connectTaskStream(taskId) {
    if (activeWs) {
      try {
        activeWs.close();
      } catch (_) {}
    }
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${proto}//${window.location.host}/ws/tasks/${taskId}`;
    let lastLogIndex = -1;

    activeWs = new WebSocket(wsUrl);
    activeWs.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        if (msg.type === "snapshot") {
          const d = msg.data || {};
          (d.logs || []).forEach((l) => {
            if (l.index > lastLogIndex) {
              lastLogIndex = l.index;
              appendLog(l.message, l.level);
            }
          });
          if (d.progress) updateProgressUI(d.progress);
        } else if (msg.type === "log") {
          const l = msg.data || {};
          if (typeof l.index !== "number" || l.index > lastLogIndex) {
            if (typeof l.index === "number") lastLogIndex = l.index;
            appendLog(l.message, l.level);
          }
        } else if (msg.type === "progress") {
          updateProgressUI(msg.data);
        } else if (msg.type === "completed") {
          setRunningState(false);
          liveRunBadge.textContent = "✅ เสร็จสมบูรณ์";
          liveRunBadge.className = "live-indicator done";
          if (msg.data && msg.data.progress) updateProgressUI(msg.data.progress);
          const stats = (msg.data && msg.data.result && msg.data.result.stats) || {};
          showAlert(
            `🎉 ส่งคำตอบครบเรียบร้อย! ผ่านเพิ่ม ${stats.passed || 0} บท รับรางวัล +${stats.gold_earned || 0} Gold, +${stats.silver_earned || 0} Silver`,
            "success"
          );
          refreshSessionStatus();
        } else if (msg.type === "failed") {
          setRunningState(false);
          liveRunBadge.textContent = "⚠️ หยุดทำงาน";
          liveRunBadge.className = "live-indicator";
          const err = (msg.data && msg.data.error) || "การทำงานหยุดลง";
          showAlert(err, "error");
          refreshSessionStatus();
        }
      } catch (_) {}
    };

    activeWs.onerror = () => {
      startPollingFallback(taskId);
    };
  }

  function startPollingFallback(taskId) {
    if (pollTimer) clearInterval(pollTimer);
    let seenLogs = 0;
    pollTimer = setInterval(async () => {
      try {
        const resp = await fetch(`/api/status/${taskId}`);
        if (!resp.ok) return;
        const snap = await resp.json();
        const logs = snap.logs || [];
        while (seenLogs < logs.length) {
          const l = logs[seenLogs++];
          appendLog(l.message, l.level);
        }
        if (snap.progress) updateProgressUI(snap.progress);
        if (snap.status === "completed" || snap.status === "failed") {
          clearInterval(pollTimer);
          setRunningState(false);
          refreshSessionStatus();
        }
      } catch (_) {}
    }, 1000);
  }

  solverForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    showAlert("");
    solvedChaptersCount = 0;
    liveChapterList.innerHTML = "";
    solvedFeedCount.textContent = "0 บท";
    setRunningState(true);
    setPipelinePhase("auth");

    const rawId = garenaIdInput.value.trim();
    const rawPw = garenaPasswordInput.value.trim();
    const rawTok = extractCleanJwt(jwtTokenInput.value);

    try {
      const resp = await fetch("/api/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          garena_id: rawId || null,
          garena_password: rawPw || null,
          jwt_token: rawTok || null,
        }),
      });
      const data = await resp.json();
      if (!resp.ok || !data.task_id) {
        setRunningState(false);
        showAlert(data.detail || data.error || "ไม่สามารถเริ่มงานได้", "error");
        return;
      }
      connectTaskStream(data.task_id);
    } catch (err) {
      setRunningState(false);
      showAlert(`เชื่อมต่อเซิร์ฟเวอร์ไม่สำเร็จ: ${err}`, "error");
    }
  });

  function renderVault(filterText = "") {
    const q = filterText.trim().toLowerCase();
    const filtered = vaultDataCache.filter((ch) => {
      if (!q) return true;
      if (String(ch.chapter_id).includes(q) || `บทที่ ${ch.chapter_id}`.includes(q)) return true;
      return (ch.qa || []).some(
        (item) =>
          (item.question || "").toLowerCase().includes(q) ||
          (item.answer || "").toLowerCase().includes(q)
      );
    });

    if (filtered.length === 0) {
      vaultList.innerHTML = `<div class="empty-feed">ไม่พบบทเรียนหรือคำถามที่ตรงกับ "${filterText}"</div>`;
      return;
    }

    vaultList.innerHTML = filtered
      .map((ch) => {
        const qaHtml = (ch.qa || [])
          .map(
            (item, idx) => `
            <div class="vault-qa-item">
              <div class="vault-q"><strong>ข้อ ${idx + 1}:</strong> ${item.question}</div>
              <div class="vault-a">✅ ตอบ: ${item.answer}</div>
            </div>
          `
          )
          .join("");
        return `
          <article class="vault-chapter-card">
            <div class="vault-ch-head">
              <span class="vault-ch-badge">📘 บทที่ ${ch.chapter_id}</span>
              <span class="vault-ch-count">${ch.questions_count} ข้อ · ยืนยันแล้ว 100%</span>
            </div>
            ${qaHtml}
          </article>
        `;
      })
      .join("");
  }

  async function loadHistoryAndVault() {
    try {
      const [hResp, vResp] = await Promise.all([fetch("/api/history"), fetch("/api/vault")]);
      if (hResp.ok) {
        const hData = await hResp.json();
        const list = hData.history || [];
        if (list.length === 0) {
          historyList.innerHTML = `<div class="empty-feed">ยังไม่มีประวัติการส่งคำตอบ</div>`;
        } else {
          historyList.innerHTML = list
            .map(
              (h) => `
              <div class="history-item">
                <div class="history-top">
                  <span class="history-acc">👤 ${h.garena_id || "ผู้เล่น RoV"}</span>
                  <span class="history-time">${h.timestamp || ""}</span>
                </div>
                <div class="history-stats">
                  ✅ ผ่านเพิ่ม <strong>${h.passed || 0}</strong> บท (เคยผ่านแล้ว ${h.already_done || 0}/${h.total || 40} บท)<br/>
                  🪙 <strong>+${h.gold_earned || 0} Gold</strong> · 🥈 <strong>+${h.silver_earned || 0} Silver</strong>
                </div>
              </div>
            `
            )
            .join("");
        }
      }
      if (vResp.ok) {
        const vData = await vResp.json();
        vaultDataCache = vData.chapters || [];
        renderVault(vaultSearchInput.value);
      }
    } catch (_) {}
  }

  vaultSearchInput.addEventListener("input", () => {
    renderVault(vaultSearchInput.value);
  });

  refreshHistoryBtn.addEventListener("click", loadHistoryAndVault);

  refreshSessionStatus();
  loadHistoryAndVault();
})();
