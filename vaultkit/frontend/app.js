(function () {
  "use strict";

  var view = document.getElementById("view");
  var idleEl = document.getElementById("idle");
  var idleControl = document.getElementById("idle-control");
  var idleSelect = document.getElementById("idle-select");
  var lockBtn = document.getElementById("lock-btn");
  var foot = document.getElementById("foot-path");
  var toastEl = document.getElementById("toast");
  var dialog = document.getElementById("dialog");
  var connEl = document.getElementById("conn");
  var connText = document.getElementById("conn-text");
  var connRetry = document.getElementById("conn-retry");
  var lockwarn = document.getElementById("lockwarn");
  var pokeBtn = document.getElementById("poke");

  var status = null;
  var mode = "boot";
  var epoch = 0;
  var remain = -1;
  var hideTimer = 0;
  var revealTick = 0;
  var toastTimer = 0;
  var lastTouch = 0;
  var libraryKind = "all";
  var libraryQuery = "";
  var librarySort = "updated";
  var knownTitles = [];
  var editorDirty = false;
  var editorCheckTimer = 0;
  var dialogPrevFocus = null;

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    var key;
    attrs = attrs || {};
    for (key in attrs) {
      if (!Object.prototype.hasOwnProperty.call(attrs, key)) continue;
      var value = attrs[key];
      if (value == null || value === false) continue;
      if (key === "class") node.className = value;
      else if (typeof value === "function" && key.indexOf("on") === 0) node.addEventListener(key.slice(2), value);
      else node.setAttribute(key, value === true ? "" : String(value));
    }
    appendChildren(node, children || []);
    return node;
  }

  function appendChildren(node, children) {
    var i;
    for (i = 0; i < children.length; i += 1) {
      var child = children[i];
      if (child == null || child === false) continue;
      if (Array.isArray(child)) appendChildren(node, child);
      else node.append(child);
    }
  }

  function banner(text, kind) {
    return el("p", {class: "banner " + kind}, [text]);
  }

  function toast(text, kind) {
    window.clearTimeout(toastTimer);
    if (!text) {
      toastEl.hidden = true;
      toastEl.replaceChildren();
      return;
    }
    var dismiss = el("button", {type: "button", class: "toast-close", "aria-label": "关闭提示", onclick: function () { toast("", "ok"); }}, ["关闭"]);
    toastEl.hidden = false;
    toastEl.className = "toast " + (kind || "ok");
    toastEl.replaceChildren(el("span", {class: "toast-text"}, [text]), dismiss);
    toastTimer = window.setTimeout(function () {
      toastEl.hidden = true;
      toastEl.replaceChildren();
    }, kind === "bad" ? 8000 : 4200);
  }

  function setMode(next) {
    mode = next;
    if (next !== "editor") editorDirty = false;
    document.body.dataset.mode = next === "list" || next === "editor" || next === "passwd" ? "library" : "gate";
  }

  function sensitiveInput(type, extra) {
    return el("input", Object.assign({
      type: type || "text",
      autocomplete: "off",
      spellcheck: "false",
      autocapitalize: "none",
      autocorrect: "off",
      writingsuggestions: "false",
      "data-1p-ignore": "true",
      "data-lpignore": "true"
    }, extra || {}));
  }

  function sensitiveArea(extra) {
    return el("textarea", Object.assign({
      autocomplete: "off",
      spellcheck: "false",
      autocapitalize: "none",
      autocorrect: "off",
      writingsuggestions: "false",
      "data-1p-ignore": "true"
    }, extra || {}));
  }

  function field(label, node, hint, optional) {
    return el("label", {class: "field"}, [
      el("span", {class: "field-label"}, [label, optional ? el("em", null, ["选填"]) : null]),
      node,
      hint || null
    ]);
  }

  // Keeps the label for screen readers when the section heading already names the field.
  function bare(node) {
    node.classList.add("bare");
    return node;
  }

  function passwordLine(autocompleteValue) {
    var node = sensitiveInput("password", {autocomplete: autocompleteValue || "off"});
    var toggle = el("button", {type: "button", class: "peek"}, ["显示"]);
    var caps = el("p", {class: "caps-hint", hidden: true}, ["大写锁定（Caps Lock）开着，注意密码大小写"]);
    function capsUpdate(event) {
      if (event.getModifierState) caps.hidden = !event.getModifierState("CapsLock");
    }
    node.addEventListener("keydown", capsUpdate);
    node.addEventListener("keyup", capsUpdate);
    node.addEventListener("blur", function () { caps.hidden = true; });
    toggle.addEventListener("click", function () {
      var hidden = node.type === "password";
      node.type = hidden ? "text" : "password";
      toggle.textContent = hidden ? "隐藏" : "显示";
    });
    return {
      wrap: el("div", {class: "passcol"}, [el("div", {class: "passline"}, [node, toggle]), caps]),
      node: node
    };
  }

  function take(node) {
    var value = node.value;
    node.value = "";
    return value;
  }

  function bindEnter(node, button) {
    node.addEventListener("keydown", function (event) {
      if (event.key === "Enter" && !event.isComposing) {
        event.preventDefault();
        button.click();
      }
    });
  }

  function formatRemain(seconds) {
    var total = Math.max(0, seconds | 0);
    var minutes = Math.floor(total / 60);
    var rest = total % 60;
    return minutes + ":" + (rest < 10 ? "0" : "") + rest;
  }

  function kindName(kind) {
    if (kind === "mnemonic") return "助记词";
    if (kind === "card") return "银行卡";
    return "机密";
  }

  function groupCard(number) {
    var digits = String(number || "");
    var parts = [];
    var i;
    for (i = 0; i < digits.length; i += 4) parts.push(digits.slice(i, i + 4));
    return parts.join(" ");
  }

  function luhnOk(digits) {
    var total = 0;
    var alt = false;
    var i;
    for (i = digits.length - 1; i >= 0; i -= 1) {
      var d = digits.charCodeAt(i) - 48;
      if (d < 0 || d > 9) return false;
      if (alt) {
        d *= 2;
        if (d > 9) d -= 9;
      }
      total += d;
      alt = !alt;
    }
    return total % 10 === 0;
  }

  function timeAgo(iso) {
    var t = Date.parse(iso || "");
    if (!t || isNaN(t)) return "";
    var s = Math.max(0, Math.floor((Date.now() - t) / 1000));
    if (s < 60) return "刚刚";
    if (s < 3600) return Math.floor(s / 60) + " 分钟前";
    if (s < 86400) return Math.floor(s / 3600) + " 小时前";
    if (s < 2592000) return Math.floor(s / 86400) + " 天前";
    var d = new Date(t);
    return d.getFullYear() + " 年 " + (d.getMonth() + 1) + " 月 " + d.getDate() + " 日";
  }

  function normWordList(value) {
    return String(value || "").toLowerCase().split(/\s+/).filter(Boolean);
  }

  function wordCount(value) {
    var text = String(value || "").trim();
    if (!text) return 0;
    return text.split(/\s+/).length;
  }

  function countHint(count) {
    var ok = count === 12 || count === 15 || count === 18 || count === 21 || count === 24;
    var text = count ? ("现在 " + count + " 个词") : "还没有词";
    if (!ok) text += "，常见是 12、15、18、21 或 24";
    return el("p", {class: ok ? "fine" : "hint"}, [text]);
  }

  async function runBusy(button, label, fn) {
    var previous = button.textContent;
    button.disabled = true;
    button.textContent = label;
    try {
      return await fn();
    } finally {
      button.disabled = false;
      if (button.isConnected) button.textContent = previous;
    }
  }

  function wipeRevealed() {
    window.clearTimeout(hideTimer);
    window.clearInterval(revealTick);
    revealTick = 0;
    document.querySelectorAll("[data-secret]").forEach(function (node) {
      node.textContent = "";
      node.remove();
    });
  }

  function clearClipboard() {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText("").catch(function () {});
    }
  }

  function closeDialog() {
    wipeRevealed();
    dialog.hidden = true;
    dialog.className = "";
    dialog.replaceChildren();
    if (dialogPrevFocus && dialogPrevFocus.isConnected) dialogPrevFocus.focus();
    dialogPrevFocus = null;
  }

  function wipeSensitive() {
    closeDialog();
    document.querySelectorAll("input, textarea").forEach(function (node) {
      node.value = "";
    });
    document.querySelectorAll("[data-ephemeral]").forEach(function (node) {
      node.textContent = "";
    });
    toast("", "ok");
  }

  function dialogFocusables(root) {
    return Array.prototype.filter.call(
      root.querySelectorAll("button, input, textarea, select, a[href], [tabindex]:not([tabindex='-1'])"),
      function (node) { return !node.disabled && node.offsetWidth > 0; }
    );
  }

  // Opens a drawer from the right; short confirmations pass variant "modal" for a centered box.
  function openDialog(title, children, opts) {
    opts = opts || {};
    wipeRevealed();
    if (dialog.hidden) dialogPrevFocus = document.activeElement;
    var modal = opts.variant === "modal";
    var close = el("button", {type: "button", class: "link sheet-close", "aria-label": "关闭", onclick: closeDialog}, ["关闭", el("kbd", null, ["Esc"])]);
    var sheet = el("div", {class: "sheet " + (modal ? "modal" : "drawer"), role: "dialog", "aria-modal": "true", "aria-labelledby": "sheet-title"}, [
      el("header", {class: "sheet-head"}, [
        el("div", null, [
          opts.kicker ? el("p", {class: "kicker"}, [opts.kicker]) : null,
          el("h2", {id: "sheet-title"}, [title])
        ]),
        modal ? null : close
      ]),
      el("div", {class: "sheet-body"}, children)
    ]);
    var backdrop = el("div", {class: modal ? "backdrop center" : "backdrop"}, [sheet]);
    backdrop.addEventListener("click", function (event) {
      if (event.target === backdrop) closeDialog();
    });
    dialog.className = "dialog";
    dialog.replaceChildren(backdrop);
    dialog.hidden = false;
    var first = dialogFocusables(sheet).filter(function (node) { return node !== close; })[0];
    if (first) first.focus();
    return sheet;
  }

  function touchAuth() { epoch += 1; }

  async function api(path, body) {
    var response;
    try {
      response = await fetch(path, {
        method: "POST",
        credentials: "same-origin",
        cache: "no-store",
        headers: {"Content-Type": "application/json", "X-Offline-Vault": "1"},
        body: JSON.stringify(body || {})
      });
    } catch (err) {
      var network = new Error("连不上本机服务。确认运行保险库的那个窗口还在。");
      network.code = "network";
      throw network;
    }
    var data = null;
    try { data = await response.json(); }
    catch (err) {
      var bad = new Error("本机服务返回了无法识别的数据");
      bad.code = "bad-response";
      throw bad;
    }
    if (!response.ok || !data.ok) {
      var error = new Error((data && data.error) || "操作失败");
      error.code = data && data.code;
      error.status = response.status;
      if (data && data.locked) {
        touchAuth();
        wipeSensitive();
        if (status) status.unlocked = false;
        showUnlock(data.error || "已锁定");
      }
      throw error;
    }
    return data;
  }

  function paintIdle() {
    if (remain < 0) {
      idleEl.textContent = "";
      idleControl.classList.remove("soon");
      return;
    }
    idleEl.textContent = formatRemain(remain);
    idleControl.classList.toggle("soon", remain <= 30);
  }

  function applyStatus(data) {
    status = data;
    foot.replaceChildren(
      data.path ? el("span", {title: data.path}, [data.path]) : "",
      data.fingerprint ? el("span", null, ["校验 ", el("code", null, [data.fingerprint])]) : ""
    );
    lockBtn.hidden = !data.unlocked;
    idleControl.hidden = !data.unlocked;
    if (data.unlocked) {
      remain = data.idle_remaining;
      if (idleSelect.querySelector('option[value="' + data.idle_seconds + '"]')) {
        idleSelect.value = String(data.idle_seconds);
      }
    } else {
      remain = -1;
    }
    paintIdle();
  }

  function setConn(message) {
    if (!message) {
      if (!connEl.hidden) connEl.hidden = true;
      return;
    }
    connText.textContent = message;
    connEl.hidden = false;
  }

  connRetry.addEventListener("click", function () { poll(); });

  async function poll() {
    var seen = epoch;
    try {
      var data = await api("/api/status", {});
      if (seen !== epoch) return;
      setConn("");
      applyStatus(data);
      if (mode === "boot") {
        showHome();
        return;
      }
      if (!data.unlocked && mode !== "setup" && mode !== "unlock") {
        wipeSensitive();
        showUnlock(data.notice || "已锁定");
      } else if (data.notice && mode === "list") {
        toast(data.notice, "warn");
      }
    } catch (err) {
      if (seen !== epoch) return;
      if (err.code === "locked") return;
      idleEl.textContent = "";
      setConn(err.code === "network" ? "和本机服务失去联系。确认运行保险库的那个终端窗口还开着。" : (err.message || "状态刷新失败"));
    }
  }

  function showHome() {
    if (!status || !status.vault_exists) showSetup();
    else if (!status.unlocked) showUnlock("");
    else showList("");
  }

  function locationBanner() {
    if (status && status.location_warning) return banner(status.location_warning, "warn");
    return null;
  }

  function specRow(label, value) {
    return el("div", null, [el("dt", null, [label]), el("dd", null, [value])]);
  }

  function gatePage(title, lede, body, withSpec) {
    return el("section", {class: "gate"}, [
      el("header", {class: "gate-head"}, [el("h2", null, [title]), el("p", {class: "lede"}, [lede])]),
      el("div", {class: "gate-body"}, body),
      withSpec ? el("dl", {class: "spec"}, [
        specRow("加密", "AES-256-GCM"),
        specRow("密钥派生", "Argon2id"),
        specRow("网络", "只监听 127.0.0.1，不加载外部资源")
      ]) : null
    ]);
  }

  function showSetup() {
    setMode("setup");
    toast("", "ok");
    var first = passwordLine("new-password");
    var second = passwordLine("new-password");
    var chips = el("ol", {class: "seed", "data-ephemeral": "1", hidden: true}, []);
    var message = el("p", {class: "banner bad", hidden: true}, []);
    var button = el("button", {type: "button", class: "btn primary block"}, ["创建保险库"]);
    var suggestion = "";
    var suggestActions = el("div", {class: "suggest-actions", hidden: true}, [
      el("button", {type: "button", class: "btn", onclick: function () {
        if (!suggestion) return;
        first.node.value = suggestion;
        second.node.value = suggestion;
        first.node.focus();
      }}, ["填入上面两栏"]),
      el("button", {type: "button", class: "link muted", onclick: function () {
        suggestion = "";
        chips.replaceChildren();
        chips.hidden = true;
        suggestActions.hidden = true;
      }}, ["擦掉"])
    ]);
    bindEnter(first.node, button);
    bindEnter(second.node, button);
    function paintChips(words) {
      chips.hidden = false;
      suggestActions.hidden = false;
      chips.replaceChildren();
      words.forEach(function (word, index) {
        chips.append(el("li", null, [el("i", null, [String(index + 1)]), word]));
      });
    }
    button.addEventListener("click", function () {
      message.hidden = true;
      if (first.node.value !== second.node.value) {
        message.hidden = false;
        message.textContent = "两次输入的主密码不一致";
        return;
      }
      runBusy(button, "正在创建，大约需要一秒…", async function () {
        var password = first.node.value;
        var confirm = second.node.value;
        first.node.value = "";
        second.node.value = "";
        suggestion = "";
        chips.replaceChildren();
        chips.hidden = true;
        suggestActions.hidden = true;
        touchAuth();
        try {
          await api("/api/create", {password: password, confirm: confirm});
          password = "";
          confirm = "";
          await poll();
          showList("保险库已创建。主密码没有备份，丢了就打不开。");
        } catch (err) {
          password = "";
          confirm = "";
          if (err.code === "locked") return;
          message.hidden = false;
          message.textContent = err.message;
        }
      });
    });
    var generate = el("button", {type: "button", class: "link", onclick: function (event) {
      var own = event.currentTarget;
      runBusy(own, "正在生成…", async function () {
        try {
          var data = await api("/api/suggest-password", {});
          suggestion = data.password;
          paintChips(suggestion.split(" "));
        } catch (err) {
          message.hidden = false;
          message.textContent = err.message;
        }
      });
    }}, ["生成 8 个随机词"]);
    view.replaceChildren(gatePage("新建保险库", "主密码按你输入的原样使用，区分大小写，空格也算。建议用 8 个随机词，并马上手抄到纸上。", [
      locationBanner(),
      field("主密码", first.wrap),
      field("再输入一次", second.wrap),
      el("div", {class: "suggest"}, [
        el("div", {class: "suggest-head"}, [el("span", null, ["想不好主密码？"]), generate]),
        chips,
        suggestActions,
        el("p", {class: "fine"}, ["这组词不会写进保险库。关掉页面，没抄下来就没了。不要让浏览器把它存进会同步的密码库。"])
      ]),
      message,
      button
    ], true));
    first.node.focus();
  }

  function showUnlock(notice) {
    setMode("unlock");
    libraryQuery = "";
    libraryKind = "all";
    closeDialog();
    var pass = passwordLine("current-password");
    var message = el("p", {class: "banner bad", hidden: !notice}, notice ? [notice] : []);
    var button = el("button", {type: "button", class: "btn primary block"}, ["解锁"]);
    bindEnter(pass.node, button);
    button.addEventListener("click", function () {
      message.hidden = true;
      runBusy(button, "正在核对主密码…", async function () {
        var password = take(pass.node);
        touchAuth();
        try {
          await api("/api/unlock", {password: password});
          password = "";
          await poll();
          showList("");
        } catch (err) {
          password = "";
          if (err.code === "locked") return;
          message.hidden = false;
          message.textContent = err.message;
          pass.node.focus();
        }
      });
    });
    view.replaceChildren(gatePage("解锁", "解锁后只能看到标题。助记词、卡号和备注要再输入一次主密码才显示。", [
      locationBanner(),
      field("主密码", pass.wrap),
      message,
      button
    ], true));
    pass.node.focus();
  }

  function matches(entry) {
    if (libraryKind !== "all" && entry.kind !== libraryKind) return false;
    if (!libraryQuery) return true;
    return String(entry.title || "").toLowerCase().indexOf(libraryQuery) !== -1;
  }

  function sortedEntries(list) {
    var out = list.filter(matches);
    if (librarySort === "title") {
      out.sort(function (a, b) {
        return String(a.title || "").localeCompare(String(b.title || ""), "zh-Hans-CN");
      });
    } else {
      out.sort(function (a, b) {
        return String(b.updated_at || "").localeCompare(String(a.updated_at || ""));
      });
    }
    return out;
  }

  async function showList(message) {
    setMode("list");
    closeDialog();
    if (message) toast(message, "ok");
    var data;
    try {
      data = await api("/api/entries/list", {});
    } catch (err) {
      if (err.code === "locked") return;
      view.replaceChildren(banner(err.message, "bad"));
      return;
    }
    var entries = data.entries || [];
    knownTitles = entries.map(function (entry) {
      return {id: entry.id, title: String(entry.title || "").trim().toLowerCase()};
    });
    var counts = {all: entries.length, mnemonic: 0, card: 0, secret: 0};
    entries.forEach(function (entry) {
      if (counts[entry.kind] != null) counts[entry.kind] += 1;
    });
    var search = sensitiveInput("text", {placeholder: "搜索标题", value: libraryQuery, "aria-label": "搜索标题，按 / 聚焦"});
    var cards = el("div", null, []);
    function paintCards() {
      var visible = sortedEntries(entries);
      if (!entries.length) {
        cards.replaceChildren(el("div", {class: "empty"}, [
          el("p", null, ["还没有条目。先放进一条你最不想明文留在磁盘上的内容。"]),
          el("div", {class: "actions"}, [
            el("button", {type: "button", class: "btn", onclick: function () { showEditor("mnemonic", null); }}, ["添加助记词"]),
            el("button", {type: "button", class: "btn", onclick: function () { showEditor("card", null); }}, ["添加银行卡"]),
            el("button", {type: "button", class: "btn", onclick: function () { showEditor("secret", null); }}, ["添加其他机密"])
          ])
        ]));
        return;
      }
      if (!visible.length) {
        cards.replaceChildren(el("p", {class: "empty"}, ["没有标题匹配。搜索只看标题，不会翻出正文。"]));
        return;
      }
      cards.replaceChildren.apply(cards, visible.map(entryRow));
    }
    search.addEventListener("input", function () {
      libraryQuery = search.value.trim().toLowerCase();
      paintCards();
    });
    function chip(kind, label) {
      var button = el("button", {type: "button"}, [label, el("span", {class: "n"}, [String(counts[kind])])]);
      function sync() { button.setAttribute("aria-pressed", libraryKind === kind ? "true" : "false"); }
      sync();
      button.addEventListener("click", function () {
        libraryKind = kind;
        filters.querySelectorAll("button").forEach(function (node) {
          node.setAttribute("aria-pressed", node === button ? "true" : "false");
        });
        paintCards();
      });
      return button;
    }
    var filters = el("div", {class: "tabs"}, [
      chip("all", "全部"),
      chip("mnemonic", "助记词"),
      chip("card", "银行卡"),
      chip("secret", "机密")
    ]);
    var sortBtn = el("button", {type: "button", class: "link muted sort"}, []);
    function paintSortBtn() {
      sortBtn.textContent = librarySort === "title" ? "排序：按标题" : "排序：最近更新";
      sortBtn.setAttribute("aria-pressed", librarySort === "title" ? "true" : "false");
    }
    sortBtn.addEventListener("click", function () {
      librarySort = librarySort === "title" ? "updated" : "title";
      paintSortBtn();
      paintCards();
    });
    paintSortBtn();
    paintCards();
    function addButton(kind, label) {
      return el("button", {type: "button", class: "btn primary", "aria-label": "新建" + label, onclick: function () { showEditor(kind, null); }}, [label]);
    }
    view.replaceChildren(el("div", {class: "library"}, [
      locationBanner(),
      el("div", {class: "lib-head"}, [
        el("h2", null, ["条目", el("span", {class: "num"}, [String(entries.length)])]),
        el("div", {class: "lib-actions"}, [
          el("button", {type: "button", class: "link muted", onclick: function () { showPasswd(); }}, ["更换主密码"]),
          el("div", {class: "newgroup", role: "group", "aria-label": "新建条目"}, [
            el("span", {class: "newgroup-label", "aria-hidden": "true"}, ["新建"]),
            addButton("mnemonic", "助记词"),
            addButton("card", "银行卡"),
            addButton("secret", "机密")
          ])
        ])
      ]),
      el("div", {class: "lib-bar"}, [
        filters,
        el("div", {class: "lib-tools"}, [
          sortBtn,
          el("label", {class: "search"}, [search, el("kbd", {"aria-hidden": "true"}, ["/"])])
        ])
      ]),
      entries.length ? el("div", {class: "ledger-head", "aria-hidden": "true"}, [
        el("span", null, ["类型"]),
        el("span", null, ["标题"]),
        el("span", null, ["摘要"]),
        el("span", null, ["更新"]),
        el("span", null, ["操作"])
      ]) : null,
      cards,
      el("p", {class: "lib-note"}, ["解锁后只显示标题和摘要。查看、修改、删除都要再输入一次主密码。"])
    ]));
  }

  function entryRow(entry) {
    var ago = timeAgo(entry.updated_at);
    var name = "「" + entry.title + "」";
    return el("article", {class: "row"}, [
      el("span", {class: "tag"}, [kindName(entry.kind)]),
      el("h3", {class: "row-title", title: entry.title}, [entry.title]),
      el("p", {class: "row-hint"}, [entry.hint || "没有摘要"]),
      el("p", {class: "row-time"}, [ago || "—"]),
      el("div", {class: "row-actions"}, [
        el("button", {type: "button", class: "link strong", "aria-label": "查看" + name, onclick: function () { openReveal(entry); }}, ["查看"]),
        el("button", {type: "button", class: "link muted", "aria-label": "修改" + name, onclick: function () { startEdit(entry); }}, ["修改"]),
        el("button", {type: "button", class: "link danger", "aria-label": "删除" + name, onclick: function () { openDelete(entry); }}, ["删除"])
      ])
    ]);
  }

  function entryFacts(entry) {
    var ago = timeAgo(entry.updated_at);
    return el("dl", {class: "facts"}, [
      kvRow("类型", kindName(entry.kind)),
      kvRow("摘要", entry.hint || "没有摘要"),
      ago ? kvRow("更新", ago) : null
    ]);
  }

  function openReveal(entry) {
    var pass = passwordLine("current-password");
    var message = el("p", {class: "banner bad", hidden: true}, []);
    var result = el("div", null, []);
    var button = el("button", {type: "button", class: "btn primary"}, ["显示内容"]);
    var ask = el("div", {class: "stack"}, [
      el("p", {class: "lede"}, ["再输入主密码。明文大约 30 秒后从页面上擦掉，按 Esc 可以马上擦掉。"]),
      field("主密码", pass.wrap),
      message,
      el("div", {class: "actions"}, [
        button,
        el("button", {type: "button", class: "link muted", onclick: closeDialog}, ["取消"])
      ])
    ]);
    bindEnter(pass.node, button);
    button.addEventListener("click", function () {
      message.hidden = true;
      runBusy(button, "正在核对…", async function () {
        var password = take(pass.node);
        try {
          var data = await api("/api/entries/reveal", {id: entry.id, password: password});
          password = "";
          ask.hidden = true;
          paintSecret(result, data.entry, function () { ask.hidden = false; });
          data.entry = null;
          data = null;
        } catch (err) {
          password = "";
          if (err.code === "locked") return;
          message.hidden = false;
          message.textContent = err.message;
          pass.node.focus();
        }
      });
    });
    openDialog(entry.title, [entryFacts(entry), ask, result], {kicker: "查看"});
    pass.node.focus();
  }

  function paintSecret(container, entry, onWipe) {
    var secret = entry.secret || {};
    var bits = [];
    var details = [];
    var hold = {entry: entry};
    var left = 30;
    var bar = el("i", null, []);
    var meter = el("div", {class: "meter"}, [bar]);
    var countdown = el("span", null, ["30 秒后擦掉"]);
    if (entry.kind === "mnemonic") {
      var words = String(secret.words || "").split(/\s+/).filter(Boolean);
      var grid = el("ol", {class: "words"}, []);
      words.forEach(function (word, index) {
        grid.append(el("li", null, [el("i", null, [String(index + 1)]), el("span", null, [word])]));
      });
      bits.push(grid);
      bits.push(banner(secret.verified ? "英文 BIP39 校验通过。" : "这条助记词保存时没有通过英文 BIP39 校验。", secret.verified ? "ok" : "warn"));
      details.push(kvRow("BIP39 口令", secret.passphrase || "没有（不是主密码）", !!secret.passphrase));
      if (secret.address_hint) details.push(kvRow("核对用地址", secret.address_hint, true));
    } else if (entry.kind === "card") {
      bits.push(el("p", {class: "cardno"}, [groupCard(secret.number)]));
      details.push(kvRow("银行", secret.bank || "—"));
      details.push(kvRow("持卡人", secret.holder || "—"));
      details.push(kvRow("有效期", secret.expiry || "—", true));
      if (secret.cvv) details.push(kvRow("CVV", secret.cvv, true));
      if (secret.pin) details.push(kvRow("卡密码", secret.pin, true));
      if (secret.luhn_ok === false) bits.push(banner("卡号没通过 Luhn 校验，请核对是不是抄错了。", "warn"));
    } else {
      bits.push(el("div", {class: "secret-text"}, [secret.body || ""]));
    }
    if (secret.note) details.push(kvRow("备注", secret.note));
    if (details.length) bits.push(el("dl", {class: "kv"}, details));
    var copyBtn = el("button", {type: "button", class: "btn"}, ["复制明文"]);
    copyBtn.addEventListener("click", async function () {
      if (!hold.entry || !navigator.clipboard || !navigator.clipboard.writeText) {
        copyBtn.textContent = "浏览器没有允许复制，请手抄";
        return;
      }
      try {
        await navigator.clipboard.writeText(secretText(hold.entry));
        copyBtn.textContent = "已复制，用完请清掉剪贴板";
      } catch (err) {
        copyBtn.textContent = "浏览器没有允许复制，请手抄";
      }
    });
    var wipeBtn = el("button", {type: "button", class: "btn", onclick: function () {
      hold.entry = null;
      clearClipboard();
      closeDialog();
    }}, ["现在擦掉"]);
    bits.push(el("div", {class: "actions"}, [copyBtn, wipeBtn]));
    container.replaceChildren(el("div", {class: "secret-block", "data-secret": "1"}, [
      el("div", {class: "timer"}, [countdown, meter])
    ].concat(bits)));
    wipeBtn.focus();
    window.clearTimeout(hideTimer);
    window.clearInterval(revealTick);
    revealTick = window.setInterval(function () {
      left -= 1;
      if (left <= 0) {
        hold.entry = null;
        wipeRevealed();
        if (container.isConnected) {
          container.append(el("p", {class: "fine"}, ["明文已从页面擦掉。"]));
          if (onWipe) onWipe();
        }
        clearClipboard();
        return;
      }
      countdown.textContent = left + " 秒后擦掉";
      bar.style.transform = "scaleX(" + (left / 30) + ")";
      if (left <= 5) meter.classList.add("low");
    }, 1000);
  }

  function kvRow(label, value, mono) {
    return el("div", null, [el("dt", null, [label]), el("dd", {class: mono ? "mono" : null}, [value])]);
  }

  function secretText(entry) {
    var secret = entry.secret || {};
    if (entry.kind === "mnemonic") {
      var lines = [secret.words || ""];
      if (secret.passphrase) lines.push("BIP39 passphrase: " + secret.passphrase);
      if (secret.address_hint) lines.push(secret.address_hint);
      if (secret.note) lines.push(secret.note);
      return lines.join("\n");
    }
    if (entry.kind === "card") {
      return ["银行 " + (secret.bank || ""), "持卡人 " + (secret.holder || ""), groupCard(secret.number), secret.expiry || "", secret.cvv || "", secret.pin || "", secret.note || ""].filter(Boolean).join("\n");
    }
    return [secret.body || "", secret.note || ""].filter(Boolean).join("\n");
  }

  function openDelete(entry) {
    var pass = passwordLine("current-password");
    var message = el("p", {class: "banner bad", hidden: true}, []);
    var button = el("button", {type: "button", class: "btn danger"}, ["确认删除"]);
    bindEnter(pass.node, button);
    button.addEventListener("click", function () {
      runBusy(button, "正在删除…", async function () {
        var password = take(pass.node);
        try {
          await api("/api/entries/delete", {id: entry.id, password: password});
          password = "";
          showList("已删除「" + entry.title + "」。");
        } catch (err) {
          password = "";
          if (err.code === "locked") return;
          message.hidden = false;
          message.textContent = err.message;
        }
      });
    });
    openDialog(entry.title, [
      entryFacts(entry),
      el("p", {class: "banner bad"}, ["删除后无法从保险库里恢复。"]),
      field("主密码", pass.wrap),
      message,
      el("div", {class: "actions"}, [
        button,
        el("button", {type: "button", class: "link muted", onclick: closeDialog}, ["取消"])
      ])
    ], {kicker: "删除"});
    pass.node.focus();
  }

  function startEdit(entry) {
    var pass = passwordLine("current-password");
    var message = el("p", {class: "banner bad", hidden: true}, []);
    var button = el("button", {type: "button", class: "btn primary"}, ["继续"]);
    bindEnter(pass.node, button);
    button.addEventListener("click", function () {
      message.hidden = true;
      runBusy(button, "正在核对…", async function () {
        var password = take(pass.node);
        try {
          var data = await api("/api/entries/reveal", {id: entry.id, password: password});
          var full = data.entry;
          data = null;
          password = "";
          if (full.kind === "mnemonic") full.secret.words = "";
          closeDialog();
          showEditor(full.kind, full);
        } catch (err) {
          password = "";
          if (err.code === "locked") return;
          message.hidden = false;
          message.textContent = err.message;
          pass.node.focus();
        }
      });
    });
    openDialog(entry.title, [
      entryFacts(entry),
      el("p", {class: "lede"}, ["修改前再核对一次主密码。助记词本身不会先显示出来。"]),
      field("主密码", pass.wrap),
      message,
      el("div", {class: "actions"}, [
        button,
        el("button", {type: "button", class: "link muted", onclick: closeDialog}, ["返回"])
      ])
    ], {kicker: "修改"});
    pass.node.focus();
  }

  function formSection(label, desc, body, extraClass) {
    return el("div", {class: extraClass ? "form-sec " + extraClass : "form-sec"}, [
      el("div", {class: "sec-label"}, [el("h3", null, [label]), desc ? el("p", null, [desc]) : null]),
      el("div", {class: "sec-body"}, body)
    ]);
  }

  function showEditor(kind, existing) {
    setMode("editor");
    closeDialog();
    var editing = !!(existing && existing.id);
    var secret = (existing && existing.secret) || {};
    var title = sensitiveInput("text", {value: editing ? existing.title : "", maxlength: "80"});
    var titleWarn = el("p", {class: "hint", hidden: true}, ["库里已有同名条目，确认不是重复添加。"]);
    title.addEventListener("input", function () {
      var value = title.value.trim().toLowerCase();
      if (!value) {
        titleWarn.hidden = true;
        return;
      }
      var selfId = editing ? existing.id : "";
      titleWarn.hidden = !knownTitles.some(function (item) {
        return item.title === value && item.id !== selfId;
      });
    });
    var note = sensitiveArea();
    note.value = secret.note || "";
    note.setAttribute("maxlength", "4000");
    var message = el("p", {class: "banner bad", hidden: true}, []);
    var savePass = passwordLine("current-password");
    var contentSec = null;
    var moreBody = [];
    var words = null;
    var confirmWords = null;
    var replaceInput = null;
    var passNode = null;
    var address = null;
    var bank = null;
    var holder = null;
    var number = null;
    var expiry = null;
    var cvv = null;
    var pin = null;
    var body = null;
    var allowUnsafe = false;
    var unsafe = el("label", {class: "check", hidden: true}, [
      el("input", {type: "checkbox", onchange: function (event) { allowUnsafe = event.target.checked; }}),
      el("span", null, ["我已逐词核对，仍要保存这条未通过英文校验的助记词"])
    ]);
    if (kind === "mnemonic") {
      words = sensitiveArea({class: "mono", rows: "4"});
      confirmWords = sensitiveArea({class: "mono", rows: "4"});
      words.setAttribute("maxlength", "1000");
      confirmWords.setAttribute("maxlength", "1000");
      var live = countHint(0);
      var liveConfirm = countHint(0);
      var diffLine = el("p", {class: "fine"}, ["两次输入一致后，这里会给出逐词对比。"]);
      var checkLine = el("p", {class: "fine", hidden: true}, []);
      words.addEventListener("input", function () {
        var next = countHint(wordCount(words.value));
        live.replaceWith(next);
        live = next;
      });
      confirmWords.addEventListener("input", function () {
        var next = countHint(wordCount(confirmWords.value));
        liveConfirm.replaceWith(next);
        liveConfirm = next;
      });
      function updateDiff() {
        var left = normWordList(words.value);
        var right = normWordList(confirmWords.value);
        if (!left.length && !right.length) {
          diffLine.className = "fine";
          diffLine.textContent = "两次输入一致后，这里会给出逐词对比。";
          return;
        }
        if (left.length !== right.length) {
          diffLine.className = "hint";
          diffLine.textContent = "两次输入的词数不同：" + left.length + " 个和 " + right.length + " 个。";
          return;
        }
        for (var i = 0; i < left.length; i += 1) {
          if (left[i] !== right[i]) {
            diffLine.className = "hint";
            diffLine.textContent = "第 " + (i + 1) + " 个词不一致：「" + left[i] + "」和「" + right[i] + "」。";
            return;
          }
        }
        diffLine.className = "okfine";
        diffLine.textContent = "两次输入一致，共 " + left.length + " 个词。";
      }
      words.addEventListener("input", updateDiff);
      confirmWords.addEventListener("input", updateDiff);
      function scheduleCheck() {
        window.clearTimeout(editorCheckTimer);
        editorCheckTimer = window.setTimeout(function () {
          if (!checkLine.isConnected) return;
          var count = normWordList(words.value).length;
          if (count !== 12 && count !== 15 && count !== 18 && count !== 21 && count !== 24) {
            checkLine.hidden = true;
            return;
          }
          checkLine.hidden = false;
          checkLine.className = "fine";
          checkLine.textContent = "正在对照英文 BIP39 词表…";
          api("/api/entries/check-mnemonic", {words: words.value}).then(function (data) {
            if (!checkLine.isConnected) return;
            var check = (data && data.check) || {};
            if (check.ok) {
              checkLine.className = "okfine";
              checkLine.textContent = "英文 BIP39 校验通过。";
            } else if (check.reason === "unknown" && check.unknown && check.unknown.length) {
              checkLine.className = "hint";
              checkLine.textContent = "这些词不在英文词表里：" + check.unknown.join("、") + "。请核对拼写。";
            } else if (check.reason === "checksum") {
              checkLine.className = "hint";
              checkLine.textContent = "词都在词表里，但校验和不通过：可能有错词或顺序颠倒了。";
            } else {
              checkLine.hidden = true;
            }
          }).catch(function () {
            if (checkLine.isConnected) checkLine.hidden = true;
          });
        }, 400);
      }
      words.addEventListener("input", scheduleCheck);
      var pass = passwordLine("off");
      passNode = pass.node;
      passNode.setAttribute("maxlength", "256");
      if (editing && secret.passphrase) passNode.value = secret.passphrase;
      address = sensitiveInput("text", {value: secret.address_hint || "", maxlength: "200"});
      var wordWrap = el("div", {class: "cols-2"}, [
        field("助记词", words, [live, checkLine]),
        field("再输入一次", confirmWords, [liveConfirm, diffLine])
      ]);
      var wordBody = [wordWrap];
      if (editing) {
        replaceInput = el("input", {type: "checkbox"});
        wordWrap.hidden = true;
        replaceInput.addEventListener("change", function () {
          wordWrap.hidden = !replaceInput.checked;
          if (!replaceInput.checked) {
            words.value = "";
            confirmWords.value = "";
          }
        });
        wordBody.unshift(el("label", {class: "check"}, [replaceInput, el("span", null, ["更换助记词。不勾选则原词保持不变，页面上也不会把它显示出来。"])]));
      }
      contentSec = formSection("助记词", "两次输入必须完全一致。英文词会做 BIP39 校验，用来发现抄错，不会据此推导地址。", wordBody);
      moreBody.push(el("div", {class: "cols-2"}, [
        field("BIP39 口令", pass.wrap, el("p", {class: "fine"}, ["这不是保险库主密码。"]), true),
        field("核对用地址", address, null, true)
      ]));
    } else if (kind === "card") {
      bank = sensitiveInput("text", {value: secret.bank || "", maxlength: "40"});
      holder = sensitiveInput("text", {value: secret.holder || "", maxlength: "80"});
      number = sensitiveInput("text", {value: secret.number || "", inputmode: "numeric", class: "mono"});
      expiry = sensitiveInput("text", {value: secret.expiry || "", maxlength: "10", placeholder: "MM/YY", class: "mono"});
      cvv = sensitiveInput("password", {value: secret.cvv || "", inputmode: "numeric", maxlength: "4", class: "mono"});
      pin = sensitiveInput("password", {value: secret.pin || "", inputmode: "numeric", maxlength: "12", class: "mono"});
      var cardLive = el("p", {class: "fine"}, []);
      function updateCardLive() {
        var digits = String(number.value || "").replace(/\D/g, "");
        if (!digits) {
          cardLive.textContent = "";
          return;
        }
        var text = groupCard(digits) + " · " + digits.length + " 位";
        if (digits.length < 12) {
          text += "，还差 " + (12 - digits.length) + " 位";
          cardLive.className = "fine";
        } else if (digits.length > 19) {
          text += "，超过了 19 位";
          cardLive.className = "hint";
        } else if (luhnOk(digits)) {
          text += " · Luhn 校验通过";
          cardLive.className = "okfine";
        } else {
          text += " · Luhn 未通过，请核对是不是抄错了";
          cardLive.className = "hint";
        }
        cardLive.textContent = text;
      }
      number.addEventListener("input", updateCardLive);
      contentSec = formSection("卡片", "卡号会做 Luhn 校验，只用来发现抄错。", [
        el("div", {class: "cols-2"}, [field("银行", bank), field("持卡人", holder, null, true)]),
        field("卡号", number, cardLive),
        el("div", {class: "cols-3"}, [field("有效期", expiry, null, true), field("CVV", cvv, null, true), field("卡密码", pin, null, true)])
      ]);
      if (editing) updateCardLive();
    } else {
      body = sensitiveArea({rows: "8"});
      body.value = secret.body || "";
      body.setAttribute("maxlength", "8000");
      contentSec = formSection("内容", "整段原样加密保存，换行也会保留。", [bare(field("内容", body))]);
    }
    moreBody.push(field("备注", note, null, true));
    var button = el("button", {type: "button", class: "btn primary"}, [editing ? "保存修改" : "保存"]);
    bindEnter(savePass.node, button);
    button.addEventListener("click", function () {
      message.hidden = true;
      if (kind === "mnemonic" && (!editing || (replaceInput && replaceInput.checked))) {
        var leftWords = String(words.value || "").trim().replace(/\s+/g, " ").toLowerCase();
        var rightWords = String(confirmWords.value || "").trim().replace(/\s+/g, " ").toLowerCase();
        if (leftWords !== rightWords) {
          message.hidden = false;
          message.textContent = "两次输入的助记词不一致";
          return;
        }
      }
      runBusy(button, "正在加密保存…", async function () {
        var payloadSecret = {note: note.value};
        if (kind === "mnemonic") {
          payloadSecret.passphrase = passNode.value;
          payloadSecret.address_hint = address.value;
          if (!editing || (replaceInput && replaceInput.checked)) {
            payloadSecret.words = words.value;
            payloadSecret.words_confirm = confirmWords.value;
          } else {
            payloadSecret.keep_mnemonic = true;
          }
        } else if (kind === "card") {
          payloadSecret.bank = bank.value;
          payloadSecret.holder = holder.value;
          payloadSecret.number = number.value;
          payloadSecret.expiry = expiry.value;
          payloadSecret.cvv = cvv.value;
          payloadSecret.pin = pin.value;
        } else {
          payloadSecret.body = body.value;
        }
        var password = take(savePass.node);
        try {
          await api("/api/entries/save", {
            id: editing ? existing.id : "",
            kind: kind,
            title: title.value,
            allow_unsafe_mnemonic: allowUnsafe,
            password: password,
            secret: payloadSecret
          });
          password = "";
          payloadSecret = null;
          wipeSensitive();
          showList("已保存。");
        } catch (err) {
          password = "";
          if (err.code === "locked") return;
          if (err.code === "mnemonic") unsafe.hidden = false;
          message.hidden = false;
          message.textContent = err.message;
        }
      });
    });
    var heading = editing ? existing.title : "添加" + kindName(kind);
    var intro = kind === "mnemonic"
      ? "助记词等于整份资产。只在这台你信任的电脑上输入，不要发给任何人，包括自称客服的人。"
      : "所有字段都会和标题一起加密写进保险库文件。";
    function leaveEditor() {
      editorDirty = false;
      window.clearTimeout(editorCheckTimer);
      wipeSensitive();
      showList("");
    }
    function confirmDiscard() {
      if (!editorDirty) {
        leaveEditor();
        return;
      }
      var keep = el("button", {type: "button", class: "btn"}, ["继续编辑"]);
      var drop = el("button", {type: "button", class: "btn danger"}, ["放弃这些内容"]);
      keep.addEventListener("click", closeDialog);
      drop.addEventListener("click", function () {
        closeDialog();
        leaveEditor();
      });
      openDialog("放弃未保存的内容？", [
        el("p", {class: "lede"}, ["返回会立即擦掉已经填写的内容，且无法找回。"]),
        el("div", {class: "actions"}, [keep, drop])
      ], {variant: "modal"});
      keep.focus();
    }
    var section = el("section", {class: "editor"}, [
      el("div", {class: "editor-top"}, [
        el("button", {type: "button", class: "link muted", onclick: confirmDiscard}, ["← 返回条目"])
      ]),
      el("header", {class: "editor-head"}, [
        el("p", {class: "kicker"}, [editing ? "修改" + kindName(kind) : "新建条目"]),
        el("h2", null, [heading]),
        el("p", {class: "lede"}, [intro])
      ]),
      formSection("标题", "解锁后能看见。不要把助记词写进标题。", [bare(field("标题", title, titleWarn))]),
      contentSec,
      formSection("补充", "都可以留空。", moreBody),
      formSection("确认保存", "保存前再输入一次主密码，这一步大约需要一秒。", [
        unsafe,
        field("主密码", savePass.wrap),
        message,
        el("div", {class: "actions"}, [
          button,
          el("button", {type: "button", class: "link muted", onclick: confirmDiscard}, ["取消"])
        ])
      ], "confirm")
    ]);
    section.addEventListener("input", function () { editorDirty = true; });
    section.addEventListener("change", function () { editorDirty = true; });
    view.replaceChildren(section);
    title.focus();
  }

  function showPasswd() {
    setMode("passwd");
    closeDialog();
    var current = passwordLine("current-password");
    var next = passwordLine("new-password");
    var again = passwordLine("new-password");
    var message = el("p", {class: "banner bad", hidden: true}, []);
    var button = el("button", {type: "button", class: "btn primary block"}, ["更换主密码"]);
    bindEnter(again.node, button);
    button.addEventListener("click", function () {
      message.hidden = true;
      if (next.node.value !== again.node.value) {
        message.hidden = false;
        message.textContent = "两次输入的新主密码不一致";
        return;
      }
      runBusy(button, "正在重新加密…", async function () {
        var oldPassword = take(current.node);
        var newPassword = next.node.value;
        var confirm = take(again.node);
        next.node.value = "";
        touchAuth();
        try {
          await api("/api/change-password", {current: oldPassword, password: newPassword, confirm: confirm});
          oldPassword = "";
          newPassword = "";
          confirm = "";
          await poll();
          showList("主密码已更换。旧密码立即失效。");
        } catch (err) {
          oldPassword = "";
          newPassword = "";
          confirm = "";
          if (err.code === "locked") return;
          message.hidden = false;
          message.textContent = err.message;
        }
      });
    });
    view.replaceChildren(gatePage("更换主密码", "会用新盐重新加密整个文件。新密码同样无法找回。这一步要算两次慢哈希。", [
      field("现在的主密码", current.wrap),
      field("新主密码", next.wrap),
      field("再输入一次", again.wrap),
      message,
      button,
      el("button", {type: "button", class: "link muted", onclick: function () { wipeSensitive(); showList(""); }}, ["取消，返回条目"])
    ], false));
    current.node.focus();
  }

  lockBtn.addEventListener("click", async function () {
    touchAuth();
    wipeSensitive();
    try { await api("/api/lock", {}); } catch (err) {}
    if (status) status.unlocked = false;
    lockBtn.hidden = true;
    idleControl.hidden = true;
    remain = -1;
    paintIdle();
    showUnlock("已锁定");
  });

  idleSelect.addEventListener("change", async function () {
    try {
      var updated = await api("/api/idle", {seconds: Number(idleSelect.value)});
      remain = updated.idle_remaining;
      if (status) status.idle_seconds = updated.idle_seconds;
      paintIdle();
    } catch (err) {
      if (err.code !== "locked") toast(err.message, "bad");
    }
  });

  function isTypingTarget(node) {
    if (!node || !node.tagName) return false;
    var tag = node.tagName;
    return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || node.isContentEditable === true;
  }

  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") {
      if (!dialog.hidden) closeDialog();
      else wipeRevealed();
      return;
    }
    if (!dialog.hidden && event.key === "Tab") {
      var items = dialogFocusables(dialog);
      if (!items.length) return;
      var first = items[0];
      var last = items[items.length - 1];
      var active = document.activeElement;
      if (!dialog.contains(active)) {
        event.preventDefault();
        first.focus();
      } else if (event.shiftKey && active === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && active === last) {
        event.preventDefault();
        first.focus();
      }
      return;
    }
    if (event.ctrlKey || event.metaKey || event.altKey) return;
    if (mode !== "list" || !dialog.hidden || isTypingTarget(event.target)) return;
    if (event.key === "/") {
      var box = view.querySelector(".search input");
      if (box) {
        event.preventDefault();
        box.focus();
      }
    } else if (event.key === "n" || event.key === "N") {
      event.preventDefault();
      showEditor("mnemonic", null);
    }
  });
  document.addEventListener("visibilitychange", function () {
    if (document.visibilityState === "hidden") closeDialog();
  });
  document.addEventListener("pointerdown", noteActivity);
  document.addEventListener("keydown", noteActivity);
  document.addEventListener("wheel", noteActivity, {passive: true});
  window.addEventListener("beforeunload", function (event) {
    if (editorDirty) {
      event.preventDefault();
      event.returnValue = "";
    }
  });

  pokeBtn.addEventListener("click", async function () {
    try {
      var data = await api("/api/touch", {});
      remain = data.idle_remaining;
      paintIdle();
    } catch (err) {}
  });

  async function noteActivity() {
    if (!status || !status.unlocked || mode === "boot" || mode === "setup" || mode === "unlock") return;
    var now = Date.now();
    if (now - lastTouch < 20000) return;
    lastTouch = now;
    try {
      var data = await api("/api/touch", {});
      remain = data.idle_remaining;
      paintIdle();
    } catch (err) {}
  }

  window.setInterval(function () {
    if (!status || !status.unlocked || remain < 0) {
      lockwarn.hidden = true;
      return;
    }
    remain -= 1;
    paintIdle();
    if (remain === 0) {
      remain = -1;
      poll();
    }
    lockwarn.hidden = !(mode === "editor" && editorDirty && remain > 0 && remain <= 20);
  }, 1000);
  function schedulePoll() {
    window.setTimeout(function () {
      poll();
      schedulePoll();
    }, status && status.unlocked ? 5000 : 10000);
  }
  schedulePoll();
  poll();
})();
