function customAlert(message) {
  return new Promise((resolve) => {
    const overlay = document.createElement("div");
    overlay.className = "modal-overlay";
    overlay.innerHTML = '<div class="modal-card"><div class="modal-msg">' + String(message).replace(/</g,"&lt;").replace(/>/g,"&gt;") + '</div><div class="modal-btns"><button class="modal-btn modal-btn-primary" id="modal-ok">确定</button></div></div>';
    document.body.appendChild(overlay);
    overlay.querySelector("#modal-ok").onclick = () => { closeOverlay(overlay, () => resolve()); };
  });
}
function customConfirm(message) {
  return new Promise((resolve) => {
    const overlay = document.createElement("div");
    overlay.className = "modal-overlay";
    overlay.innerHTML = '<div class="modal-card"><div class="modal-msg">' + String(message).replace(/</g,"&lt;").replace(/>/g,"&gt;") + '</div><div class="modal-btns"><button class="modal-btn" id="modal-cancel">取消</button><button class="modal-btn modal-btn-primary" id="modal-ok">确定</button></div></div>';
    document.body.appendChild(overlay);
    overlay.querySelector("#modal-ok").onclick = () => { closeOverlay(overlay, () => resolve(true)); };
    overlay.querySelector("#modal-cancel").onclick = () => { closeOverlay(overlay, () => resolve(false)); };
  });
}
function customVersionSelect(message, options) {
  return new Promise((resolve) => {
    const overlay = document.createElement("div");
    overlay.className = "modal-overlay";
    let btnsHtml = "";
    const btnIds = [];
    options.forEach((opt, i) => {
      const id = "modal-opt-" + i;
      btnIds.push({ id, value: opt.value });
      btnsHtml += '<button class="modal-btn modal-btn-primary" style="width:100%" id="' + id + '">' + String(opt.label).replace(/</g,"&lt;").replace(/>/g,"&gt;") + '</button>';
    });
    overlay.innerHTML = '<div class="modal-card"><div class="modal-msg">' + String(message).replace(/</g,"&lt;").replace(/>/g,"&gt;") + '</div><div class="modal-btns" style="flex-direction:column">' + btnsHtml + '</div></div>';
    document.body.appendChild(overlay);
    btnIds.forEach(({ id, value }) => {
      overlay.querySelector("#" + id).onclick = () => { closeOverlay(overlay, () => resolve(value)); };
    });
  });
}
function customFileSelect(message, accept) {
  return new Promise((resolve) => {
    const overlay = document.createElement("div");
    overlay.className = "modal-overlay";
    const card = document.createElement("div");
    card.className = "modal-card";
    const msg = document.createElement("div");
    msg.className = "modal-msg";
    msg.textContent = message;
    card.appendChild(msg);

    // 使用 <label> 包裹隐藏的 input，移动端 Firefox 上更可靠
    const fileInput = document.createElement("input");
    fileInput.type = "file";
    fileInput.accept = accept || ".so";
    fileInput.style.display = "none";

    const pickLabel = document.createElement("label");
    pickLabel.className = "modal-btn modal-btn-primary";
    pickLabel.style.cssText = "display:block;text-align:center;cursor:pointer;margin-bottom:14px;";
    pickLabel.textContent = "点击选择 .so 文件";
    pickLabel.appendChild(fileInput);
    card.appendChild(pickLabel);

    const fileName = document.createElement("div");
    fileName.style.cssText = "font-size:13px;color:#fff;margin-bottom:18px;min-height:18px;word-break:break-all;";
    card.appendChild(fileName);

    function markActive() { window.__filePickerActive = true; }
    function markInactive() { window.__filePickerActive = false; }
    fileInput.addEventListener("click", markActive);
    fileInput.addEventListener("change", () => {
      markInactive();
      const f = fileInput.files && fileInput.files[0];
      fileName.textContent = f ? ("已选择: " + f.name) : "";
    });
    function onWinFocus() {
      // 选择器关闭（无论是否选了文件）后稍延时清除标记
      setTimeout(markInactive, 300);
    }
    window.addEventListener("focus", onWinFocus);

    const btns = document.createElement("div");
    btns.className = "modal-btns";
    const cancelBtn = document.createElement("button");
    cancelBtn.className = "modal-btn";
    cancelBtn.textContent = "取消";
    const okBtn = document.createElement("button");
    okBtn.className = "modal-btn modal-btn-primary";
    okBtn.textContent = "确定";
    btns.appendChild(cancelBtn);
    btns.appendChild(okBtn);
    card.appendChild(btns);
    overlay.appendChild(card);
    document.body.appendChild(overlay);
    function cleanup() {
      window.removeEventListener("focus", onWinFocus);
      markInactive();
    }
    cancelBtn.onclick = () => { cleanup(); closeOverlay(overlay, () => resolve(null)); };
    okBtn.onclick = () => {
      const file = fileInput.files && fileInput.files[0] ? fileInput.files[0] : null;
      cleanup();
      closeOverlay(overlay, () => resolve(file));
    };
  });
}
function closeOverlay(overlay, cb) {
  overlay.style.animation = "modalFadeOut 0.2s ease forwards";
  const card = overlay.querySelector(".modal-card");
  if (card) card.style.animation = "modalSlideOut 0.2s ease forwards";
  setTimeout(() => { overlay.remove(); if (cb) cb(); }, 200);
}