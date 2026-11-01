(function () {
  "use strict";

  var dataElement = document.getElementById("protected-data");
  var shell = document.querySelector(".gate-shell");
  var form = document.getElementById("gate-form");
  var input = document.getElementById("gate-password");
  var submit = document.getElementById("gate-submit");
  var status = document.getElementById("gate-status");
  var storageKey = "relay-sim:access-password";

  if (!dataElement || !form || !input || !submit || !status) {
    showGate();
    return;
  }

  var payload;

  try {
    payload = JSON.parse(dataElement.textContent);
  } catch (error) {
    setStatus("页面加密数据无效。", true);
    showGate();
    return;
  }

  function showGate() {
    if (shell) {
      shell.classList.add("gate-visible");
    }
  }

  function setStatus(message, isError) {
    status.textContent = message;
    status.className = isError ? "gate-status gate-error" : "gate-status";
  }

  function base64ToBytes(value) {
    var binary = window.atob(value);
    var bytes = new Uint8Array(binary.length);

    for (var i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }

    return bytes;
  }

  function showError(message) {
    showGate();
    setStatus(message, true);
    submit.disabled = false;
    input.disabled = false;
    input.focus();
    input.select();
  }

  function getSavedPassword() {
    try {
      return window.sessionStorage.getItem(storageKey);
    } catch (error) {
      return null;
    }
  }

  function savePassword(password) {
    try {
      window.sessionStorage.setItem(storageKey, password);
    } catch (error) {
      return;
    }
  }

  function clearSavedPassword() {
    try {
      window.sessionStorage.removeItem(storageKey);
    } catch (error) {
      return;
    }
  }

  function unlock(password, isAutomatic) {
    submit.disabled = true;
    input.disabled = true;
    setStatus("正在解密页面…", false);

    window.crypto.subtle
      .importKey(
        "raw",
        new TextEncoder().encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
      )
      .then(function (baseKey) {
        return window.crypto.subtle.deriveKey(
          {
            name: "PBKDF2",
            salt: base64ToBytes(payload.salt),
            iterations: payload.iterations,
            hash: "SHA-256"
          },
          baseKey,
          { name: "AES-GCM", length: 256 },
          false,
          ["decrypt"]
        );
      })
      .then(function (key) {
        return window.crypto.subtle.decrypt(
          {
            name: "AES-GCM",
            iv: base64ToBytes(payload.iv),
            additionalData: new TextEncoder().encode(payload.page)
          },
          key,
          base64ToBytes(payload.ciphertext)
        );
      })
      .then(function (decrypted) {
        var html = new TextDecoder().decode(decrypted);
        savePassword(password);
        document.open();
        document.write(html);
        document.close();
      })
      .catch(function () {
        if (isAutomatic) {
          clearSavedPassword();
          showError("保存的密码已失效，请重新输入。");
          return;
        }

        showError("密码不正确，或页面数据已损坏。");
      });
  }

  form.addEventListener("submit", function (event) {
    event.preventDefault();

    var password = input.value;

    if (!password) {
      setStatus("请输入访问密码。", true);
      input.focus();
      return;
    }

    unlock(password, false);
  });

  var savedPassword = getSavedPassword();

  if (savedPassword) {
    unlock(savedPassword, true);
  } else {
    showGate();
    input.focus();
  }
})();
