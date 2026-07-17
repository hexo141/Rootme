// ansi.js — minimal ANSI escape renderer
// Exposes: window.renderAnsiToFragment(text, document) -> DocumentFragment
//
// bold/italic/underline) and converts to <span> elements with inline styles.
// Unsupported sequences are silently dropped.
(function () {
  "use strict";

  // Standard 16-color palette (ANSI / xterm)
  var COLOR_16 = [
    "#000000", "#800000", "#008000", "#808000",
    "#000080", "#800080", "#008080", "#c0c0c0",
    "#808080", "#ff0000", "#00ff00", "#ffff00",
    "#0000ff", "#ff00ff", "#00ffff", "#ffffff"
  ];

  // 256-color palette lookup (indices 16..255)
  var COLOR_256 = (function () {
    var arr = COLOR_16.slice();
    // 6x6x6 color cube (216 colors)
    var cube = [0x00, 0x5f, 0x87, 0xaf, 0xd7, 0xff];
    for (var r = 0; r < 6; r++) {
      for (var g = 0; g < 6; g++) {
        for (var b = 0; b < 6; b++) {
          arr.push("#" +
            cube[r].toString(16).padStart(2, "0") +
            cube[g].toString(16).padStart(2, "0") +
            cube[b].toString(16).padStart(2, "0"));
        }
      }
    }
    // Grayscale ramp (24 colors)
    for (var v = 0; v < 24; v++) {
      var c = (8 + 10 * v).toString(16).padStart(2, "0");
      arr.push("#" + c + c + c);
    }
    return arr;
  })();

  function applySgr(state, params) {
    for (var i = 0; i < params.length; i++) {
      var p = params[i];
      if (p === 0 || p === "") {
        state.fg = null;
        state.bg = null;
        state.bold = false;
        state.italic = false;
        state.underline = false;
        state.faint = false;
      } else if (p === 1) state.bold = true;
      else if (p === 2) state.faint = true;
      else if (p === 3) state.italic = true;
      else if (p === 4) state.underline = true;
      else if (p === 22) { state.bold = false; state.faint = false; }
      else if (p === 23) state.italic = false;
      else if (p === 24) state.underline = false;
      else if (p >= 30 && p <= 37) state.fg = COLOR_16[p - 30];
      else if (p === 38) {
        // 38;5;N  or  38;2;R;G;B
        var mode = params[i + 1];
        if (mode === 5) { state.fg = COLOR_256[params[i + 2]] || null; i += 2; }
        else if (mode === 2) {
          state.fg = "rgb(" + params[i + 2] + "," + params[i + 3] + "," + params[i + 4] + ")";
          i += 4;
        }
      } else if (p === 39) state.fg = null;
      else if (p >= 40 && p <= 47) state.bg = COLOR_16[p - 40];
      else if (p === 48) {
        var bmode = params[i + 1];
        if (bmode === 5) { state.bg = COLOR_256[params[i + 2]] || null; i += 2; }
        else if (bmode === 2) {
          state.bg = "rgb(" + params[i + 2] + "," + params[i + 3] + "," + params[i + 4] + ")";
          i += 4;
        }
      } else if (p === 49) state.bg = null;
      else if (p >= 90 && p <= 97) state.fg = COLOR_16[p - 90 + 8];
      else if (p >= 100 && p <= 107) state.bg = COLOR_16[p - 100 + 8];
    }
  }

  function styleString(state) {
    var parts = [];
    if (state.fg) parts.push("color:" + state.fg);
    if (state.bg) parts.push("background-color:" + state.bg);
    if (state.bold) parts.push("font-weight:bold");
    if (state.italic) parts.push("font-style:italic");
    if (state.underline) parts.push("text-decoration:underline");
    if (state.faint) parts.push("opacity:0.5");
    return parts.length ? parts.join(";") : null;
  }

  function renderAnsiToFragment(text, doc) {
    doc = doc || document;
    var frag = doc.createDocumentFragment();
    if (text == null) return frag;
    text = String(text);

    var state = {
      fg: null, bg: null,
      bold: false, italic: false, underline: false, faint: false
    };

    // Split by lines but keep line-break structure
    var lines = text.split(/\r?\n/);
    for (var lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      var line = lines[lineIdx];
      // Tokenize: ESC [ params letter  |  ESC ] ... BEL  |  plain text
      var re = /\x1b\[([0-9;]*)m|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-9;]*[A-Za-z]/g;
      var last = 0;
      var m;
      while ((m = re.exec(line)) !== null) {
        if (m.index > last) {
          appendSpan(frag, doc, line.slice(last, m.index), state);
        }
        // Only SGR (\x1b[...m) affects state; others ignored
        if (m[0].charAt(m[0].length - 1) === "m") {
          var params = m[1].split(";");
          applySgr(state, params);
        }
        last = m.index + m[0].length;
      }
      if (last < line.length) {
        appendSpan(frag, doc, line.slice(last), state);
      }
      if (lineIdx < lines.length - 1) {
        frag.appendChild(doc.createElement("br"));
      }
    }
    return frag;
  }

  function appendSpan(frag, doc, text, state) {
    if (text.length === 0) return;
    var span = doc.createElement("span");
    span.textContent = text;
    var style = styleString(state);
    if (style) span.setAttribute("style", style);
    frag.appendChild(span);
  }

  // Export
  window.renderAnsiToFragment = renderAnsiToFragment;
})();
