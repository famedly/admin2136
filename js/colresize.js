// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Resizable grid columns. The first `count` cells of a grid header get a
// handle at their right edge; dragging it sets the column widths in pixels
// as the CSS variable `name` on `scope`, which the header and the rows use
// as their grid-template-columns. The column after them takes the
// remaining width (at least `flexMin` pixels), followed by the `tail`
// columns. Double-clicking a handle restores the default widths. The
// widths are kept in localStorage under `storageKey`.

const MIN_WIDTH = 40;

export function resizableColumns({
  header,
  scope,
  name,
  count,
  flexMin,
  tail,
  storageKey,
}) {
  const cells = [...header.children];
  const apply = (widths) => {
    if (widths) {
      scope.style.setProperty(
        name,
        widths.map((w) => Math.round(w) + "px").join(" ") +
          ` minmax(${flexMin}px, 1fr) ${tail}`,
      );
    } else {
      scope.style.removeProperty(name);
    }
  };
  const save = (widths) => {
    if (widths) localStorage.setItem(storageKey, JSON.stringify(widths));
    else localStorage.removeItem(storageKey);
  };

  try {
    const w = JSON.parse(localStorage.getItem(storageKey));
    if (
      Array.isArray(w) &&
      w.length === count &&
      w.every((x) => Number.isFinite(x) && x >= MIN_WIDTH)
    ) {
      apply(w);
    }
  } catch (e) {
    /* ignore */
  }

  for (let i = 0; i < count; i++) {
    const handle = document.createElement("span");
    handle.className = "col-resize";
    handle.setAttribute("role", "separator");
    handle.setAttribute("aria-orientation", "vertical");
    handle.title = "Drag to resize the column, double-click to reset";
    cells[i].appendChild(handle);

    let drag = null;
    handle.addEventListener("pointerdown", (e) => {
      if (e.button !== 0) return;
      e.preventDefault();
      handle.setPointerCapture(e.pointerId);
      // Start from the current track widths; the flexible column gives
      // up (or takes) the width the dragged column gains (or loses).
      const widths = cells
        .slice(0, count)
        .map((c) => c.getBoundingClientRect().width);
      const slack = Math.max(
        0,
        cells[count].getBoundingClientRect().width - flexMin,
      );
      drag = { x: e.clientX, widths, start: widths[i], max: widths[i] + slack };
      header.classList.add("resizing");
    });
    handle.addEventListener("pointermove", (e) => {
      if (!drag) return;
      const w = drag.start + e.clientX - drag.x;
      drag.widths[i] = Math.max(MIN_WIDTH, Math.min(drag.max, w));
      apply(drag.widths);
    });
    const end = () => {
      if (!drag) return;
      save(drag.widths);
      drag = null;
      header.classList.remove("resizing");
    };
    handle.addEventListener("pointerup", end);
    handle.addEventListener("pointercancel", end);
    handle.addEventListener("dblclick", () => {
      apply(null);
      save(null);
    });
  }
}
