// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Minimal virtual list: renders only the visible slice of a large row set
// into a small, reused pool of DOM elements. Rows have a fixed height.

export class VirtualList {
  constructor(viewport, rowHeight, renderRow) {
    this.viewport = viewport; // scrollable element
    this.rowHeight = rowHeight;
    this.renderRow = renderRow; // (index, rowElement) => void
    this.count = 0;
    this.pool = [];

    this.inner = document.createElement("div");
    this.inner.className = "vlist-inner";
    viewport.appendChild(this.inner);

    viewport.addEventListener("scroll", () => this._update(false));
    if (typeof ResizeObserver !== "undefined") {
      new ResizeObserver(() => this._update(false)).observe(viewport);
    }
  }

  setCount(n) {
    this.count = n;
    this.inner.style.height = n * this.rowHeight + "px";
    this._update(true);
  }

  refresh() {
    this._update(true);
  }

  _ensurePool(n) {
    while (this.pool.length < n) {
      const el = document.createElement("div");
      el.className = "vlist-row";
      el.style.height = this.rowHeight + "px";
      el._idx = -1;
      this.inner.appendChild(el);
      this.pool.push(el);
    }
  }

  _update(force) {
    const { scrollTop, clientHeight } = this.viewport;
    const overscan = 4;
    const first = Math.max(
      0,
      Math.floor(scrollTop / this.rowHeight) - overscan,
    );
    const last = Math.min(
      this.count,
      Math.ceil((scrollTop + clientHeight) / this.rowHeight) + overscan,
    );
    const needed = Math.max(0, last - first);
    this._ensurePool(needed);
    for (let j = 0; j < this.pool.length; j++) {
      const el = this.pool[j];
      if (j < needed) {
        const idx = first + j;
        el.style.display = "";
        el.style.top = idx * this.rowHeight + "px";
        if (force || el._idx !== idx) {
          el._idx = idx;
          this.renderRow(idx, el);
        }
      } else if (el._idx !== -1) {
        el.style.display = "none";
        el._idx = -1;
      }
    }
  }
}
