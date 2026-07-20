// Vanilla JS Liquid Glass Effect - Element-level button glass
// Created by Shu Ding (https://github.com/shuding/liquid-glass) in 2025.
// Modified for per-element glass overlay support.

(function() {
  'use strict';

  // Utility functions
  function smoothStep(a, b, t) {
    t = Math.max(0, Math.min(1, (t - a) / (b - a)));
    return t * t * (3 - 2 * t);
  }

  function length(x, y) {
    return Math.sqrt(x * x + y * y);
  }

  function roundedRectSDF(x, y, width, height, radius) {
    const qx = Math.abs(x) - width + radius;
    const qy = Math.abs(y) - height + radius;
    return Math.min(Math.max(qx, qy), 0) + length(Math.max(qx, 0), Math.max(qy, 0)) - radius;
  }

  function texture(x, y) {
    return { type: 't', x, y };
  }

  function generateId() {
    return 'liquid-glass-' + Math.random().toString(36).substr(2, 9);
  }

  // ElementGlass - creates a glass overlay positioned over a specific DOM element
  class ElementGlass {
    constructor(targetElement, options = {}) {
      this.target = targetElement;
      this.width = options.width || targetElement.offsetWidth;
      this.height = options.height || targetElement.offsetHeight;
      this.fragment = options.fragment || ((uv) => texture(uv.x, uv.y));
      this.canvasDPI = options.canvasDPI || 1;
      this.id = generateId();
      this.borderRadius = options.borderRadius || '20px';
      this.zIndex = options.zIndex || 500;

      this.mouse = { x: 0.5, y: 0.5 };
      this.mouseUsed = false;

      this.createElement();
      this.updatePosition();
      this.setupEventListeners();
      this.updateShader();
    }

    createElement() {
      // Create SVG filter
      this.svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      this.svg.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
      this.svg.setAttribute('width', '0');
      this.svg.setAttribute('height', '0');
      this.svg.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        pointer-events: none;
        z-index: 0;
      `;

      const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
      const filter = document.createElementNS('http://www.w3.org/2000/svg', 'filter');
      filter.setAttribute('id', `${this.id}_filter`);
      filter.setAttribute('filterUnits', 'userSpaceOnUse');
      filter.setAttribute('colorInterpolationFilters', 'sRGB');
      filter.setAttribute('x', '0');
      filter.setAttribute('y', '0');
      filter.setAttribute('width', this.width.toString());
      filter.setAttribute('height', this.height.toString());

      this.feImage = document.createElementNS('http://www.w3.org/2000/svg', 'feImage');
      this.feImage.setAttribute('id', `${this.id}_map`);
      this.feImage.setAttribute('width', this.width.toString());
      this.feImage.setAttribute('height', this.height.toString());

      this.feDisplacementMap = document.createElementNS('http://www.w3.org/2000/svg', 'feDisplacementMap');
      this.feDisplacementMap.setAttribute('in', 'SourceGraphic');
      this.feDisplacementMap.setAttribute('in2', `${this.id}_map`);
      this.feDisplacementMap.setAttribute('xChannelSelector', 'R');
      this.feDisplacementMap.setAttribute('yChannelSelector', 'G');

      filter.appendChild(this.feImage);
      filter.appendChild(this.feDisplacementMap);
      defs.appendChild(filter);
      this.svg.appendChild(defs);

      // Create glass overlay container
      this.container = document.createElement('div');
      this.container.style.cssText = `
        position: fixed;
        overflow: hidden;
        border-radius: ${this.borderRadius};
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15), 0 -10px 25px inset rgba(0, 0, 0, 0.08);
        backdrop-filter: url(#${this.id}_filter) contrast(1.15) brightness(1.03) saturate(1.05);
        z-index: 0;
        pointer-events: none;
      `;

      // Create canvas for displacement map
      this.canvas = document.createElement('canvas');
      this.canvas.width = this.width * this.canvasDPI;
      this.canvas.height = this.height * this.canvasDPI;
      this.canvas.style.display = 'none';

      this.context = this.canvas.getContext('2d');
    }

    updatePosition() {
      const rect = this.target.getBoundingClientRect();
      this.container.style.left = rect.left + 'px';
      this.container.style.top = rect.top + 'px';
      this.container.style.width = rect.width + 'px';
      this.container.style.height = rect.height + 'px';

      // Update SVG filter dimensions
      this.feImage.setAttribute('width', rect.width.toString());
      this.feImage.setAttribute('height', rect.height.toString());
      this.svg.querySelector('filter').setAttribute('width', rect.width.toString());
      this.svg.querySelector('filter').setAttribute('height', rect.height.toString());

      // Update canvas dimensions
      this.width = rect.width;
      this.height = rect.height;
      this.canvas.width = this.width * this.canvasDPI;
      this.canvas.height = this.height * this.canvasDPI;
      this.context = this.canvas.getContext('2d');
    }

    setupEventListeners() {
      this._onMouseMove = (e) => {
        const rect = this.target.getBoundingClientRect();
        this.mouse.x = (e.clientX - rect.left) / rect.width;
        this.mouse.y = (e.clientY - rect.top) / rect.height;
        if (this.mouseUsed) {
          this.updateShader();
        }
      };

      this._onScroll = () => {
        this.updatePosition();
      };

      this._onResize = () => {
        this.updatePosition();
        this.updateShader();
      };

      document.addEventListener('mousemove', this._onMouseMove);
      window.addEventListener('scroll', this._onScroll, true);
      window.addEventListener('resize', this._onResize);
    }

    updateShader() {
      const mouseProxy = new Proxy(this.mouse, {
        get: (target, prop) => {
          this.mouseUsed = true;
          return target[prop];
        }
      });

      this.mouseUsed = false;

      const w = this.canvas.width;
      const h = this.canvas.height;
      if (w === 0 || h === 0) return;

      const data = new Uint8ClampedArray(w * h * 4);

      let maxScale = 0;
      const rawValues = [];

      for (let i = 0; i < data.length; i += 4) {
        const x = (i / 4) % w;
        const y = Math.floor(i / 4 / w);
        const pos = this.fragment(
          { x: x / w, y: y / h },
          mouseProxy
        );
        const dx = pos.x * w - x;
        const dy = pos.y * h - y;
        maxScale = Math.max(maxScale, Math.abs(dx), Math.abs(dy));
        rawValues.push(dx, dy);
      }

      maxScale *= 0.5;

      let index = 0;
      for (let i = 0; i < data.length; i += 4) {
        const r = rawValues[index++] / maxScale + 0.5;
        const g = rawValues[index++] / maxScale + 0.5;
        data[i] = r * 255;
        data[i + 1] = g * 255;
        data[i + 2] = 0;
        data[i + 3] = 255;
      }

      this.context.putImageData(new ImageData(data, w, h), 0, 0);
      this.feImage.setAttributeNS('http://www.w3.org/1999/xlink', 'href', this.canvas.toDataURL());
      this.feDisplacementMap.setAttribute('scale', Math.max(1, maxScale / this.canvasDPI).toString());
    }

    appendTo(parent) {
      parent.appendChild(this.svg);
      parent.appendChild(this.container);
    }

    destroy() {
      document.removeEventListener('mousemove', this._onMouseMove);
      window.removeEventListener('scroll', this._onScroll, true);
      window.removeEventListener('resize', this._onResize);
      if (this.svg && this.svg.parentNode) this.svg.remove();
      if (this.container && this.container.parentNode) this.container.remove();
      if (this.canvas && this.canvas.parentNode) this.canvas.remove();
    }
  }

  // Apply liquid glass effect to elements matching a CSS selector
  function applyLiquidGlass(selector, options) {
    const elements = document.querySelectorAll(selector);
    const glasses = [];

    elements.forEach(function(el) {
      const rect = el.getBoundingClientRect();
      if (rect.width === 0 || rect.height === 0) return;

      const glass = new ElementGlass(el, Object.assign({
        width: rect.width,
        height: rect.height,
        borderRadius: getComputedStyle(el).borderRadius || '20px',
        zIndex: (parseInt(getComputedStyle(el).zIndex) || 500) - 1,
        fragment: (uv, mouse) => {
          const ix = uv.x - 0.5;
          const iy = uv.y - 0.5;
          const distanceToEdge = roundedRectSDF(ix, iy, 0.35, 0.25, 0.5);
          const displacement = smoothStep(0.8, 0, distanceToEdge - 0.12);
          const scaled = smoothStep(0, 1, displacement);
          return texture(ix * scaled + 0.5, iy * scaled + 0.5);
        }
      }, options || {}));

      glass.appendTo(document.body);
      glasses.push(glass);
    });

    return glasses;
  }

  // Expose API
  window.liquidGlassAPI = {
    ElementGlass: ElementGlass,
    applyLiquidGlass: applyLiquidGlass,
    destroyAll: function(glasses) {
      (glasses || []).forEach(function(g) { g.destroy(); });
    }
  };

  console.log('Liquid Glass API loaded. Use liquidGlassAPI.applyLiquidGlass(selector) to apply glass effects.');
})();