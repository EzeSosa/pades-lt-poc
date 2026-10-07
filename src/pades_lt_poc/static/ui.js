// Helpers compartidos por los scripts de /ui (scripts clásicos: quedan como globales).

const $ = (sel, root = document) => root.querySelector(sel);

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
}

function badge(text, tone) {
  return el("span", `badge ${tone}`, text);
}

// Ficha de dos columnas: cada fila es [término, ...contenido]. El término puede ser texto o un <dt> armado.
function facts(rows) {
  const dl = el("dl", "facts");
  for (const [term, ...content] of rows) {
    const dd = el("dd");
    dd.append(...content.filter(Boolean));
    dl.append(term instanceof Node ? term : el("dt", null, term), dd);
  }
  return dl;
}

function cn(rfc4514) {
  // RFC 4514 con comas escapadas como "\,": se parte sólo en las comas sin escapar.
  const attr = rfc4514.split(/(?<!\\),/).find((part) => part.startsWith("CN="));
  return attr ? attr.slice(3).replace(/\\(.)/g, "$1") : rfc4514;
}

function date(iso) {
  return new Date(iso).toLocaleDateString("es-AR", { day: "2-digit", month: "2-digit", year: "numeric", timeZone: "UTC" });
}

function when(iso) {
  return new Date(iso).toISOString().replace("T", " ").replace(/\.\d+Z$|Z$/, " UTC");
}

// POST de un formulario a la API; devuelve el JSON o lanza un Error con el `detail`.
async function postForm(url, body) {
  const response = await fetch(url, { method: "POST", body });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail);
    throw new Error(detail || `HTTP ${response.status}`);
  }
  return data;
}

// --------------------------------------------------------------------------- certificados
function certFilename(subjectRfc4514, serial) {
  const base = cn(subjectRfc4514).normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/[^\w.-]+/g, "_");
  return `${base || serial}.crt`;
}

function downloadDer(b64, filename) {
  const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  const url = URL.createObjectURL(new Blob([bytes], { type: "application/pkix-cert" }));
  const a = el("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Contexto no seguro (p. ej. la app servida por IP sin HTTPS): fallback.
    const area = el("textarea");
    area.value = text;
    document.body.append(area);
    area.select();
    const ok = document.execCommand("copy");
    area.remove();
    return ok;
  }
}

// Marca `button` como copiado y desmarca el que lo estaba. El texto va en un `.label`.
function markCopied(button) {
  document.querySelectorAll(".copy.copied").forEach((b) => {
    b.classList.remove("copied");
    $(".label", b).textContent = b.dataset.label;
  });
  button.dataset.label ??= $(".label", button).textContent;
  button.classList.add("copied");
  $(".label", button).textContent = "Copiado";
}

const ICONS = {
  download: '<path d="M12 3v12"/><path d="m7 10 5 5 5-5"/><path d="M5 21h14"/>',
  copy: '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>',
  inspect: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  moon: '<path d="M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5Z"/>',
};

function icon(name) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  for (const [k, v] of Object.entries({ width: 16, height: 16, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor",
    "stroke-width": 2, "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true" })) {
    svg.setAttribute(k, v);
  }
  svg.innerHTML = ICONS[name];
  return svg;
}

// Botones "Descargar .crt" y "Copiar base64" de un certificado. `onDone(mensaje)` informa el resultado.
function certActions(b64, subjectRfc4514, serial, onDone) {
  const name = cn(subjectRfc4514);
  const download = el("button", "secondary");
  download.type = "button";
  download.append(icon("download"), "Descargar .crt");
  download.setAttribute("aria-label", `Descargar ${name}.crt`);
  download.addEventListener("click", () => {
    const filename = certFilename(subjectRfc4514, serial);
    downloadDer(b64, filename);
    onDone(`Descargado: ${filename}`);
  });

  const copy = el("button", "secondary copy");
  copy.type = "button";
  copy.append(icon("copy"), el("span", "label", "Copiar base64"));
  copy.setAttribute("aria-label", `Copiar base64 de ${name}`);
  copy.addEventListener("click", async () => {
    if (!(await copyText(b64))) return onDone("No se pudo copiar al portapapeles");
    markCopied(copy);
    onDone(`Base64 de ${name} copiado al portapapeles`);
  });
  return [download, copy];
}

// --------------------------------------------------------------------------- tema
// Por defecto sigue al sistema; el botón lo fija y se recuerda. El <head> de cada página
// aplica el tema guardado antes de pintar, para que no parpadee.
function setupThemeButton(button) {
  const prefersDark = matchMedia("(prefers-color-scheme: dark)");
  const current = () => document.documentElement.dataset.theme || (prefersDark.matches ? "dark" : "light");
  const render = () => {
    const dark = current() === "dark";
    const label = dark ? "Cambiar a tema claro" : "Cambiar a tema oscuro";
    button.replaceChildren(icon(dark ? "sun" : "moon"));
    button.setAttribute("aria-label", label);
    button.title = label;
  };
  button.addEventListener("click", () => {
    const next = current() === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    try {
      localStorage.setItem("ui-theme", next);
    } catch {}
    render();
  });
  prefersDark.addEventListener("change", render);
  render();
}

// --------------------------------------------------------------------------- guardado
// El PDF o el certificado que se analizó se guarda en IndexedDB (que admite archivos
// enteros), para que moverse entre /ui/firmas y /ui/certificado no los pierda. Todo
// falla en silencio: sin almacenamiento (p. ej. una ventana privada) la página anda igual.
function openStore() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open("pades-ui", 1);
    request.onupgradeneeded = () => request.result.createObjectStore("kv");
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function storeOp(mode, op) {
  const db = await openStore();
  return new Promise((resolve, reject) => {
    const request = op(db.transaction("kv", mode).objectStore("kv"));
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function loadSaved(key) {
  try {
    return await storeOp("readonly", (s) => s.get(key));
  } catch {
    return undefined;
  }
}

async function save(key, value) {
  try {
    await storeOp("readwrite", (s) => s.put(value, key));
  } catch {}
}

async function forget(key) {
  try {
    await storeOp("readwrite", (s) => s.delete(key));
  } catch {}
}

// Vuelve a poner un archivo guardado en su <input type=file>, para que se vea elegido.
function restoreFileInput(input, file) {
  try {
    const transfer = new DataTransfer();
    transfer.items.add(file);
    input.files = transfer.files;
  } catch {}
}

function kb(file) {
  return `${Math.max(1, Math.round(file.size / 1024))} KB`;
}
