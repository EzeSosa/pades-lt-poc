// /ui/firmas: un PDF, tres tabs. Al elegir el PDF se piden /certificates y /verify en
// paralelo; cada tab vuelve a pedir lo suyo si cambian sus opciones, con el mismo PDF.
// El PDF y lo que se estaba mirando (opciones, tab, certificado) se guardan en el
// navegador y se restauran al volver a la página.

const TABS = ["certificados", "verificacion", "inspeccion"];
const EMPTY = {
  certificados: "Subí un PDF firmado para ver la cadena de certificados de cada firma.",
  verificacion: "Subí un PDF firmado para ver el reporte de verificación.",
  inspeccion: "Elegí un certificado del PDF, o tocá «Ver detalle» en la tab Certificados.",
};

const state = {
  file: null,
  certs: [], // certificados del PDF, sin repetir, para el selector de Inspección
  // Cada pedido lleva un número: si llega la respuesta de uno viejo (cambió el PDF o una opción), se descarta.
  tickets: { certificados: 0, verificacion: 0, inspeccion: 0 },
  // Lo que se guarda además del PDF ("firmas-pdf"), en "firmas-view".
  view: { tab: "certificados", fetchMissing: true, revocation: "offline", validationTime: "now", diffPolicy: "default", inspected: null },
};

function persistView(changes) {
  Object.assign(state.view, changes);
  save("firmas-view", state.view);
}

const out = (tab) => $(`#${tab}-out`);
const setCount = (tab, text) => { $(`#count-${tab}`).textContent = text; };

function message(tab, text, className = "empty") {
  out(tab).replaceChildren(el(className === "empty" ? "p" : "div", className, text));
}

// Corre `request` como el pedido vigente de `tab`; `render` sólo se aplica si nadie lo reemplazó.
async function run(tab, loadingText, request, render, errorPrefix) {
  const ticket = ++state.tickets[tab];
  message(tab, loadingText);
  try {
    const data = await request();
    if (ticket === state.tickets[tab]) render(data);
  } catch (error) {
    if (ticket === state.tickets[tab]) message(tab, `${errorPrefix}: ${error.message}`, "error-box");
  }
}

// --------------------------------------------------------------------------- tabs
function selectTab(name, { focus = false } = {}) {
  for (const tab of TABS) {
    const button = $(`#tab-${tab}`);
    const selected = tab === name;
    button.setAttribute("aria-selected", selected);
    button.tabIndex = selected ? 0 : -1;
    $(`#panel-${tab}`).hidden = !selected;
    if (selected && focus) button.focus();
  }
  history.replaceState(null, "", `#${name}`);
  persistView({ tab: name });
}

for (const tab of TABS) {
  $(`#tab-${tab}`).addEventListener("click", () => selectTab(tab));
}
$("[role=tablist]").addEventListener("keydown", (event) => {
  const current = TABS.findIndex((t) => $(`#tab-${t}`).getAttribute("aria-selected") === "true");
  const moves = { ArrowRight: current + 1, ArrowLeft: current - 1, Home: 0, End: TABS.length - 1 };
  if (!(event.key in moves)) return;
  event.preventDefault();
  selectTab(TABS[(moves[event.key] + TABS.length) % TABS.length], { focus: true });
});

// --------------------------------------------------------------------------- Certificados
function loadCertificates() {
  const body = new FormData();
  body.append("pdf", state.file);
  body.append("fetch_missing", $("#fetch-missing").checked);
  setCount("certificados", "");
  return run(
    "certificados",
    "Extrayendo certificados…",
    () => postForm("/certificates", body),
    (data) => {
      out("certificados").replaceChildren(renderCertificates(data, {
        onInspect: inspectFromPdf,
        onStatus: (text) => { $("#certificados-status").textContent = text; },
      }));
      setCount("certificados", plural(data.signatures.length, "firma", "firmas"));
      state.certs = uniqueCertificates(data);
      fillPicker();
    },
    "No se pudo procesar el PDF",
  );
}

// --------------------------------------------------------------------------- Verificación
const online = () => state.view.revocation === "online";

// Con conexión sólo se valida a la hora actual: el selector de hora queda fijo en "Ahora".
function applyRevocationMode() {
  for (const b of document.querySelectorAll("[data-revocation]")) b.setAttribute("aria-pressed", b.dataset.revocation === state.view.revocation);
  const time = $("#validation-time");
  time.disabled = online();
  time.value = online() ? "now" : state.view.validationTime;
  time.title = online() ? "Con conexión se valida a la hora actual: la revocación que se descarga es de hoy." : "";
  setRevocationNote();
}

// La nota del control: qué hace el modo y, después de verificar, qué se descargó.
function setRevocationNote(revocation) {
  const note = $("#revocation-note");
  note.classList.toggle("used", Boolean(revocation?.fetched));
  if (!online()) {
    note.textContent = "Sin conexión: sólo cuenta la revocación (CRL y OCSP) que trae el PDF.";
  } else if (!revocation?.fetched) {
    note.textContent = "Con conexión: descarga CRL y OCSP actualizadas de las URLs de cada certificado, a la hora actual.";
  } else {
    const { crls, ocsps, certs } = revocation.fetched;
    const cached = crls.filter((c) => c.from_cache).length;
    const parts = [
      `${plural(crls.length, "CRL", "CRL")}${cached ? ` (${cached} del caché)` : ""}`,
      plural(ocsps.length, "respuesta OCSP", "respuestas OCSP"),
    ];
    if (certs.length) parts.push(plural(certs.length, "emisor por AIA", "emisores por AIA"));
    note.textContent = crls.length || ocsps.length || certs.length
      ? `Se usó revocación descargada, no sólo la del PDF: ${parts.join(" · ")}.`
      : "Con conexión, pero no se descargó nada: alcanzó con lo que trae el PDF.";
  }
}

function loadVerify() {
  const body = new FormData();
  body.append("pdf", state.file);
  body.append("revocation", state.view.revocation);
  body.append("validation_time", online() ? "now" : $("#validation-time").value);
  body.append("diff_policy", $("#diff-policy").value);
  setCount("verificacion", "");
  setRevocationNote();
  return run(
    "verificacion",
    online() ? "Verificando y descargando revocación…" : "Verificando…",
    () => postForm("/verify", body),
    (data) => {
      out("verificacion").replaceChildren(renderReport(state.file.name, data));
      setCount("verificacion", data.pades_level.replace(/^PAdES /, ""));
      setRevocationNote(data.revocation);
    },
    "No se pudo verificar el PDF",
  );
}

// --------------------------------------------------------------------------- Inspección
function fillPicker() {
  const picker = $("#cert-picker");
  const selected = picker.value;
  const options = state.certs.map((c) => {
    const option = el("option", null, `${cn(c.subject)} — ${ROLES[c.type]}`);
    option.value = c.der_b64;
    return option;
  });
  const placeholder = el("option", null, state.certs.length ? "Elegí un certificado…" : "Subí un PDF para elegir uno de sus certificados");
  placeholder.value = "";
  picker.replaceChildren(placeholder, ...options);
  picker.disabled = !state.certs.length;
  picker.value = state.certs.some((c) => c.der_b64 === selected) ? selected : "";
  setCount("inspeccion", state.certs.length ? plural(state.certs.length, "cert", "certs") : "");
}

function inspectFromPdf(der, { switchTab = true } = {}) {
  $("#cert-picker").value = der;
  if (switchTab) selectTab("inspeccion");
  persistView({ inspected: der });
  const body = new FormData();
  body.append("b64", der);
  return run(
    "inspeccion",
    "Leyendo el certificado…",
    () => postForm("/certificates/inspect", body),
    (data) => out("inspeccion").replaceChildren(renderInspection(data.certificates, (text) => {
      $("#inspeccion-status").textContent = text;
    }, { origin: "pdf" })),
    "No se pudo leer el certificado",
  );
}

$("#cert-picker").addEventListener("change", (event) => {
  if (event.target.value) inspectFromPdf(event.target.value);
});

// --------------------------------------------------------------------------- el PDF
// `inspected`: el certificado que se estaba mirando, para volver a abrirlo al restaurar.
async function usePdf(file, { inspected = null } = {}) {
  state.file = file;
  state.certs = [];
  fillPicker();
  state.tickets.inspeccion++; // descarta una inspección en curso del PDF anterior
  message("inspeccion", EMPTY.inspeccion);
  $("#pdf-status").textContent = kb(file);
  $("#pdf-clear").hidden = false;
  persistView({ inspected });

  const certificates = loadCertificates();
  loadVerify();
  await certificates;
  if (inspected && state.certs.some((c) => c.der_b64 === inspected)) inspectFromPdf(inspected, { switchTab: false });
}

function clearPdf() {
  state.file = null;
  state.certs = [];
  for (const tab of TABS) {
    state.tickets[tab]++;
    setCount(tab, "");
    message(tab, EMPTY[tab]);
  }
  fillPicker();
  setRevocationNote();
  $("#pdf").value = "";
  $("#pdf-status").textContent = "";
  $("#pdf-clear").hidden = true;
  forget("firmas-pdf");
  persistView({ inspected: null });
}

$("#pdf-form").addEventListener("submit", (event) => event.preventDefault());

$("#pdf").addEventListener("change", (event) => {
  const file = event.target.files[0];
  if (!file) return;
  save("firmas-pdf", file);
  usePdf(file);
});
$("#pdf-clear").addEventListener("click", clearPdf);

$("#fetch-missing").addEventListener("change", (event) => {
  persistView({ fetchMissing: event.target.checked });
  if (state.file) loadCertificates();
});
for (const b of document.querySelectorAll("[data-revocation]")) {
  b.addEventListener("click", () => {
    if (b.dataset.revocation === state.view.revocation) return;
    persistView({ revocation: b.dataset.revocation });
    applyRevocationMode();
    if (state.file) loadVerify();
  });
}
$("#validation-time").addEventListener("change", (event) => {
  persistView({ validationTime: event.target.value });
  if (state.file) loadVerify();
});
$("#diff-policy").addEventListener("change", (event) => {
  persistView({ diffPolicy: event.target.value });
  if (state.file) loadVerify();
});

// --------------------------------------------------------------------------- arranque
async function restore() {
  Object.assign(state.view, (await loadSaved("firmas-view")) || {});
  $("#fetch-missing").checked = state.view.fetchMissing;
  $("#diff-policy").value = state.view.diffPolicy;
  applyRevocationMode();
  const fromHash = location.hash.slice(1);
  selectTab(TABS.includes(fromHash) ? fromHash : TABS.includes(state.view.tab) ? state.view.tab : "certificados");

  const file = await loadSaved("firmas-pdf");
  if (file instanceof Blob) {
    restoreFileInput($("#pdf"), file);
    await usePdf(file, { inspected: state.view.inspected });
  }
}

for (const tab of TABS) message(tab, EMPTY[tab]);
setupThemeButton($("#theme"));
restore();
