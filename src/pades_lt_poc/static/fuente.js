// /ui/fuente: la fuente de certificados (/store/certificates): ver, habilitar, confiar, anotar y
// borrar. Las altas se hacen desde el reporte de inspección (inspect.js), donde se ve qué es
// el certificado antes de agregarlo.

const KINDS = { root: "Raíz", intermediate: "Intermedia" };
const ORIGINS = { seed: "carga inicial", manual: "manual", pdf: "desde un PDF" };

// `panels`: el detalle de cada certificado abierto, armado una sola vez. Se reusa al redibujar la
// lista para no volver a pedir la inspección ni perder las notas que se están escribiendo.
const state = { certs: [], kind: "all", query: "", open: new Set(), panels: new Map() };

const setSeedStatus = (text) => { $("#seed-status").textContent = text; };
const setListStatus = (text) => { $("#list-status").textContent = text; };

// --------------------------------------------------------------------------- lista
async function load() {
  try {
    const data = await api("/store/certificates");
    state.certs = data.certificates;
    renderSummary(data.summary);
    renderList();
  } catch (error) {
    $("#list").replaceChildren(el("li", "card-error", `No se pudo leer la fuente: ${error.message}`));
  }
}

function renderSummary(summary) {
  const cell = (label, value, sub) => {
    const div = el("div");
    div.append(el("span", "label", label), el("span", "value", value), el("span", "sub", sub));
    return div;
  };
  $("#summary").replaceChildren(
    cell("Raíces confiables", String(summary.trusted_roots), "Anclas de confianza de /verify, más la raíz de la PoC"),
    cell("Intermedios", String(summary.intermediates), "Completan cadenas que el PDF no trae"),
    cell("Deshabilitados", String(summary.disabled), "Están en la fuente, pero el validador no los usa"),
    cell("Total", String(summary.total), "Raíces e intermedios cargados"),
  );
}

function matches(cert) {
  if (state.kind !== "all" && cert.kind !== state.kind) return false;
  const q = state.query.trim().toLowerCase();
  return !q || [cert.subject, cert.issuer, cert.notes].some((text) => text.toLowerCase().includes(q));
}

function renderList() {
  const visible = state.certs.filter(matches);
  const list = $("#list");
  list.replaceChildren(...visible.map(row));
  if (!visible.length) list.append(el("li", "card-note", state.certs.length ? "Ningún certificado coincide con el filtro." : "La fuente está vacía."));
  $("#list-count").textContent = visible.length === state.certs.length ? plural(state.certs.length, "certificado", "certificados") : `${visible.length} de ${state.certs.length}`;
}

function button(label, className, onClick, ariaLabel) {
  const b = el("button", className, label);
  b.type = "button";
  if (ariaLabel) b.setAttribute("aria-label", ariaLabel);
  b.addEventListener("click", onClick);
  return b;
}

function row(cert) {
  const name = cn(cert.subject);
  const li = el("li", cert.enabled ? null : "disabled");
  const info = el("div", "cert-info");

  const title = el("div", "cert-title");
  title.append(el("span", "role", KINDS[cert.kind]), el("span", "cn", name), el("span", "source", ORIGINS[cert.origin]));
  const badges = el("div", "cert-title");
  if (cert.kind === "root") badges.append(cert.trusted ? badge("Confiable", "ok") : el("span", "chip", "No confiable"));
  if (!cert.enabled) badges.append(badge("Deshabilitado", "warn"));
  if (cert.validity_status === "expired") badges.append(badge("Vencido", "bad"));
  if (cert.validity_status === "not_yet_valid") badges.append(badge("Todavía no vigente", "warn"));
  if (badges.children.length) title.append(...badges.children);

  const meta = el("div", "meta");
  meta.append(
    el("span", null, `Emisor: ${cn(cert.issuer)}${cert.kind === "root" ? " (autofirmado)" : ""}`),
    el("span", null, `Vigencia: ${date(cert.not_before)} – ${date(cert.not_after)}`),
    el("span", "mono", `SHA-256 ${cert.sha256.slice(0, 16)}…`),
  );
  info.append(title, meta);
  if (cert.notes) info.append(el("p", "row-notes", cert.notes));

  const open = state.open.has(cert.id);
  const actions = el("div", "actions");
  const detail = button(open ? "Ocultar detalle" : "Ver detalle", "secondary", () => toggleDetail(cert.id), `Ver detalle de ${name}`);
  detail.setAttribute("aria-expanded", open);
  actions.append(
    detail,
    button(cert.enabled ? "Deshabilitar" : "Habilitar", "secondary", () =>
      change(cert, { enabled: !cert.enabled }, `${name} ${cert.enabled ? "deshabilitado" : "habilitado"}`)),
  );
  if (cert.kind === "root") {
    actions.append(button(cert.trusted ? "Dejar de confiar" : "Confiar", "secondary", () =>
      change(cert, { trusted: !cert.trusted }, `${name}: ${cert.trusted ? "ya no es" : "ahora es"} ancla de confianza`)));
  }
  actions.append(button("Borrar", "secondary danger", () => remove(cert), `Borrar ${name} de la fuente`));

  li.append(info, actions);
  if (open) li.append(detailPanel(cert));
  return li;
}

// --------------------------------------------------------------------------- detalle y notas
function detailPanel(cert) {
  let entry = state.panels.get(cert.id);
  if (!entry) {
    entry = buildDetailPanel(cert);
    state.panels.set(cert.id, entry);
  } else if (entry.savedNotes !== cert.notes) {
    // Las notas cambiaron en la fuente (se guardaron): el campo pasa a mostrar lo guardado.
    entry.input.value = entry.savedNotes = cert.notes;
  }
  return entry.panel;
}

function buildDetailPanel(cert) {
  const panel = el("div", "row-detail");
  const out = el("div", "results");
  out.append(el("p", "card-note", "Leyendo el certificado…"));

  const notesForm = el("form", "notes-form");
  const label = el("label", "field grow");
  const input = el("input");
  input.type = "text";
  input.value = cert.notes;
  label.append(el("span", null, "Notas"), input);
  const save = el("button", "secondary", "Guardar notas");
  save.type = "submit";
  notesForm.append(label, save);
  notesForm.addEventListener("submit", (event) => {
    event.preventDefault();
    change(cert, { notes: input.value }, `Notas de ${cn(cert.subject)} guardadas`);
  });

  panel.append(notesForm, out);
  const body = new FormData();
  body.append("b64", cert.der_b64);
  postForm("/certificates/inspect", body)
    .then((data) => out.replaceChildren(renderInspection(data.certificates, setListStatus)))
    .catch((error) => out.replaceChildren(el("div", "error-box", `No se pudo leer el certificado: ${error.message}`)));
  return { panel, input, savedNotes: cert.notes };
}

function toggleDetail(id) {
  if (state.open.has(id)) {
    state.open.delete(id);
    state.panels.delete(id);
  } else state.open.add(id);
  renderList();
}

// --------------------------------------------------------------------------- modificaciones y bajas
async function change(cert, changes, done) {
  try {
    await patchJSON(`/store/certificates/${cert.id}`, changes);
    setListStatus(done);
    await load();
  } catch (error) {
    setListStatus(`No se pudo modificar: ${error.message}`);
  }
}

async function remove(cert) {
  const name = cn(cert.subject);
  const seedNote = cert.origin === "seed" ? " Es de la carga inicial: se puede recuperar con «Restaurar carga inicial»." : "";
  if (!confirm(`¿Borrar ${name} de la fuente?${seedNote}`)) return;
  try {
    await api(`/store/certificates/${cert.id}`, { method: "DELETE" });
    state.open.delete(cert.id);
    state.panels.delete(cert.id);
    setListStatus(`${name} se borró de la fuente`);
    await load();
  } catch (error) {
    setListStatus(`No se pudo borrar: ${error.message}`);
  }
}

// --------------------------------------------------------------------------- carga inicial
$("#seed").addEventListener("click", async () => {
  try {
    const { added } = await postForm("/store/certificates/seed", new FormData());
    setSeedStatus(added.length ? `Se restauraron: ${added.map((c) => cn(c.subject)).join(", ")}` : "La carga inicial ya estaba completa");
    await load();
  } catch (error) {
    setSeedStatus(`No se pudo restaurar: ${error.message}`);
  }
});

// --------------------------------------------------------------------------- filtros
for (const b of document.querySelectorAll(".segmented button")) {
  b.addEventListener("click", () => {
    state.kind = b.dataset.kind;
    for (const other of document.querySelectorAll(".segmented button")) other.setAttribute("aria-pressed", other === b);
    renderList();
  });
}
$("#search").addEventListener("input", (event) => {
  state.query = event.target.value;
  renderList();
});

setupThemeButton($("#theme"));
load();
