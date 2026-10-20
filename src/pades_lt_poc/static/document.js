// Tab Documento: el análisis del PDF (POST /document), más allá de sus firmas.
// Traduce la respuesta, sin recalcular nada: los hallazgos y su severidad los decide la API.

const SEVERITY = {
  critical: ["Crítico", "bad"],
  warning: ["Advertencia", "warn"],
  info: ["Informativo", "chip"],
};

const CHANGE_KINDS = {
  page_content: "Contenido de página",
  page: "Página",
  page_tree: "Árbol de páginas",
  resource: "Fuente o imagen",
  annotation: "Anotación",
  form_field: "Campo de formulario",
  signature: "Firma",
  dss: "DSS",
  acroform: "Formulario (/AcroForm)",
  catalog: "Catálogo",
  metadata: "Metadatos",
  embedded_file: "Adjunto",
  action: "Acción",
  structure: "Estructura",
  other: "Otro objeto",
};
const CHANGE_TYPES = { added: "agregado", modified: "modificado", freed: "liberado" };

const PERMISSIONS = {
  print: "Imprimir",
  modify: "Modificar",
  copy: "Copiar texto",
  annotate: "Anotar",
  fill_forms: "Completar campos",
  accessibility: "Accesibilidad",
  assemble: "Armar páginas",
  print_high_quality: "Imprimir en alta",
};

const FIELD_TYPES = {
  text: "Texto",
  checkbox: "Casilla",
  radio: "Opción",
  pushbutton: "Botón",
  choice: "Lista",
  signature: "Firma",
  unknown: "Otro",
};

function severityBadge(severity) {
  const [text, tone] = SEVERITY[severity] || [severity, "warn"];
  return tone === "chip" ? el("span", "chip", text) : badge(text, tone);
}

function bytes(n) {
  if (n == null) return "—";
  return n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`;
}


function findingsList(findings) {
  const list = el("ul", "paths findings");
  list.setAttribute("aria-label", "Hallazgos del documento");
  list.append(...findings.map((f) => {
    const li = el("li");
    const head = el("div", "path-head");
    head.append(severityBadge(f.severity), el("span", "path-chain", f.message));
    li.append(head);
    return li;
  }));
  return list;
}

function protectionRows(protection) {
  if (!protection) return [["Protección", el("span", "sub", "No se pudo leer")]];
  const e = protection.encryption;
  const rows = [];
  if (e) {
    const perms = e.permissions;
    rows.push([
      "Cifrado",
      el("strong", null, `${e.algorithm}${e.key_bits ? ` · ${e.key_bits} bits` : ""}`),
      el("span", "sub", `${e.handler}${e.revision ? ` · R${e.revision}` : ""} · abre sin contraseña (sólo clave de propietario)`),
    ]);
    if (perms) {
      const list = el("ul");
      for (const [key, label] of Object.entries(PERMISSIONS)) {
        const li = el("li");
        li.append(perms[key] ? badge("Sí", "ok") : badge("No", "bad"), ` ${label}`);
        list.append(li);
      }
      rows.push(["Permisos", list]);
    }
  } else {
    rows.push(["Cifrado", badge("Sin cifrar", "ok")]);
  }
  const c = protection.certification;
  rows.push(c
    ? ["Certificación", el("strong", null, `DocMDP P=${c.permission} · ${c.field}`), el("span", "sub", c.meaning), c.first_signature ? null : badge("No es la primera firma", "bad")]
    : ["Certificación", el("span", "sub", "No está certificado (sin DocMDP)")]);
  if (protection.field_locks.length) {
    const list = el("ul");
    list.append(...protection.field_locks.map((l) => el("li", null, `${l.field}: ${l.action}${l.fields.length ? ` (${l.fields.join(", ")})` : ""}`)));
    rows.push(["Bloqueos (FieldMDP)", list]);
  }
  if (protection.usage_rights) rows.push(["Derechos de uso", el("span", null, "/Perms /UR3 (Adobe Reader)")]);
  return rows;
}

function structureRows(s, revisions) {
  if (!s) return [["Estructura", el("span", "sub", "No se pudo leer")]];
  const xrefs = [...new Set(revisions.map((r) => r.xref))].join(", ");
  return [
    ["Versión", el("strong", null, `PDF ${s.version}`), s.catalog_version ? el("span", "sub", `cabecera ${s.header_version}, catálogo ${s.catalog_version}`) : null],
    ["Páginas y revisiones", el("span", null, `${plural(s.pages, "página", "páginas")} · ${plural(s.revisions, "revisión", "revisiones")}`), xrefs && el("span", "sub", `xref: ${xrefs}${s.object_streams ? " · object streams" : ""}`)],
    ["Conformidad", s.pdfa ? el("strong", null, `Declara PDF/A-${s.pdfa}`) : el("span", "sub", "No declara PDF/A"), s.tagged ? el("span", "chip", "Etiquetado") : null, s.linearized ? el("span", "chip", "Linealizado") : null],
    ["Generado con", el("span", null, [s.producer, s.creator].filter(Boolean).join(" · ") || "—"), s.extensions.length ? el("span", "sub", `Extensiones: ${s.extensions.join(", ")}`) : null],
    ["Después del %%EOF", s.trailing_bytes ? badge(bytes(s.trailing_bytes), "warn") : el("span", "sub", "Nada")],
  ];
}

function formRows(form) {
  if (!form) return [["Formulario", el("span", "sub", "No tiene")]];
  const list = el("ul");
  list.append(...form.fields.map((f) => {
    const li = el("li");
    li.append(el("span", "mono", f.name), ` · ${FIELD_TYPES[f.type] || f.type}`);
    if (f.type === "signature") li.append(" ", f.signed ? badge("Firmado", "ok") : badge("Vacío", "warn"));
    else if (f.value != null) li.append(el("span", "sub", ` = ${f.value}`));
    if (f.read_only) li.append(" ", el("span", "chip", "Sólo lectura"));
    if (f.actions) li.append(" ", el("span", "chip", "Con acciones"));
    return li;
  }));
  return [
    ["Campos", form.fields.length ? list : el("span", "sub", "Sin campos")],
    ["Apariencias", form.need_appearances ? badge("NeedAppearances: las regenera el visor", "warn") : el("span", "sub", "Las trae el PDF"), form.xfa ? badge("XFA", "warn") : null],
  ];
}

function activeRows(active) {
  if (!active) return [["Contenido activo", el("span", "sub", "No se pudo leer")]];
  const rows = [];
  const actions = el("ul");
  actions.append(...active.actions.map((a) => el("li", null, `${a.type} · ${a.location}`)));
  rows.push(["Acciones", active.actions.length ? actions : el("span", "sub", "Ninguna")]);
  const files = el("ul");
  files.append(...active.embedded_files.map((f) => el("li", null, `${f.name} · ${f.mime_type || "sin tipo"} · ${bytes(f.size)}`)));
  rows.push(["Adjuntos", active.embedded_files.length ? files : el("span", "sub", "Ninguno")]);
  if (active.optional_content) {
    const { groups, hidden } = active.optional_content;
    rows.push(["Capas", el("span", null, plural(groups, "capa", "capas")), hidden ? badge(`${hidden} oculta${hidden === 1 ? "" : "s"}`, "warn") : null]);
  }
  return rows;
}

function card(title, chip, ...content) {
  const article = el("article");
  const head = el("div", "card-head");
  head.append(el("h3", null, title));
  if (chip) head.append(chip instanceof Node ? chip : el("span", "chip", chip));
  article.append(head, ...content.filter(Boolean));
  return article;
}

function overviewCellDoc(label, value, sub) {
  const cell = el("div");
  cell.append(el("span", "label", label), value instanceof Node ? value : el("span", "value", value));
  if (sub) cell.append(el("span", "sub", sub));
  return cell;
}

function documentOverview(doc) {
  const { critical, warning, info } = doc.summary;
  const s = doc.structure;
  const p = doc.protection;
  const after = doc.revisions.filter((r) => r.after_signature);
  const risky = after.filter((r) => r.severity !== "info").length;
  const grid = el("section", "overview");
  grid.setAttribute("aria-label", "Resumen del documento");
  grid.append(
    overviewCellDoc(
      "Hallazgos",
      critical ? plural(critical, "crítico", "críticos") : warning ? plural(warning, "advertencia", "advertencias") : "Sin observaciones",
      [critical && warning && plural(warning, "advertencia", "advertencias"), info && plural(info, "nota", "notas")].filter(Boolean).join(" · ") || null,
    ),
    overviewCellDoc("PDF", s ? `${s.version} · ${plural(s.pages, "página", "páginas")}` : "—", s?.pdfa ? `Declara PDF/A-${s.pdfa}` : s?.producer),
    overviewCellDoc(
      "Revisiones",
      String(doc.revisions.length),
      after.length ? (risky ? `${risky} de ${after.length} posteriores a la firma con cambios a revisar` : `${plural(after.length, "posterior", "posteriores")} a la firma, sólo mantenimiento`) : "Ninguna posterior a una firma",
    ),
    overviewCellDoc(
      "Protección",
      !p ? "—" : p.encryption ? `Cifrado ${p.encryption.algorithm}` : p.certification ? `Certificado P=${p.certification.permission}` : "Sin protección",
      p?.encryption && p.certification ? `Certificado P=${p.certification.permission}` : null,
    ),
    overviewCellDoc(
      "Formulario",
      doc.form ? plural(doc.form.fields.length, "campo", "campos") : "No tiene",
      doc.form ? plural(doc.form.fields.filter((f) => f.type === "signature").length, "de firma", "de firma") : null,
    ),
    overviewCellDoc(
      "Contenido activo",
      doc.active_content ? plural(doc.active_content.actions.length, "acción", "acciones") : "—",
      doc.active_content ? plural(doc.active_content.embedded_files.length, "adjunto", "adjuntos") : null,
    ),
  );
  return grid;
}

// El diccionario de cada firma (o sello de documento), tal como está en el PDF.
function signatureDictionaryCard(d) {
  const used = d.contents.capacity ? Math.round((100 * d.contents.used) / d.contents.capacity) : 0;
  const ok = d.byte_range_regular && d.covers_revision;
  return card(d.field, d.type === "/DocTimeStamp" ? "Sello de documento" : "Diccionario de firma", facts([
    [
      "ByteRange",
      el("span", "mono", `[${d.byte_range.join(" ")}]`),
      ok ? badge(`Regular · cubre la revisión ${d.revision}`, "ok") : badge(d.byte_range_regular ? "No llega al fin de su revisión" : "Irregular", "bad"),
    ],
    ["/Contents", el("span", null, `${bytes(d.contents.used)} de ${bytes(d.contents.capacity)} reservados (${used} %)`)],
    ["Filter / SubFilter", el("span", "mono", [d.filter, d.subfilter].filter(Boolean).join(" · ")), d.references.length ? el("span", "chip", d.references.join(", ")) : null],
    ["Hora declarada (/M)", el("span", "mono", d.signing_time || "—")],
    ["Motivo y lugar", el("span", null, [d.reason, d.location].filter(Boolean).join(" · ") || "—")],
    ["Widget", el("span", null, d.visible ? `Visible en la página ${d.page}` : `Invisible${d.page ? ` (página ${d.page})` : ""}`), d.application ? el("span", "sub", `Firmado con ${d.application}`) : null],
  ]));
}

// Una fila por revisión: qué firmas la cierran, si es posterior a una firma y el riesgo de lo que agrega.
function revisionsCard(revisions) {
  const list = el("ul", "paths");
  list.setAttribute("aria-label", "Revisiones del documento");
  list.append(...revisions.map((r) => {
    const li = el("li");
    const head = el("div", "path-head");
    head.append(el("span", "role", `Rev ${r.number}`));
    head.append(el("span", "path-chain", r.number === 1 ? `Original · ${plural(r.objects, "objeto", "objetos")}` : plural(r.changes.length, "objeto", "objetos")));
    for (const field of r.signed_by) head.append(badge(`Firmada: ${field}`, "ok"));
    if (r.after_signature) head.append(severityBadge(r.severity));
    li.append(head);
    if (r.changes.length) {
      const changes = el("ul", "changes");
      changes.append(...r.changes.map((c) => {
        const item = el("li", "sub");
        const where = [c.subtype, c.page && `pág. ${c.page}`, c.keys.length && c.keys.join(" ")].filter(Boolean).join(" · ");
        item.append(el("span", "mono", c.object), ` ${CHANGE_KINDS[c.kind] || c.kind} ${CHANGE_TYPES[c.change] || c.change}${where ? ` (${where})` : ""}`);
        return item;
      }));
      li.append(changes);
    }
    return li;
  }));
  return card("Revisiones", "Actualizaciones incrementales", el("p", "card-note", "Qué escribe cada revisión. Las posteriores a la primera firma llevan el riesgo de su cambio más grave."), list);
}

function renderDocument(fileName, doc) {
  const fragment = document.createDocumentFragment();
  const title = el("div", "summary");
  const print = el("button", "secondary no-print", "Imprimir / guardar PDF");
  print.type = "button";
  print.addEventListener("click", () => window.print());
  title.append(el("h2", null, `Análisis del documento · ${fileName}`), print);
  fragment.append(
    title,
    documentOverview(doc),
    el("p", "sub", "No cambia el veredicto de las firmas (eso es la tab Verificación): explica lo que la validación no mira."),
  );

  const cards = el("div", "cards");
  cards.append(
    card("Hallazgos", doc.findings.length ? plural(doc.findings.length, "hallazgo", "hallazgos") : "Ninguno",
      doc.findings.length ? findingsList(doc.findings) : el("p", "card-note", "No hay nada que señalar en el documento.")),
    card("Estructura y protección", null, facts([...structureRows(doc.structure, doc.revisions), ...protectionRows(doc.protection)])),
    card("Formulario y contenido activo", null, facts([...formRows(doc.form), ...activeRows(doc.active_content)])),
    ...doc.signature_dictionaries.map(signatureDictionaryCard),
    revisionsCard(doc.revisions),
  );
  fragment.append(cards);
  return fragment;
}

// Lo que dice la etiqueta de la tab: lo más grave que hay.
function documentCount(doc) {
  const { critical, warning } = doc.summary;
  return critical ? plural(critical, "crítico", "críticos") : warning ? plural(warning, "aviso", "avisos") : "OK";
}
