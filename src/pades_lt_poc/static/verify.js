// Tab Verificación: reporte de POST /verify.

const COVERAGE = {
  ENTIRE_FILE: ["Todo el archivo", "ok", null],
  // Lo normal en B-LT/B-LTA: después de firmar se agregan el DSS y el sello de documento.
  ENTIRE_REVISION: ["Toda su revisión", "ok", "Lo agregado después se evalúa en Modificaciones"],
  CONTIGUOUS_BLOCK_FROM_START: ["Un bloque desde el inicio, no una revisión completa", "bad", null],
};
const MODIFICATIONS = {
  NONE: ["Sin cambios", "ok"],
  LTA_UPDATES: ["Sólo actualizaciones LTV / LTA", "ok"],
  FORM_FILLING: ["Llenado de formularios", "warn"],
  ANNOTATIONS: ["Anotaciones", "warn"],
  OTHER: ["Otros cambios", "bad"],
};

// Motivo de cada camino probado cuando la firma no es confiable (trust_problem.paths[].reason).
const PATH_REASONS = {
  revoked: ["Revocado", "bad"],
  stale_revocation: ["Revocación vencida", "warn"],
  missing_revocation: ["Sin revocación", "warn"],
  algorithm: ["Algoritmo no permitido", "bad"],
  expired: ["Certificado vencido", "warn"],
  not_yet_valid: ["Todavía no vigente", "warn"],
  other: ["No valida", "bad"],
};

function yesNo(value, yes, no) {
  return value ? badge(yes, "ok") : badge(no, "bad");
}

function commonName(humanFriendly) {
  // pyHanko: "Common Name: Firmante de Prueba, Organization: PoC PAdES, Country: AR"
  const match = /Common Name: (.*?)(?:, [A-Z][\w ]*: |$)/.exec(humanFriendly);
  return match ? match[1] : humanFriendly;
}

function overviewCell(label, value, sub, valueClass = "value") {
  const cell = el("div");
  cell.append(el("span", "label", label));
  cell.append(value instanceof Node ? value : el("span", valueClass, value));
  if (sub) cell.append(el("span", "sub", sub));
  return cell;
}

function revocationCell(revocation) {
  if (revocation.mode !== "online") return overviewCell("Revocación", "Sólo la del PDF", "Sin conexión: CRL y OCSP embebidas");
  const { crls, ocsps } = revocation.fetched;
  return overviewCell("Revocación", "Descargada", `Con conexión: ${plural(crls.length, "CRL", "CRL")} · ${ocsps.length} OCSP, además de lo del PDF`);
}

function overview(body, sigs) {
  const online = body.revocation.mode === "online";
  const ok = sigs.filter((s) => s.bottom_line).length;
  const grid = el("section", "overview");
  grid.setAttribute("aria-label", "Resumen");
  grid.append(
    overviewCell("Nivel alcanzado", body.pades_level, "Nivel máximo que cumplen todas las firmas", "value level"),
    overviewCell("Firmas", `${ok} de ${sigs.length} válidas`, sigs.length && ok === sigs.length ? "Todas pasan la validación" : "Revisá las que no pasan"),
    overviewCell(
      "DSS",
      body.dss ? `${body.dss.Certs} certs · ${body.dss.OCSPs} OCSP · ${body.dss.CRLs} CRL` : "No tiene",
      body.dss
        ? "Material de validación embebido"
        : online ? "Sin DSS: la revocación salió sólo de lo descargado" : "Sin DSS no hay revocación: ninguna firma es confiable",
    ),
    revocationCell(body.revocation),
    overviewCell(
      "Fuente de certificados",
      `${plural(body.certificate_store.trusted_roots, "raíz", "raíces")} · ${plural(body.certificate_store.intermediates, "intermedio", "intermedios")}`,
      body.certificate_store.self_contained ? "El PDF alcanzó solo: no hizo falta" : "Se usó para completar cadenas",
    ),
    overviewCell(
      "Validado",
      body.validation_time.mode === "now" ? "A la hora actual" : "A la hora declarada",
      body.diff_policy.mode === "default" ? "Modificaciones: política por defecto" : "Modificaciones: tolera entradas libres sin asignar",
    ),
  );
  return grid;
}

// Intermedios que no venían en el PDF y salieron de la fuente; null si no hubo.
function fromStore(list) {
  if (!list?.length) return null;
  const wrap = el("span", "sub");
  wrap.append(badge("Completada con la fuente", "warn"), ` ${list.map((c) => commonName(c.subject)).join(", ")}`);
  return wrap;
}

// El porqué de "No confiable", para la fila de la ficha; [] si es confiable.
function problemFacts(problem) {
  if (!problem) return [];
  return [el("span", "problem", problem.summary), problem.hint && el("span", "sub", problem.hint)];
}

// Los caminos que se probaron hasta una raíz y por qué falló cada uno, de la hoja a la raíz.
function pathsDetails(sig) {
  const sections = [
    ["Firmante", sig.trust_problem],
    ["Sello de tiempo", sig.signature_timestamp?.trust_problem],
  ].filter(([, problem]) => problem?.paths.length);
  if (!sections.length) return null;

  const details = el("details");
  const summary = el("summary");
  summary.append(el("strong", null, "Por qué no es confiable"), el("span", "sub", "Caminos probados hasta una raíz"), el("span", "toggle", "Ver"));
  details.append(summary);
  for (const [label, problem] of sections) {
    const list = el("ul", "paths");
    list.setAttribute("aria-label", `Caminos probados · ${label}`);
    list.append(...problem.paths.map((path) => {
      const li = el("li");
      const head = el("div", "path-head");
      const [text, tone] = path.reason ? PATH_REASONS[path.reason] || [path.reason, "bad"] : ["Valida", "ok"];
      const chain = path.chain.map((c) => `${c.subject} (hasta ${date(c.not_after)})`).join(" → ");
      head.append(el("span", "role", label), el("span", "path-chain", chain), badge(text, tone));
      li.append(head);
      if (path.message) li.append(el("span", "mono sub", path.message));
      return li;
    }));
    details.append(list);
  }
  return details;
}

// Lo descargado en modo con conexión: CRLs, respuestas OCSP y emisores por AIA.
function fetchedDetails(fetched) {
  const items = [
    ...fetched.crls.map((c) => [
      "CRL",
      commonName(c.issuer),
      [
        c.next_update ? `vigente hasta ${when(c.next_update)}` : "sin próxima actualización",
        c.from_cache && `del caché: descargada ${when(c.fetched_at)}`,
      ].filter(Boolean).join(" · "),
    ]),
    ...fetched.ocsps.map((r) => ["OCSP", `Serie ${r.serial_number}: ${r.status === "good" ? "no revocado" : r.status}`, `emitida ${when(r.produced_at)}`]),
    ...fetched.certs.map((c) => ["AIA", commonName(c.subject), "emisor descargado"]),
  ];
  if (!items.length) return null;

  const details = el("details");
  const summary = el("summary");
  summary.append(el("strong", null, "Revocación descargada"), el("span", "sub", plural(items.length, "elemento", "elementos")), el("span", "toggle", "Ver"));
  const list = el("ul", "paths");
  list.append(...items.map(([kind, what, sub]) => {
    const li = el("li");
    const head = el("div", "path-head");
    head.append(el("span", "role", kind), el("span", "path-chain", what));
    li.append(head, el("span", "sub", sub));
    return li;
  }));
  details.append(summary, list);
  const article = el("article", "fetched");
  article.append(details);
  return article;
}

function callout(tone, title, text) {
  const box = el("div", `callout ${tone}`);
  box.append(el("strong", null, title), document.createTextNode(text));
  return box;
}

function signatureReportCard(sig, online) {
  const article = el("article");
  const head = el("div", "card-head");
  head.append(el("h3", null, sig.field));
  article.append(head);

  if (sig.type === "DocTimeStamp") {
    head.append(el("span", "chip", "Sello de documento"));
    article.append(el("p", "card-note", "Sello de tiempo de documento (B-LTA): este endpoint no lo valida por separado; cuenta para el nivel alcanzado."));
    return article;
  }

  head.append(
    el("span", "chip", "Firma"),
    el("span", "spacer"),
    sig.bottom_line ? badge("Válida", "ok") : badge("No válida", "bad"),
  );

  const [coverage, coverageTone, coverageNote] = COVERAGE[sig.coverage] || [sig.coverage, "warn", null];
  const mods = sig.modifications;
  const [level, levelTone] = MODIFICATIONS[mods.level] || [mods.level ?? "Sin análisis", "warn"];
  const ts = sig.signature_timestamp;

  article.append(facts([
    ["Firmante", el("strong", null, commonName(sig.signer)), el("span", "sub", sig.signer)],
    ["Integridad", yesNo(sig.intact, "Íntegra", "Alterada"), el("span", "sub", "El contenido firmado no cambió")],
    ["Firma criptográfica", yesNo(sig.valid, "Válida", "Inválida")],
    [
      "Confianza",
      yesNo(sig.trusted, "Confiable", "No confiable"),
      el("span", "sub", online ? "Cadena hasta una raíz de confianza, con revocación embebida o descargada" : "Cadena hasta una raíz de confianza, con revocación embebida"),
      fromStore(sig.completed_from_store),
      ...problemFacts(sig.trust_problem),
    ],
    ["Cobertura", badge(coverage, coverageTone), coverageNote && el("span", "sub", coverageNote)],
    [
      "Modificaciones",
      badge(level, mods.suspicious ? "bad" : levelTone),
      mods.docmdp_ok === false ? badge("Viola los permisos DocMDP", "bad") : null,
      mods.suspicious ? el("span", "suspicious", mods.suspicious) : null,
    ],
    [
      "Sello de tiempo",
      ...(ts
        ? [
            el("span", "mono", when(ts.time)),
            el("span", null, commonName(ts.tsa)),
            yesNo(ts.valid, "Válido", "Inválido"),
            yesNo(ts.trusted, "Confiable", "No confiable"),
            fromStore(ts.completed_from_store),
            ...problemFacts(ts.trust_problem),
          ]
        : [badge("Sin sello", "warn"), el("span", "sub", "Sin sello no llega a B-T")]),
    ],
    [
      "Validada a",
      el("span", "mono", when(sig.validated_at.time)),
      el("span", "sub", sig.validated_at.source === "now" ? "hora actual" : "hora declarada por la firma"),
    ],
    ["SubFilter", el("span", "mono", sig.subfilter)],
  ]));

  const details = el("details");
  const summary = el("summary");
  summary.append(el("strong", null, "Detalle de pyHanko"), el("span", "toggle", "Ver"));
  details.append(summary, el("pre", null, sig.details));
  const paths = pathsDetails(sig);
  if (paths) article.append(paths);
  article.append(details);
  return article;
}

function renderReport(fileName, body) {
  const fragment = document.createDocumentFragment();
  const sigs = body.signatures.filter((s) => s.type === "Signature");

  const title = el("div", "summary");
  const print = el("button", "secondary no-print", "Imprimir / guardar PDF");
  print.type = "button";
  print.addEventListener("click", () => window.print());
  title.append(el("h2", null, `Reporte de verificación · ${fileName}`), print);
  fragment.append(title, overview(body, sigs));

  if (body.validation_time.warning) fragment.append(callout("warn", "Validado a la hora declarada", body.validation_time.warning));
  if (body.diff_policy.note) fragment.append(callout("warn", "Análisis de modificaciones relajado", body.diff_policy.note));
  if (body.revocation.note) fragment.append(callout("warn", "Validado con conexión: revocación descargada", body.revocation.note));
  if (body.certificate_store.note) fragment.append(callout("warn", "Cadena completada con la fuente de certificados", body.certificate_store.note));
  const fetched = body.revocation.fetched && fetchedDetails(body.revocation.fetched);
  if (fetched) fragment.append(fetched);

  const cards = el("div", "cards");
  cards.append(...body.signatures.map((s) => signatureReportCard(s, body.revocation.mode === "online")));
  fragment.append(cards);
  return fragment;
}
