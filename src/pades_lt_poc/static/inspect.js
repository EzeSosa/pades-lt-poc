// Tab Inspección: detalle de un certificado (respuesta de POST /certificates/inspect).

const ATTRIBUTES = {
  commonName: "Nombre común (CN)",
  serialNumber: "Número de serie (serialNumber)",
  givenName: "Nombre",
  surname: "Apellido",
  title: "Cargo",
  organizationName: "Organización (O)",
  organizationalUnitName: "Unidad (OU)",
  organizationIdentifier: "Identificador de la organización",
  countryName: "País (C)",
  stateOrProvinceName: "Provincia (ST)",
  localityName: "Localidad (L)",
  streetAddress: "Dirección",
  postalCode: "Código postal",
  emailAddress: "Email",
};
const EXTENSIONS = {
  basicConstraints: "Restricciones básicas",
  keyUsage: "Uso de la clave",
  extendedKeyUsage: "Uso extendido de la clave",
  authorityInfoAccess: "Acceso a la información de la autoridad (AIA)",
  subjectInfoAccess: "Acceso a la información del sujeto",
  cRLDistributionPoints: "Puntos de distribución de CRL",
  freshestCRL: "CRL delta",
  certificatePolicies: "Políticas de certificación",
  subjectAltName: "Nombres alternativos del sujeto",
  issuerAltName: "Nombres alternativos del emisor",
  subjectKeyIdentifier: "Identificador de clave del sujeto",
  authorityKeyIdentifier: "Identificador de clave de la autoridad",
  OCSPNoCheck: "OCSP no-check",
  msCertificateTemplateName: "Plantilla de certificado (Microsoft)",
  msCertificateTemplate: "Plantilla de certificado (Microsoft)",
  msCAVersion: "Versión de la CA (Microsoft)",
  msPreviousCACertHash: "Hash del certificado anterior de la CA (Microsoft)",
  msApplicationPolicies: "Políticas de aplicación (Microsoft)",
};

function certRole(cert) {
  if (cert.is_ca) return cert.self_signed ? "CA raíz" : "CA intermedia";
  return cert.self_signed ? "Entidad final (autofirmado)" : "Entidad final";
}

function validityBadge(validity) {
  if (validity.status === "expired") return badge("Vencido", "bad");
  if (validity.status === "not_yet_valid") return badge("Todavía no vigente", "warn");
  const days = validity.days_left;
  return badge(`Vigente · ${days === 1 ? "queda 1 día" : `quedan ${days} días`}`, days < 30 ? "warn" : "ok");
}

function camel(snake) {
  return snake.replace(/_(.)/g, (_, c) => c.toUpperCase());
}

function nameFacts(attributes) {
  // El DER va de lo general a lo particular (C … CN): se muestra al revés, como RFC 4514.
  return facts([...attributes].reverse().map((a) => {
    const term = el("dt", null, ATTRIBUTES[a.name] || a.name);
    if (!ATTRIBUTES[a.name]) term.append(el("span", "oid", a.oid));
    // En los certificados de la PKI argentina el CUIL/CUIT del titular va en serialNumber.
    const id = a.name === "serialNumber" && /^(CUIL|CUIT)\b/i.test(a.value) ? badge(a.value.split(/\s+/)[0].toUpperCase(), "ok") : null;
    return [term, el("span", a.name === "serialNumber" ? "mono" : null, a.value), id];
  }));
}

function lines(values) {
  const ul = el("ul");
  ul.append(...values.map((v) => el("li", null, v)));
  return ul;
}

function extensionFacts(extensions) {
  if (!extensions.length) return el("p", "card-note", "No tiene extensiones (certificado v1).");
  return facts(extensions.map((ext) => {
    const term = el("dt", null, EXTENSIONS[ext.name] || ext.name);
    term.append(el("span", "oid", ext.oid));
    const values = ext.name === "keyUsage" ? ext.values.map(camel) : ext.values;
    return [term, ext.critical ? badge("Crítica", "warn") : null, values.length ? lines(values) : el("span", "sub", "(vacía)")];
  }));
}

function inStoreLink() {
  const link = el("a", "chip in-store", "En la fuente ↗");
  link.href = "/ui/fuente";
  link.title = "Ver la fuente de certificados";
  return link;
}

// Alta en la fuente: sólo para CAs. Una raíz puede quedar, o no, como ancla de confianza.
// `origin`: "manual" (certificado suelto) o "pdf" (salió de un PDF firmado).
function storeActions(cert, onStatus, origin) {
  if (!cert.is_ca) return [];
  if (cert.in_store) return [inStoreLink()];

  const wrap = el("div", "store-add");
  const add = el("button", "secondary");
  add.type = "button";
  add.append(icon("plus"), "Agregar a la fuente");
  add.setAttribute("aria-label", `Agregar ${cn(cert.subject_rfc4514)} a la fuente de certificados`);
  wrap.append(add);

  let trust = null;
  if (cert.self_signed) {
    const label = el("label", "check");
    trust = el("input");
    trust.type = "checkbox";
    trust.checked = true;
    label.append(trust, el("span", null, "Confiar en esta raíz"));
    wrap.append(label);
  }

  add.addEventListener("click", async () => {
    const body = new FormData();
    body.append("b64", cert.der_b64);
    body.append("origin", origin);
    body.append("trusted", trust ? trust.checked : false);
    add.disabled = true;
    try {
      await postForm("/store/certificates", body);
      wrap.replaceWith(inStoreLink());
      // Para que otras vistas de la página (la cadena en /ui/firmas) se enteren.
      document.dispatchEvent(new CustomEvent("store:added", { detail: { sha256: cert.fingerprints.sha256 } }));
      onStatus(`${cn(cert.subject_rfc4514)} se agregó a la fuente`);
    } catch (error) {
      add.disabled = false;
      onStatus(`No se pudo agregar a la fuente: ${error.message}`);
    }
  });
  return [wrap];
}

function inspectionCard(cert, onStatus, origin) {
  const article = el("article");
  const head = el("div", "card-head");
  head.append(
    el("h3", null, cn(cert.subject_rfc4514)),
    el("span", "chip", certRole(cert)),
    el("span", "spacer"),
    validityBadge(cert.validity),
    el("span", "sub mono", cert.subject_rfc4514),
  );

  const actions = el("div", "card-actions");
  actions.append(
    ...certActions(cert.der_b64, cert.subject_rfc4514, cert.serial_number, onStatus),
    ...storeActions(cert, onStatus, origin),
  );

  const key = cert.public_key;
  const keyText = [key.type, key.size && `${key.size} bits`, key.curve].filter(Boolean).join(" · ");

  article.append(
    head,
    actions,
    el("h4", null, "Sujeto"),
    nameFacts(cert.subject),
    el("h4", null, "Emisor"),
    cert.self_signed ? el("p", "card-note", "Autofirmado: el emisor es el mismo sujeto y la firma verifica con su propia clave.") : nameFacts(cert.issuer),
    el("h4", null, "Certificado"),
    facts([
      ["Vigencia", el("span", "mono", `${when(cert.validity.not_before)} → ${when(cert.validity.not_after)}`)],
      ["Número de serie", el("span", "mono", cert.serial_number)],
      ["Versión", el("span", null, `v${cert.version}`)],
      ["Algoritmo de firma", el("span", "mono", cert.signature_algorithm)],
      ["Clave pública", el("span", null, keyText)],
      ["Huella SHA-256", el("span", "mono", cert.fingerprints.sha256.match(/../g).join(":"))],
      ["Huella SHA-1", el("span", "mono", cert.fingerprints.sha1.match(/../g).join(":"))],
    ]),
    el("h4", null, "Extensiones"),
    extensionFacts(cert.extensions),
  );
  return article;
}

function renderInspection(certificates, onStatus, { origin = "manual" } = {}) {
  const fragment = document.createDocumentFragment();
  if (certificates.length > 1) {
    const title = el("div", "summary");
    title.append(el("h2", null, `${certificates.length} certificados`));
    fragment.append(title);
  }
  fragment.append(...certificates.map((c) => inspectionCard(c, onStatus, origin)));
  return fragment;
}
