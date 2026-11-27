/**
 * Maestro PJe Mobile - Motor da Aplicação Android
 * Gestão de Pautas, Importação de Conversas do WhatsApp para Escala & Calendário,
 * Acompanhamento de Perícias Marcadas/Pendentes e Relatórios.
 * Governança com Restrição Rígida de Escopo por Subseção e Criptografia AES-GCM 256 (MGZ1).
 */

(function () {
  "use strict";

  const Parser = (typeof window !== "undefined" && window.MaestroWhatsAppParser) ? window.MaestroWhatsAppParser : null;

  // =========================================================================
  // 0. UTILITÁRIOS DE SEGURANÇA (XSS, CSV DDE, PBKDF2, GZIP MGZ1 & AES-GCM-256)
  // =========================================================================
  function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function sanitizarCelulaCSV(valor) {
    const str = String(valor ?? "").replace(/"/g, '""');
    if (/^[\s]*[=+\-@\t\r]/.test(str)) {
      return `"'${str}"`;
    }
    return `"${str}"`;
  }

  function stringToUint8Array(str) {
    return new TextEncoder().encode(String(str ?? ""));
  }

  function uint8ArrayToString(bufferOrBytes) {
    return new TextDecoder().decode(bufferOrBytes);
  }

  function base64ToUint8Array(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  function arrayBufferToBase64(buffer) {
    let binary = "";
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  // Prefixo de 4 bytes ("MGZ1") alinhado com shared/crypto.js
  const GZIP_MAGIC_PREFIX = new Uint8Array([0x4D, 0x47, 0x5A, 0x31]);

  function suportaGzipNativoMobile() {
    return typeof CompressionStream !== "undefined" && typeof DecompressionStream !== "undefined";
  }

  async function lerStreamComoUint8ArrayMobile(readableStream) {
    const reader = readableStream.getReader();
    const chunks = [];
    let totalLen = 0;
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (value && value.byteLength > 0) {
        chunks.push(value);
        totalLen += value.byteLength;
      }
    }
    const result = new Uint8Array(totalLen);
    let offset = 0;
    for (const chunk of chunks) {
      result.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return result;
  }

  async function comprimirBytesGzipMobile(uint8Bytes) {
    if (!suportaGzipNativoMobile()) {
      throw new Error("CompressionStream (GZIP) indisponível neste navegador.");
    }
    const cs = new CompressionStream("gzip");
    const writer = cs.writable.getWriter();
    const writePromise = (async () => {
      await writer.write(uint8Bytes);
      await writer.close();
    })();
    const [compressed] = await Promise.all([
      lerStreamComoUint8ArrayMobile(cs.readable),
      writePromise
    ]);
    return compressed;
  }

  async function descomprimirBytesGzipMobile(uint8Bytes) {
    if (!suportaGzipNativoMobile()) {
      throw new Error("DecompressionStream (GZIP) indisponível neste navegador.");
    }
    const ds = new DecompressionStream("gzip");
    const writer = ds.writable.getWriter();
    const writePromise = (async () => {
      await writer.write(uint8Bytes);
      await writer.close();
    })();
    const [decompressed] = await Promise.all([
      lerStreamComoUint8ArrayMobile(ds.readable),
      writePromise
    ]);
    return decompressed;
  }

  function ehPayloadComprimidoMGZ1Mobile(bytes) {
    return Boolean(
      bytes &&
      bytes.byteLength >= 6 &&
      bytes[0] === 0x4D &&
      bytes[1] === 0x47 &&
      bytes[2] === 0x5A &&
      bytes[3] === 0x31 &&
      bytes[4] === 0x1F &&
      bytes[5] === 0x8B
    );
  }

  async function verificarHashPBKDF2Mobile(segredoDigitado, hashEsperadoBase64, saltBase64) {
    if (!segredoDigitado || !hashEsperadoBase64 || !saltBase64 || !crypto?.subtle) return false;
    try {
      const salt = base64ToUint8Array(saltBase64);
      const senhaBuffer = new TextEncoder().encode(String(segredoDigitado).trim());
      const keyMaterial = await crypto.subtle.importKey("raw", senhaBuffer, { name: "PBKDF2" }, false, ["deriveBits"]);
      const hashBuffer = await crypto.subtle.deriveBits(
        { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
        keyMaterial,
        256
      );
      return arrayBufferToBase64(hashBuffer) === hashEsperadoBase64;
    } catch (e) {
      console.warn("[Maestro Mobile] Falha ao verificar hash PBKDF2:", e);
      return false;
    }
  }

  async function derivarChaveAesMobile(senha, saltBytes) {
    const senhaBuffer = stringToUint8Array(String(senha).trim());
    const keyMaterial = await crypto.subtle.importKey("raw", senhaBuffer, { name: "PBKDF2" }, false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: saltBytes, iterations: 100000, hash: "SHA-256" },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async function cifrarTextoAESMobile(textoPlano, senha, opcoes = {}) {
    if (!senha || !String(senha).trim()) {
      throw new Error("Chave de Criptografia da Subseção não informada. Operação bloqueada por segurança E2EE.");
    }
    if (!crypto?.subtle) {
      throw new Error("Web Crypto API indisponível neste navegador (verifique se está usando HTTPS).");
    }
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const cryptoKey = await derivarChaveAesMobile(senha, salt);
    const rawBytes = stringToUint8Array(textoPlano);

    const deveComprimir = Boolean(
      opcoes && (
        opcoes.comprimirGzip === true ||
        (typeof opcoes.autoGzipAcimaBytes === "number" && opcoes.autoGzipAcimaBytes > 0 && rawBytes.byteLength >= opcoes.autoGzipAcimaBytes)
      )
    );

    let payloadBytes = rawBytes;
    let comprimido = false;
    if (deveComprimir && suportaGzipNativoMobile()) {
      const compressed = await comprimirBytesGzipMobile(rawBytes);
      if (compressed.byteLength + 4 < rawBytes.byteLength) {
        payloadBytes = new Uint8Array(4 + compressed.byteLength);
        payloadBytes.set(GZIP_MAGIC_PREFIX, 0);
        payloadBytes.set(compressed, 4);
        comprimido = true;
      }
    }

    const ciphertextBuffer = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      cryptoKey,
      payloadBytes
    );

    return {
      cifrado: true,
      comprimido,
      data: arrayBufferToBase64(ciphertextBuffer),
      iv: arrayBufferToBase64(iv),
      salt: arrayBufferToBase64(salt)
    };
  }

  async function decifrarTextoAESMobile(dadosCifradosBase64, ivBase64, saltBase64, senha) {
    if (!senha || !String(senha).trim()) {
      throw new Error("Chave de Criptografia da Subseção não informada.");
    }
    if (!crypto?.subtle) {
      throw new Error("Web Crypto API indisponível neste navegador.");
    }
    const salt = base64ToUint8Array(saltBase64);
    const iv = base64ToUint8Array(ivBase64);
    const ciphertext = base64ToUint8Array(dadosCifradosBase64);
    const cryptoKey = await derivarChaveAesMobile(senha, salt);
    const plaintextBuffer = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, cryptoKey, ciphertext);
    const plaintextBytes = new Uint8Array(plaintextBuffer);

    if (ehPayloadComprimidoMGZ1Mobile(plaintextBytes)) {
      const gzSlice = new Uint8Array(plaintextBytes.slice(4));
      const decompressed = await descomprimirBytesGzipMobile(gzSlice);
      return uint8ArrayToString(decompressed);
    }

    return uint8ArrayToString(plaintextBuffer);
  }

  async function decodificarOuDecifrarDadoNuvemMobile(rawStr, ivBase64, saltBase64, senha) {
    if (!rawStr) return null;
    if (ivBase64 && saltBase64) {
      if (!senha) return null;
      const texto = await decifrarTextoAESMobile(rawStr, ivBase64, saltBase64, senha);
      return JSON.parse(texto);
    }
    const trimStr = String(rawStr).trim();
    if (trimStr.startsWith("[") || trimStr.startsWith("{")) {
      return JSON.parse(trimStr);
    }
    return null;
  }

  // =========================================================================
  // 1. CONFIGURAÇÕES & DICIONÁRIO DE SUBSEÇÕES DA JUSTIÇA FEDERAL
  // =========================================================================
  const SUBSECOES_MAP = {
    sobral: {
      id: "sobral",
      nome: "Sobral",
      descricao: "18ª e 31ª Varas (Mistas) e 19ª Vara Federal (JEF)",
      varas: ["18", "19", "31"]
    },
    fortaleza: {
      id: "fortaleza",
      nome: "Fortaleza (Sede JFCE)",
      descricao: "1ª à 14ª, 20ª, 21ª, 26ª, 28ª, 32ª e 33ª Varas",
      varas: ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "20", "21", "26", "28", "32", "33"]
    },
    juazeiro_do_norte: {
      id: "juazeiro_do_norte",
      nome: "Juazeiro do Norte",
      descricao: "16ª Vara (Mista), 17ª Vara (JEF) e 30ª Vara Federal",
      varas: ["16", "17", "30"]
    },
    limoeiro_do_norte: {
      id: "limoeiro_do_norte",
      nome: "Limoeiro do Norte",
      descricao: "15ª Vara (Mista) e 29ª Vara Federal (JEF)",
      varas: ["15", "29"]
    },
    crateus: {
      id: "crateus",
      nome: "Crateús",
      descricao: "22ª Vara Federal (Vara Única Mista e JEF)",
      varas: ["22"]
    },
    quixada: {
      id: "quixada",
      nome: "Quixadá",
      descricao: "23ª Vara Federal (Vara Única Mista e JEF)",
      varas: ["23"]
    },
    taua: {
      id: "taua",
      nome: "Tauá",
      descricao: "24ª Vara Federal (Vara Única Mista e JEF)",
      varas: ["24"]
    },
    iguatu: {
      id: "iguatu",
      nome: "Iguatu",
      descricao: "25ª Vara Federal (Vara Única Mista e JEF)",
      varas: ["25"]
    },
    itapipoca: {
      id: "itapipoca",
      nome: "Itapipoca",
      descricao: "27ª Vara Federal (Vara Única Mista e JEF)",
      varas: ["27"]
    },
    maracanau: {
      id: "maracanau",
      nome: "Maracanaú",
      descricao: "34ª Vara (Cível/Mista) e 35ª Vara Federal (JEF)",
      varas: ["34", "35"]
    }
  };

  const MESES_NOMES = [
    "Janeiro", "Fevereiro", "Março", "Abril", "Maio", "Junho",
    "Julho", "Agosto", "Setembro", "Outubro", "Novembro", "Dezembro"
  ];

  const LOCAIS_PADRAO_OPTIONS = [
    { value: "Justiça Federal", label: "🏢 Justiça Federal (Prédio JF)" },
    { value: "Clínica Própria", label: "🏥 Clínica Própria (Externa / Fora)" },
    { value: "Clínica particular", label: "🏥 Clínica particular (Externa / Fora)" },
    { value: "Fora / Consultório / Hospital", label: "📍 Fora (Consultório / Hospital / Domiciliar)" },
    { value: "Teleperícia (No Prédio)", label: "💻 Teleperícia (No Prédio da Justiça)" },
    { value: "Teleperícia (Remota / Externa)", label: "🌐 Teleperícia (Remota / Fora)" }
  ];

  // Base padrão da extensão para fallback offline e inicialização
  const RAW_PAUTAS_SOBRAL_BASE = [
    ['Paulo André Moreira Aguiar', 'TODAS as especialidades, menos oftalmo. 31ª VF NÃO MARCA LOAS.', 'Justiça Federal', '2026-07-07', '19', 20, '08:00', 10, 'Marcado', ''],
    ['Paulo André Moreira Aguiar', 'TODAS as especialidades, menos oftalmo.', 'Justiça Federal', '2026-07-07', '19', 20, '12:15', 10, 'Marcado', ''],
    ['Pedro Wisley Hardy', 'SÓ ORTOPEDIA', 'Clínica Própria', '2026-07-06', '19', 7, '08:00', 20, 'Marcado', ''],
    ['Amanda Gadelha Mont Alverne', 'Todas as especialidades, menos oftalmo', 'Justiça Federal', '2026-07-02', '31', 30, '08:00', 9, 'Marcado', ''],
    ['Flora Nascimento da Paz', 'Clínica Geral + Ortopedia', 'Justiça Federal', '2026-07-01', '19', 14, '13:30', 14, 'Marcado', ''],
    ['Bárbara Duarte de Carvalho', 'Psiquiatria - RQE', 'Justiça Federal', '2026-09-07', '19', 15, '08:30', 12, 'Marcado', ''],
    ['Perícia Social - Equipe', 'Estudo e Avaliação Social (LOAS/BPC)', 'Justiça Federal', '2026-09-11', '19', 18, '08:00', 20, 'Marcado', 'Perícia Social JEF']
  ];

  // =========================================================================
  // 2. ESTADO GLOBAL DA APLICAÇÃO
  // =========================================================================
  function obterHojeIsoLocal() {
    const d = new Date();
    const y = d.getFullYear();
    const m = String(d.getMonth() + 1).padStart(2, "0");
    const day = String(d.getDate()).padStart(2, "0");
    return `${y}-${m}-${day}`;
  }

  const agoraInicial = new Date();
  let sessaoUsuario = null; // { subsecaoId, subsecaoNome, usuarioCpf, role, projectId }
  let todasPautas = [];
  let todasPericiasPje = [];
  let pautasFiltradas = [];
  let bancoPeritosMobile = [];
  let pautasParaImportar = [];

  let anoAtivo = agoraInicial.getFullYear();
  let mesAtivo = agoraInicial.getMonth();
  let filtroSituacaoAtivo = "todos";
  let filtroVaraDashboard = "";
  let textoCompartilhadoPendente = null;

  let dataSelecionadaPorDia = obterHojeIsoLocal();
  let calDiaAno = agoraInicial.getFullYear();
  let calDiaMes = agoraInicial.getMonth();
  let modoVisualizacaoDia = "tudo"; // "tudo" | "escala" | "pauta"
  let calendarioDiaVisivel = true;
  let ultimaSyncEscalaTs = 0;
  let ultimaSyncPautaPjeTs = 0;
  let autoRefreshDiaAtivo = false;
  let autoRefreshDiaTimer = null;
  let temaAtualMobile = "auto";
  let pautaEmEdicaoModal = null;

  function mostrarToast(msg, tipo = "info", duracaoMs = 3200) {
    const container = document.getElementById("maestroToastContainer");
    if (!container || !msg) return;
    const toast = document.createElement("div");
    toast.className = `maestro-toast toast-${tipo}`;
    toast.textContent = String(msg);
    container.appendChild(toast);
    while (container.children.length > 3) {
      container.removeChild(container.firstChild);
    }
    setTimeout(() => {
      toast.classList.add("is-hiding");
      setTimeout(() => {
        if (toast.parentNode) toast.parentNode.removeChild(toast);
      }, 260);
    }, Math.max(1200, duracaoMs));
  }

  function aplicarTemaMobile(tema) {
    const valido = (tema === "light" || tema === "dark" || tema === "auto") ? tema : "auto";
    temaAtualMobile = valido;
    const root = document.documentElement;
    if (valido === "auto") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", valido);
    try { localStorage.setItem("maestro_mobile_theme", valido); } catch (e) {}
    document.querySelectorAll(".theme-toggle-group .theme-btn").forEach((btn) => {
      btn.classList.toggle("active", btn.getAttribute("data-tema") === valido);
    });
  }

  function inicializarTemaMobile() {
    let salvo = "auto";
    try {
      const t = localStorage.getItem("maestro_mobile_theme");
      if (t === "light" || t === "dark" || t === "auto") salvo = t;
    } catch (e) {}
    aplicarTemaMobile(salvo);
  }

  function formatarHoraCurtaTs(ts) {
    if (!ts || !Number.isFinite(Number(ts))) return "";
    const d = new Date(Number(ts));
    if (isNaN(d.getTime())) return "";
    return d.toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" });
  }

  function atualizarIndicadorSync() {
    const el = document.getElementById("lblUltimaSync");
    if (!el) return;
    if (!ultimaSyncEscalaTs && !ultimaSyncPautaPjeTs) {
      el.textContent = "Sync: aguardando...";
      return;
    }
    const hEscala = formatarHoraCurtaTs(ultimaSyncEscalaTs || Date.now());
    const hPje = ultimaSyncPautaPjeTs ? formatarHoraCurtaTs(ultimaSyncPautaPjeTs) : "";
    el.textContent = hPje ? `🔄 Sync: ${hEscala} • PJe: ${hPje}` : `🔄 Sync: ${hEscala}`;
  }

  function classificarSituacaoFiltro(situacao) {
    const s = removerAcentosLowerMobile(situacao);
    if (s.includes("em marca")) return "em_marcacao";
    if (s.includes("canc")) return "cancelado";
    if (s.includes("nao marc") || s.includes("pend") || s.includes("abert") || s.includes("reserv")) return "nao_marcado";
    if (s.includes("marc")) return "marcado";
    return "nao_marcado";
  }

  function correspondeFiltroSituacao(pauta, filtro) {
    if (!filtro || filtro === "todos") return true;
    const cls = classificarSituacaoFiltro(pauta?.situacao);
    if (filtro === "pendente") return cls === "nao_marcado" || cls === "em_marcacao";
    return cls === filtro;
  }

  function resolverPrazoInfoPauta(p) {
    if (!p || !p.data || !ehSituacaoPendente(p.situacao)) return null;
    const dataLimite = p.dataLimite || (Parser ? Parser.calcularDataLimite8DiasUteis(p.data) : "");
    if (!dataLimite) return null;
    const dias = Parser ? Parser.calcularPrazoDias(dataLimite) : p.prazoDias;
    if (dias === null || dias === undefined || isNaN(dias)) return null;
    return { dataLimite, prazoDias: Number(dias) };
  }

  function obterBadgePrazoPautaHtml(p) {
    const info = resolverPrazoInfoPauta(p);
    if (!info) return "";
    const d = info.prazoDias;
    let cls = "is-normal";
    let texto = `⏳ Limite ${formatarDataBr(info.dataLimite)} (${d}d)`;
    if (d < 0) {
      cls = "is-vencido";
      texto = `🚨 Prazo vencido há ${Math.abs(d)}d (${formatarDataBr(info.dataLimite)})`;
    } else if (d <= 5) {
      cls = "is-urgente";
      texto = d === 0
        ? `⚠️ Prazo vence HOJE (${formatarDataBr(info.dataLimite)})`
        : `⚠️ Prazo crítico: ${d}d (${formatarDataBr(info.dataLimite)})`;
    }
    return `<div class="pauta-prazo-badge ${cls}">${escapeHtml(texto)}</div>`;
  }

  function normalizarChavePeritoReconcil(nome) {
    const raw = String(nome || "").trim();
    if (!raw) return "";
    if (Parser && typeof Parser.encontrarPeritoNoTexto === "function") {
      const m = Parser.encontrarPeritoNoTexto(raw, bancoPeritosMobile);
      if (m && m.nome) return removerAcentosLowerMobile(m.nome);
    }
    return removerAcentosLowerMobile(raw);
  }

  function ehAmbienteExtensaoChrome() {
    return typeof chrome !== "undefined" && Boolean(chrome.storage && chrome.storage.local);
  }

  function obterChaveNuvemSessao() {
    if (sessaoUsuario && sessaoUsuario.chaveNuvem) return String(sessaoUsuario.chaveNuvem).trim();
    try {
      const sKey = sessionStorage.getItem("maestro_mobile_key");
      if (sKey && sKey.trim()) return sKey.trim();
    } catch (e) {}
    try {
      const lKey = localStorage.getItem("maestro_mobile_key_saved");
      if (lKey && lKey.trim()) return lKey.trim();
    } catch (e) {}
    return "";
  }

  function salvarChaveNuvemSessao(chave, persistirLocal = true) {
    const clean = String(chave || "").trim();
    if (!clean) return;
    try { sessionStorage.setItem("maestro_mobile_key", clean); } catch (e) {}
    if (persistirLocal) {
      try { localStorage.setItem("maestro_mobile_key_saved", clean); } catch (e) {}
    } else {
      try { localStorage.removeItem("maestro_mobile_key_saved"); } catch (e) {}
    }
  }

  function normalizarNumeroVara(v) {
    const raw = String(v ?? "").trim();
    if (!raw) return "";
    if (raw === "*") return "*";
    const digits = raw.replace(/\D/g, "");
    return digits || raw;
  }

  function mascararCpfMobile(cpf) {
    const limpo = String(cpf || "").replace(/\D/g, "");
    if (limpo.length === 11) {
      return `${limpo.slice(0, 3)}.***.***-${limpo.slice(-2)}`;
    }
    return String(cpf || "");
  }

  function podeEnviarPautasNaSessao(sessao = sessaoUsuario) {
    if (!sessao) return false;
    return sessao.role === "Master" || sessao.role === "Editor";
  }

  function obterSubsecoesAutorizadasSessao(sessao = sessaoUsuario) {
    const todasKeys = Object.keys(SUBSECOES_MAP);
    if (!sessao) return [];
    if (sessao.role === "Master") return todasKeys;
    const subs = Array.isArray(sessao.subsecoesPermitidas) ? sessao.subsecoesPermitidas : [];
    if (subs.includes("*")) return todasKeys;
    const validas = subs.filter((id) => Boolean(SUBSECOES_MAP[id]));
    if (validas.length > 0) return validas;
    return sessao.subsecaoId ? [sessao.subsecaoId] : [];
  }

  function resolverVarasAutorizadasSubsecao(sessao = sessaoUsuario, subIdParam = null) {
    const subId = subIdParam || sessao?.subsecaoId || "sobral";
    const varasBaseSub = Array.isArray(SUBSECOES_MAP[subId]?.varas)
      ? SUBSECOES_MAP[subId].varas.map(normalizarNumeroVara).filter(Boolean)
      : ["18", "19", "31"];

    if (!sessao || sessao.role === "Master") return varasBaseSub;
    const subsPerm = Array.isArray(sessao.subsecoesPermitidas) ? sessao.subsecoesPermitidas : [];
    if (subsPerm.includes("*")) return varasBaseSub;

    const varasObj = (sessao.varasPermitidas && typeof sessao.varasPermitidas === "object")
      ? sessao.varasPermitidas
      : {};
    const subKey = Object.keys(varasObj).find((k) => String(k).trim().toLowerCase() === String(subId).trim().toLowerCase());
    const listaCfg = subKey ? varasObj[subKey] : null;

    if (Array.isArray(listaCfg) && listaCfg.length > 0 && !listaCfg.includes("*")) {
      const filtradas = Array.from(new Set(listaCfg.map(normalizarNumeroVara).filter(Boolean)));
      if (filtradas.length > 0) return filtradas;
    }

    if (sessao.varaFixa) {
      const vFixa = normalizarNumeroVara(sessao.varaFixa);
      if (vFixa && varasBaseSub.includes(vFixa)) {
        return [vFixa];
      }
    }

    return varasBaseSub;
  }

  function isVaraAutorizadaNaSessao(varaValor, sessao = sessaoUsuario, subIdParam = null) {
    const varasAuth = resolverVarasAutorizadasSubsecao(sessao, subIdParam);
    const vNorm = normalizarNumeroVara(varaValor);
    if (!vNorm) return false;
    return varasAuth.includes(vNorm);
  }

  function obterLabelEscopoVaras(sessao = sessaoUsuario, subIdParam = null) {
    const subId = subIdParam || sessao?.subsecaoId || "sobral";
    const varasAuth = resolverVarasAutorizadasSubsecao(sessao, subId);
    const varasSub = SUBSECOES_MAP[subId]?.varas || [];
    if (!sessao || sessao.role === "Master" || varasAuth.length >= varasSub.length) {
      return varasAuth.length > 0 ? varasAuth.map((v) => `${v}ª`).join(", ") : "Todas as Varas";
    }
    return varasAuth.map((v) => `${v}ª VF`).join(", ");
  }

  // =========================================================================
  // 3. INICIALIZAÇÃO, EVENTOS (CSP-SAFE) E GERENCIAMENTO DE SESSÃO
  // =========================================================================
  document.addEventListener("DOMContentLoaded", () => {
    inicializarTemaMobile();
    vincularEventosUI();
    capturarShareTargetUrl();
    carregarSessaoSalva();
  });

  function vincularEventosUI() {
    // Login & Pareamento rápido
    document.getElementById("formLogin")?.addEventListener("submit", (e) => {
      e.preventDefault();
      window.fazerLogin();
    });

    document.getElementById("loginCpf")?.addEventListener("input", (e) => {
      const raw = e.target.value;
      if (/[a-zA-Z]/.test(raw)) return;
      let v = raw.replace(/\D/g, "").slice(0, 11);
      if (v.length > 9) v = v.replace(/(\d{3})(\d{3})(\d{3})(\d{1,2})/, "$1.$2.$3-$4");
      else if (v.length > 6) v = v.replace(/(\d{3})(\d{3})(\d{1,3})/, "$1.$2.$3");
      else if (v.length > 3) v = v.replace(/(\d{3})(\d{1,3})/, "$1.$2");
      e.target.value = v;
    });

    document.getElementById("btnAplicarCodigoMobile")?.addEventListener("click", aplicarCodigoConexaoMobile);

    const toggleAdvEl = document.getElementById("btnToggleConfigAvancada");
    if (toggleAdvEl) {
      toggleAdvEl.addEventListener("click", window.toggleConfigAvancada);
      toggleAdvEl.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          window.toggleConfigAvancada();
        }
      });
    }

    // Header & Banner PWA
    document.getElementById("selectHeaderSubsecao")?.addEventListener("change", (e) => {
      trocarSubsecaoMobile(e.target.value);
    });
    document.getElementById("btnHeaderPeritos")?.addEventListener("click", abrirModalPeritos);
    document.getElementById("btnHeaderConfig")?.addEventListener("click", abrirModalConfig);
    document.getElementById("btnHeaderSyncPautas")?.addEventListener("click", () => window.sincronizarPautas());
    document.getElementById("btnHeaderLogout")?.addEventListener("click", () => window.fazerLogout());
    document.getElementById("btnAplicarAtualizacaoPwa")?.addEventListener("click", () => window.location.reload());

    // Navegação de abas
    document.querySelectorAll(".main-tabs .tab-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        const tabId = btn.getAttribute("data-tab");
        if (tabId) window.trocarAba(tabId);
      });
    });

    // Visão Geral / Resumo
    document.getElementById("btnMesAnterior")?.addEventListener("click", () => window.alterarMes(-1));
    document.getElementById("btnMesProximo")?.addEventListener("click", () => window.alterarMes(1));
    document.getElementById("filtroVaraDashboard")?.addEventListener("change", (e) => {
      filtroVaraDashboard = e.target.value || "";
      atualizarKpisDoMes();
    });
    document.querySelectorAll("#tabDashboard [data-dash-drill]").forEach((card) => {
      card.addEventListener("click", () => {
        const situacao = card.getAttribute("data-dash-drill") || "todos";
        const vara = document.getElementById("filtroVaraDashboard")?.value || "";
        abrirListaComFiltros({ situacao, vara, periodo: "mes_atual" });
      });
    });
    document.getElementById("btnVerPrazosCriticos")?.addEventListener("click", () => {
      const vara = document.getElementById("filtroVaraDashboard")?.value || "";
      abrirListaComFiltros({ situacao: "pendente", vara, periodo: "prazo_critico", ordenacao: "prazo_asc" });
    });
    document.getElementById("listaVarasKpi")?.addEventListener("click", (e) => {
      const row = e.target.closest("[data-vara-drill]");
      if (!row) return;
      const vara = row.getAttribute("data-vara-drill") || "";
      abrirListaComFiltros({ situacao: "todos", vara, periodo: "mes_atual" });
    });
    document.getElementById("btnQuickPorDia")?.addEventListener("click", () => window.trocarAba("tabPorDia"));
    document.getElementById("btnQuickWhatsapp")?.addEventListener("click", () => window.trocarAba("tabWhatsapp"));
    document.getElementById("btnQuickRelatorio")?.addEventListener("click", () => window.abrirRelatorioRapido());
    document.getElementById("btnQuickVerPautas")?.addEventListener("click", () => window.trocarAba("tabPautas"));
    document.getElementById("btnQuickPeritos")?.addEventListener("click", abrirModalPeritos);

    // Por Dia (navegação, mini calendário, filtros e ações delegadas)
    document.getElementById("btnDiaAnterior")?.addEventListener("click", () => alterarDiaPorDia(-1));
    document.getElementById("btnDiaProximo")?.addEventListener("click", () => alterarDiaPorDia(1));
    document.getElementById("inputDataPorDia")?.addEventListener("change", (e) => {
      if (e.target && e.target.value) selecionarDataPorDia(e.target.value);
    });
    document.getElementById("btnDiaHoje")?.addEventListener("click", () => selecionarDataPorDia(obterHojeIsoLocal()));
    document.getElementById("btnDiaProximoComPauta")?.addEventListener("click", irParaProximoDiaComAtividade);
    document.getElementById("btnToggleCalendarioDia")?.addEventListener("click", alternarCalendarioPorDia);
    document.getElementById("btnCompartilharDiaWpp")?.addEventListener("click", compartilharResumoDiaWhatsApp);
    document.getElementById("btnAutoRefreshDia")?.addEventListener("click", alternarAutoRefreshDia);
    document.getElementById("btnCalDiaMesAnt")?.addEventListener("click", () => alterarMesCalendarioDia(-1));
    document.getElementById("btnCalDiaMesProx")?.addEventListener("click", () => alterarMesCalendarioDia(1));

    document.getElementById("gridCalendarioPorDia")?.addEventListener("click", (e) => {
      const cell = e.target.closest("[data-date]");
      if (!cell) return;
      const dt = cell.getAttribute("data-date");
      if (dt) selecionarDataPorDia(dt);
    });

    document.querySelectorAll(".dia-view-pills .pill").forEach((pill) => {
      pill.addEventListener("click", () => {
        const modo = pill.getAttribute("data-modo-dia") || "tudo";
        modoVisualizacaoDia = modo;
        document.querySelectorAll(".dia-view-pills .pill").forEach((p) => p.classList.remove("active"));
        pill.classList.add("active");
        renderizarAbaPorDia();
      });
    });

    document.getElementById("filtroTextoPorDia")?.addEventListener("input", () => renderizarAbaPorDia());
    document.getElementById("btnLimparBuscaPorDia")?.addEventListener("click", () => {
      const inp = document.getElementById("filtroTextoPorDia");
      if (inp) inp.value = "";
      renderizarAbaPorDia();
    });
    document.getElementById("filtroVaraPorDia")?.addEventListener("change", () => renderizarAbaPorDia());
    document.getElementById("filtroSituacaoPorDia")?.addEventListener("change", () => renderizarAbaPorDia());
    document.getElementById("filtroStatusPjePorDia")?.addEventListener("change", () => renderizarAbaPorDia());

    document.getElementById("listaPautaPjeDoDia")?.addEventListener("click", (e) => {
      const btnProx = e.target.closest("[data-action='proximo-dia-atividade']");
      if (btnProx) {
        irParaProximoDiaComAtividade();
        return;
      }
      const btnCopy = e.target.closest("[data-copy-proc]");
      if (!btnCopy) return;
      const proc = btnCopy.getAttribute("data-copy-proc") || "";
      if (!proc) return;
      if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
        navigator.clipboard.writeText(proc).then(() => {
          const orig = btnCopy.textContent;
          btnCopy.textContent = "✓ Copiado";
          mostrarToast("Número do processo copiado.", "success", 1800);
          setTimeout(() => { btnCopy.textContent = orig; }, 1400);
        }).catch(() => {});
      }
    });

    document.getElementById("listaEscalaDoDia")?.addEventListener("click", (e) => {
      const btnProx = e.target.closest("[data-action='proximo-dia-atividade']");
      if (btnProx) {
        irParaProximoDiaComAtividade();
        return;
      }
      tratarCliqueAcaoPautaCard(e);
    });

    document.getElementById("listaPautasCards")?.addEventListener("click", (e) => {
      const badgeData = e.target.closest("[data-abrir-dia]");
      if (badgeData) {
        const dt = badgeData.getAttribute("data-abrir-dia");
        if (dt && /^\d{4}-\d{2}-\d{2}$/.test(dt)) {
          selecionarDataPorDia(dt);
          window.trocarAba("tabPorDia");
        }
        return;
      }
      tratarCliqueAcaoPautaCard(e);
    });

    // Pautas (filtros completos)
    document.getElementById("filtroTexto")?.addEventListener("input", () => window.filtrarPautas());
    document.getElementById("btnLimparBusca")?.addEventListener("click", () => window.limparBusca());
    document.querySelectorAll("#tabPautas .filter-pills .pill").forEach((pill) => {
      pill.addEventListener("click", () => {
        const filtro = pill.getAttribute("data-filtro") || "todos";
        window.setFiltroSituacao(filtro, pill);
      });
    });
    document.getElementById("filtroVara")?.addEventListener("change", () => window.filtrarPautas());
    document.getElementById("filtroPeriodoPautas")?.addEventListener("change", () => window.filtrarPautas());
    document.getElementById("filtroLocalPautas")?.addEventListener("change", () => window.filtrarPautas());
    document.getElementById("filtroCategoria")?.addEventListener("change", () => window.filtrarPautas());
    document.getElementById("filtroOrdenacaoPautas")?.addEventListener("change", () => window.filtrarPautas());
    document.getElementById("btnResetFiltrosPautas")?.addEventListener("click", resetarFiltrosListaPautas);

    // Aba WhatsApp
    document.getElementById("btnColarWhatsAppMobile")?.addEventListener("click", colarTextoWhatsApp);
    document.getElementById("btnExemploTextoWpp")?.addEventListener("click", preencherExemploWhatsApp);
    document.getElementById("btnLimparTextoWpp")?.addEventListener("click", limparEntradaWhatsApp);
    document.getElementById("btnInterpretarWpp")?.addEventListener("click", interpretarTextoWhatsApp);
    document.getElementById("btnAddPautaManualWpp")?.addEventListener("click", adicionarPautaManualWpp);
    document.getElementById("btnSelecionarTodasImportWpp")?.addEventListener("click", alternarSelecaoTodasImportWpp);
    document.getElementById("btnEnviarPautasNuvemWpp")?.addEventListener("click", enviarPautasImportadasParaPlanilha);
    document.getElementById("btnReenviarFilaOffline")?.addEventListener("click", reenviarFilaOffline);

    const onConfigPadraoWppMobile = () => {
      atualizarResumoPadraoPeritoMobile();
      const txtEl = document.getElementById("txtConversaWhatsApp");
      if (txtEl && txtEl.value && txtEl.value.trim()) {
        interpretarTextoWhatsApp();
      }
    };
    document.getElementById("inpPeritoPadraoWpp")?.addEventListener("change", onConfigPadraoWppMobile);
    document.getElementById("inpPeritoPadraoWpp")?.addEventListener("input", atualizarResumoPadraoPeritoMobile);

    document.getElementById("selModoTurnosWpp")?.addEventListener("change", onConfigPadraoWppMobile);

    // Edição inline e delegação de eventos nos cards de importação WhatsApp
    const listaCardsWpp = document.getElementById("listaCardsImportWpp");
    if (listaCardsWpp) {
      listaCardsWpp.addEventListener("input", onInputCardImportacaoWpp);
      listaCardsWpp.addEventListener("change", onChangeCardImportacaoWpp);
      listaCardsWpp.addEventListener("click", onClickCardImportacaoWpp);
    }

    // Relatórios + Filtros do Relatório
    document.getElementById("relFiltroPeriodo")?.addEventListener("change", atualizarEstadoFiltrosRelatorio);
    document.getElementById("relFiltroMesInput")?.addEventListener("change", (e) => {
      if (e.target) e.target.dataset.manual = "true";
      atualizarResumoFiltroRelatorio();
    });
    document.getElementById("relFiltroVara")?.addEventListener("change", atualizarResumoFiltroRelatorio);
    document.getElementById("relFiltroSituacao")?.addEventListener("change", atualizarResumoFiltroRelatorio);
    document.getElementById("btnRelPdfMes")?.addEventListener("click", () => window.gerarRelatorioPdf("filtrado"));
    document.getElementById("btnRelPdfCompleto")?.addEventListener("click", () => window.gerarRelatorioPdf("completo"));
    document.getElementById("btnRelPdfPautaDia")?.addEventListener("click", gerarRelatorioPdfPautaPjeDia);
    document.getElementById("btnRelCsv")?.addEventListener("click", () => window.exportarRelatorioCsv());
    document.getElementById("btnRelCopiarWpp")?.addEventListener("click", () => window.copiarResumoWhatsApp());
    document.getElementById("btnRelEnviarWpp")?.addEventListener("click", () => window.compartilharWhatsAppDireto());
    document.getElementById("btnImprimirPreviewRelatorio")?.addEventListener("click", () => window.print());
    document.getElementById("btnFecharPreviewRelatorio")?.addEventListener("click", () => window.fecharPreviewRelatorio());

    // Modal Editar Pauta
    document.getElementById("btnFecharModalEditarPauta")?.addEventListener("click", fecharModalEditarPauta);
    document.getElementById("btnCancelarModalEditarPauta")?.addEventListener("click", fecharModalEditarPauta);
    document.getElementById("modalEditarPautaMobile")?.addEventListener("click", (e) => {
      if (e.target && e.target.id === "modalEditarPautaMobile") fecharModalEditarPauta();
    });
    document.getElementById("formEditarPautaMobile")?.addEventListener("submit", (e) => {
      e.preventDefault();
      salvarEdicaoPautaModal();
    });
    ["editData", "editHoraInicio", "editQuantidade", "editIntervaloMin"].forEach((id) => {
      document.getElementById(id)?.addEventListener("input", atualizarPreviewCalcModalEditar);
    });
    document.getElementById("editLocal")?.addEventListener("change", atualizarVisibilidadeEnderecoModalEditar);

    // Modal Diretório de Peritos
    document.getElementById("btnFecharModalPeritos")?.addEventListener("click", fecharModalPeritos);
    document.getElementById("modalPeritosMobile")?.addEventListener("click", (e) => {
      if (e.target && e.target.id === "modalPeritosMobile") fecharModalPeritos();
    });
    document.getElementById("filtroBuscaPeritosModal")?.addEventListener("input", renderizarDiretorioPeritos);
    document.getElementById("listaPeritosModal")?.addEventListener("click", (e) => {
      const btn = e.target.closest("[data-ver-pautas-perito]");
      if (!btn) return;
      const nome = btn.getAttribute("data-ver-pautas-perito") || "";
      fecharModalPeritos();
      abrirListaComFiltros({ texto: nome, situacao: "todos", periodo: "todos" });
    });

    // Modal Configurações
    document.getElementById("btnFecharModalConfig")?.addEventListener("click", fecharModalConfig);
    document.getElementById("modalConfigMobile")?.addEventListener("click", (e) => {
      if (e.target && e.target.id === "modalConfigMobile") fecharModalConfig();
    });
    document.querySelectorAll(".theme-toggle-group .theme-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        const tema = btn.getAttribute("data-tema") || "auto";
        aplicarTemaMobile(tema);
        mostrarToast(`Tema alterado para: ${tema === "dark" ? "Escuro" : (tema === "light" ? "Claro" : "Automático")}.`, "success", 2000);
      });
    });
    document.getElementById("btnCfgAplicarCodigo")?.addEventListener("click", aplicarCodigoConexaoNoModalConfig);
    document.getElementById("btnCfgSalvarChave")?.addEventListener("click", salvarChaveNoModalConfig);
    document.getElementById("btnCfgLimparCache")?.addEventListener("click", limparCachePwaERecarregar);

    // Conectividade / retorno online
    window.addEventListener("online", () => {
      atualizarBannerFilaOffline();
    });
  }

  function capturarShareTargetUrl() {
    try {
      const params = new URLSearchParams(window.location.search || "");
      const txt = params.get("shared_text") || "";
      const title = params.get("shared_title") || "";
      const combined = [title, txt].map((s) => String(s || "").trim()).filter(Boolean).join("\n");
      if (combined) {
        textoCompartilhadoPendente = combined;
        try { sessionStorage.setItem("maestro_mobile_shared_pending", combined); } catch (e) {}
        try {
          const cleanUrl = window.location.pathname + window.location.hash;
          window.history.replaceState({}, document.title, cleanUrl);
        } catch (e) {}
      } else if (!textoCompartilhadoPendente) {
        try {
          const savedShared = sessionStorage.getItem("maestro_mobile_shared_pending");
          if (savedShared && savedShared.trim()) {
            textoCompartilhadoPendente = savedShared;
          }
        } catch (e) {}
      }
    } catch (e) {}
  }

  function aplicarCodigoConexaoMobile() {
    const inp = document.getElementById("loginCodigoConexao");
    const statusEl = document.getElementById("loginCodigoStatus");
    let raw = (inp?.value || "").trim();
    if (!raw) {
      alert("⚠️ Cole o Código de Conexão gerado no Maestro Desktop (MAESTRO::...).");
      if (inp) inp.focus();
      return;
    }
    if (raw.startsWith("MAESTRO::")) {
      raw = raw.slice("MAESTRO::".length);
    }
    try {
      const decodedStr = decodeURIComponent(escape(atob(raw)));
      const payload = JSON.parse(decodedStr);
      if (!payload || !payload.p) {
        throw new Error("Project ID não localizado no código.");
      }

      const selSub = document.getElementById("loginSubsecao");
      const inpProj = document.getElementById("loginProjectId");
      const inpChave = document.getElementById("loginChaveNuvem");

      if (selSub && payload.s) {
        const existe = Array.from(selSub.options).some((o) => o.value === payload.s);
        if (!existe) {
          const opt = document.createElement("option");
          opt.value = payload.s;
          opt.textContent = payload.s;
          selSub.appendChild(opt);
        }
        selSub.value = payload.s;
      }
      if (inpProj) inpProj.value = payload.p;
      if (inpChave && payload.k) inpChave.value = payload.k;

      if (statusEl) {
        statusEl.textContent = `✅ Conectado ao projeto "${payload.p}" (${payload.s || "subseção"}). Agora informe seu CPF/Nome e o PIN.`;
        statusEl.style.display = "block";
      }

      const inpCpf = document.getElementById("loginCpf");
      const inpPin = document.getElementById("loginPin");
      if (inpCpf && !inpCpf.value.trim()) inpCpf.focus();
      else if (inpPin) inpPin.focus();
    } catch (err) {
      if (statusEl) statusEl.style.display = "none";
      alert("❌ Código de conexão inválido ou corrompido: " + err.message);
    }
  }

  function carregarSessaoSalva() {
    // Se dentro da extensão Chrome e sem configuração salva ainda, preenche campos iniciais do storage local
    if (ehAmbienteExtensaoChrome()) {
      chrome.storage.local.get(["firebaseProjectId", "chaveSegurancaNuvem", "subsecaoAtiva"], (resExt) => {
        const inpProj = document.getElementById("loginProjectId");
        const inpChave = document.getElementById("loginChaveNuvem");
        const selSub = document.getElementById("loginSubsecao");
        if (inpProj && !inpProj.value && resExt.firebaseProjectId) inpProj.value = resExt.firebaseProjectId;
        if (inpChave && !inpChave.value && resExt.chaveSegurancaNuvem) inpChave.value = resExt.chaveSegurancaNuvem;
        if (selSub && resExt.subsecaoAtiva) selSub.value = resExt.subsecaoAtiva;
      });
    }

    try {
      const raw = localStorage.getItem("maestro_mobile_session");
      if (raw) {
        sessaoUsuario = JSON.parse(raw);
        const loginMs = sessaoUsuario?.dataLogin ? Date.parse(sessaoUsuario.dataLogin) : 0;
        const expirada = loginMs > 0 && (Date.now() - loginMs) > (30 * 24 * 60 * 60 * 1000);
        if (expirada) {
          localStorage.removeItem("maestro_mobile_session");
          sessaoUsuario = null;
        } else if (sessaoUsuario && sessaoUsuario.subsecaoId) {
          iniciarAplicativoComSessao(obterChaveNuvemSessao());
          revalidarSessaoNaNuvem();
          return;
        }
      }
    } catch (e) {
      console.warn("Erro ao carregar sessão anterior:", e);
    }
    exibirTelaLogin();
  }

  async function revalidarSessaoNaNuvem() {
    if (!sessaoUsuario || !sessaoUsuario.projectId || sessaoUsuario.projectId.includes("exemplo")) return;
    if (typeof navigator !== "undefined" && navigator.onLine === false) return;
    try {
      const url = `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(sessaoUsuario.projectId)}/databases/(default)/documents/subsecoes/GOVERNANCA_PERMISSOES`;
      const resp = await fetch(url, { method: "GET", cache: "no-cache" });
      if (resp.status !== 200) return;
      const json = await resp.json();
      const f = json.fields || {};
      const cpfLimpo = String(sessaoUsuario.usuarioCpf || "").replace(/\D/g, "");

      const govDoc = {
        exigirCpfMobile: Boolean(f.exigirCpfMobile && f.exigirCpfMobile.booleanValue === true),
        cpfsBloqueadosJson: f.cpfsBloqueadosJson?.stringValue || "[]",
        editoresJson: f.editoresJson?.stringValue || "[]",
        mastersCpfsJson: f.mastersCpfsJson?.stringValue || "[]"
      };

      const bloqueados = JSON.parse(govDoc.cpfsBloqueadosJson || "[]").map((c) => String(c || "").replace(/\D/g, ""));
      if (cpfLimpo.length === 11 && bloqueados.includes(cpfLimpo)) {
        forcarLogoutRevogado("Este CPF foi bloqueado pela Governança Institucional.");
        return;
      }

      if (sessaoUsuario.authPorSenhaMaster) {
        return;
      }

      const escopoAtual = resolverPermissaoMobileDoc(govDoc, sessaoUsuario.usuarioCpf, sessaoUsuario.subsecaoId);
      if (!escopoAtual.autorizado) {
        forcarLogoutRevogado(escopoAtual.erro || "Sua permissão foi alterada, suspensa ou revogada pelo Administrador Master.");
        return;
      }

      const subsAntes = JSON.stringify(sessaoUsuario.subsecoesPermitidas || []);
      const varasAntes = JSON.stringify(sessaoUsuario.varasPermitidas || {});
      const roleAntes = sessaoUsuario.role;
      const nomeAntes = sessaoUsuario.usuarioNome || "";
      const varaFixaAntes = sessaoUsuario.varaFixa || null;

      sessaoUsuario.role = escopoAtual.role;
      sessaoUsuario.usuarioNome = escopoAtual.nomeUsuario || sessaoUsuario.usuarioNome || "";
      sessaoUsuario.subsecoesPermitidas = escopoAtual.subsecoesPermitidas;
      sessaoUsuario.varasPermitidas = escopoAtual.varasPermitidas;
      sessaoUsuario.varaFixa = escopoAtual.varaFixa || null;

      const houveAlteracao = (
        roleAntes !== sessaoUsuario.role ||
        nomeAntes !== sessaoUsuario.usuarioNome ||
        varaFixaAntes !== sessaoUsuario.varaFixa ||
        subsAntes !== JSON.stringify(sessaoUsuario.subsecoesPermitidas || []) ||
        varasAntes !== JSON.stringify(sessaoUsuario.varasPermitidas || {})
      );

      if (houveAlteracao) {
        localStorage.setItem("maestro_mobile_session", JSON.stringify(sessaoUsuario));
        aplicarEscopoSessaoNaUI();
        window.sincronizarPautas(obterChaveNuvemSessao());
      }
    } catch (e) {}
  }

  function forcarLogoutRevogado(motivo) {
    localStorage.removeItem("maestro_mobile_session");
    localStorage.removeItem("maestro_mobile_key_saved");
    try { sessionStorage.removeItem("maestro_mobile_key"); } catch (e) {}
    sessaoUsuario = null;
    todasPautas = [];
    todasPericiasPje = [];
    bancoPeritosMobile = [];
    pautasParaImportar = [];
    exibirTelaLogin();
    alert("🔒 Sessão encerrada: " + motivo);
  }

  function exibirTelaLogin() {
    document.getElementById("screenLogin").classList.add("active");
    document.getElementById("screenApp").classList.remove("active");
  }

  window.toggleConfigAvancada = function () {
    const box = document.getElementById("boxConfigAvancada");
    const icon = document.getElementById("iconToggleAdv");
    if (!box || !icon) return;
    if (box.style.display === "none") {
      box.style.display = "block";
      icon.textContent = "▲";
    } else {
      box.style.display = "none";
      icon.textContent = "▼";
    }
  };

  // =========================================================================
  // 4. AUTENTICAÇÃO E RESTRIÇÃO DE ESCOPO POR SUBSEÇÃO
  // =========================================================================
  window.fazerLogin = async function () {
    const selSub = document.getElementById("loginSubsecao").value;
    const txtCpf = document.getElementById("loginCpf").value.trim();
    const txtPin = document.getElementById("loginPin").value.trim();
    let txtProj = document.getElementById("loginProjectId").value.trim();
    let txtChave = document.getElementById("loginChaveNuvem").value.trim();
    const lembrarChave = Boolean(document.getElementById("chkLembrarChaveMobile")?.checked);
    const msgBox = document.getElementById("loginMsg");
    const btnLogin = document.getElementById("btnLogin");

    msgBox.style.display = "none";
    msgBox.className = "alert-box";

    if (!selSub) {
      exibirErroLogin("Por favor, selecione sua Subseção Judiciária.");
      return;
    }
    if (!txtCpf) {
      exibirErroLogin("Informe seu CPF ou nome de usuário.");
      return;
    }
    if (!txtPin) {
      exibirErroLogin("Informe o PIN de ativação da extensão.");
      return;
    }

    btnLogin.disabled = true;
    btnLogin.innerHTML = "Validando governança...";

    try {
      const lockoutInfo = verificarLockoutMobile();
      if (lockoutInfo.bloqueado) {
        exibirErroLogin(lockoutInfo.erro);
        return;
      }

      if (ehAmbienteExtensaoChrome() && (!txtProj || !txtChave)) {
        const st = await chrome.storage.local.get(["firebaseProjectId", "chaveSegurancaNuvem"]);
        if (!txtProj && st.firebaseProjectId) txtProj = st.firebaseProjectId;
        if (!txtChave && st.chaveSegurancaNuvem) txtChave = st.chaveSegurancaNuvem;
      }

      if (!txtProj) {
        exibirErroLogin("Informe o ID do Projeto Firebase em '⚙️ Parâmetros de Nuvem' ou cole o Código de Conexão gerado no Maestro Desktop.");
        return;
      }

      const projectIdEfetivo = txtProj;
      const validacao = await validarPinGovernança(txtPin, txtCpf, selSub, projectIdEfetivo);
      if (!validacao.valido) {
        exibirErroLogin(validacao.erro || "PIN de ativação incorreto. Use o mesmo PIN configurado no Maestro PJe do seu computador.");
        return;
      }

      limparLockoutMobile();

      const isMaster = validacao.role === "Master";
      const subInfo = SUBSECOES_MAP[selSub] || { id: selSub, nome: selSub, varas: [] };
      const cpfLimpo = txtCpf.replace(/\D/g, "");

      if (txtChave) {
        salvarChaveNuvemSessao(txtChave, lembrarChave);
      }

      sessaoUsuario = {
        subsecaoId: selSub,
        subsecaoNome: subInfo.nome,
        subsecaoDesc: subInfo.descricao,
        usuarioCpf: cpfLimpo.length === 11 ? cpfLimpo : txtCpf,
        usuarioNome: validacao.nomeUsuario || "",
        role: validacao.role || (isMaster ? "Master" : "Editor"),
        authPorSenhaMaster: Boolean(validacao.authPorSenhaMaster),
        subsecoesPermitidas: isMaster
          ? ["*"]
          : (Array.isArray(validacao.subsecoesPermitidas) && validacao.subsecoesPermitidas.length > 0 ? validacao.subsecoesPermitidas : [selSub]),
        varasPermitidas: isMaster ? { "*": ["*"] } : (validacao.varasPermitidas || {}),
        varaFixa: validacao.varaFixa || null,
        projectId: projectIdEfetivo,
        dataLogin: new Date().toISOString()
      };

      localStorage.setItem("maestro_mobile_session", JSON.stringify(sessaoUsuario));
      iniciarAplicativoComSessao(txtChave);
    } catch (err) {
      exibirErroLogin("Falha na validação: " + err.message);
    } finally {
      btnLogin.disabled = false;
      btnLogin.innerHTML = "<span>Entrar e Sincronizar Pautas</span> <span class='btn-arrow'>➔</span>";
    }
  };

  function verificarLockoutMobile() {
    try {
      const raw = localStorage.getItem("maestro_mobile_lockout");
      if (!raw) return { bloqueado: false };
      const st = JSON.parse(raw);
      if (st.bloqueadoAte && Date.now() < st.bloqueadoAte) {
        const rest = Math.ceil((st.bloqueadoAte - Date.now()) / 60000);
        return { bloqueado: true, erro: `Acesso bloqueado temporariamente após múltiplas tentativas inválidas. Aguarde ~${rest} min.` };
      }
      if (st.bloqueadoAte && Date.now() >= st.bloqueadoAte) {
        localStorage.removeItem("maestro_mobile_lockout");
      }
    } catch (e) {}
    return { bloqueado: false };
  }

  function registrarFalhaLoginMobile() {
    try {
      const raw = localStorage.getItem("maestro_mobile_lockout");
      const st = raw ? JSON.parse(raw) : { tentativas: 0, bloqueadoAte: 0 };
      st.tentativas = (Number(st.tentativas) || 0) + 1;
      if (st.tentativas >= 5) {
        st.bloqueadoAte = Date.now() + 5 * 60 * 1000;
        localStorage.setItem("maestro_mobile_lockout", JSON.stringify(st));
        return "PIN incorreto pela 5ª vez. Acesso bloqueado por 5 minutos.";
      }
      localStorage.setItem("maestro_mobile_lockout", JSON.stringify(st));
      return `PIN de ativação incorreto. Restam ${5 - st.tentativas} tentativa(s) antes do bloqueio temporário.`;
    } catch (e) {
      return "PIN de ativação incorreto.";
    }
  }

  function limparLockoutMobile() {
    try { localStorage.removeItem("maestro_mobile_lockout"); } catch (e) {}
  }

  function resolverPermissaoMobileDoc(govDoc, cpfUsuario, subId) {
    const doc = (govDoc && typeof govDoc === "object") ? govDoc : {};
    const cpfLimpo = String(cpfUsuario || "").replace(/\D/g, "");
    const exigirCpf = Boolean(doc.exigirCpfMobile === true);

    try {
      const bloqueadosRaw = Array.isArray(doc.cpfsBloqueados)
        ? doc.cpfsBloqueados
        : JSON.parse(doc.cpfsBloqueadosJson || "[]");
      const bloqueados = (Array.isArray(bloqueadosRaw) ? bloqueadosRaw : []).map((c) => String(c || "").replace(/\D/g, ""));
      if (cpfLimpo.length === 11 && bloqueados.includes(cpfLimpo)) {
        return { autorizado: false, erro: "Este CPF encontra-se bloqueado na governança institucional." };
      }
    } catch (e) {}

    try {
      const mastersRaw = Array.isArray(doc.mastersCpfs) ? doc.mastersCpfs : JSON.parse(doc.mastersCpfsJson || "[]");
      const masters = (Array.isArray(mastersRaw) ? mastersRaw : []).map((c) => String(c || "").replace(/\D/g, ""));
      if (cpfLimpo.length === 11 && masters.includes(cpfLimpo)) {
        return {
          autorizado: true,
          role: "Master",
          nomeUsuario: "",
          subsecoesPermitidas: ["*"],
          varasPermitidas: { "*": ["*"] },
          varaFixa: null
        };
      }
    } catch (e) {}

    try {
      const editoresRaw = Array.isArray(doc.editores) ? doc.editores : JSON.parse(doc.editoresJson || "[]");
      const editores = Array.isArray(editoresRaw) ? editoresRaw : [];
      const regsCpf = cpfLimpo.length === 11
        ? editores.filter((ed) => ed && String(ed.cpf || "").replace(/\D/g, "") === cpfLimpo)
        : [];

      if (regsCpf.length > 0) {
        const regsMobile = regsCpf.filter((ed) => ed.origem === "mobile" || String(ed.deviceId || "").startsWith("mob_"));
        const pool = regsMobile.length > 0 ? regsMobile : regsCpf;
        const ativos = pool.filter((ed) => ed.ativo !== false && ed.bloqueado !== true);
        if (ativos.length === 0) {
          return { autorizado: false, erro: "Seu usuário está bloqueado ou desativado pela Governança." };
        }

        const permitidosNaSub = ativos.filter((ed) => {
          const subs = Array.isArray(ed.subsecoesPermitidas) ? ed.subsecoesPermitidas : [];
          if (ed.papel === "master" || subs.includes("*")) return true;
          if (subs.length === 0) {
            if (ed.varaFixa && SUBSECOES_MAP[subId]?.varas) {
              return SUBSECOES_MAP[subId].varas.map(normalizarNumeroVara).includes(normalizarNumeroVara(ed.varaFixa));
            }
            return true;
          }
          return subs.includes(subId);
        });

        if (permitidosNaSub.length === 0) {
          const subsDesc = Array.from(new Set(ativos.flatMap((ed) => Array.isArray(ed.subsecoesPermitidas) ? ed.subsecoesPermitidas : [])));
          const nomesSubs = subsDesc.map((id) => SUBSECOES_MAP[id]?.nome || id).join(", ");
          return {
            autorizado: false,
            erro: nomesSubs
              ? `Seu CPF não possui acesso à subseção "${SUBSECOES_MAP[subId]?.nome || subId}". Subseção(ões) liberada(s): ${nomesSubs}.`
              : `Seu CPF não possui permissão de acesso para a subseção "${subId}".`
          };
        }

        const escolhido = permitidosNaSub.find((ed) => ed.papel === "master")
          || permitidosNaSub.find((ed) => ed.papel === "editor" || !ed.papel)
          || permitidosNaSub[0];

        const papelOrig = String(escolhido.papel || "editor").trim().toLowerCase();
        let roleMapeado = "Editor";
        if (papelOrig === "master") roleMapeado = "Master";
        else if (papelOrig === "leitor") roleMapeado = "Leitor";
        else if (papelOrig === "observador") roleMapeado = "Observador";

        const subsPerm = roleMapeado === "Master"
          ? ["*"]
          : (Array.isArray(escolhido.subsecoesPermitidas) && escolhido.subsecoesPermitidas.length > 0
              ? escolhido.subsecoesPermitidas
              : [subId]);

        const varasPerm = roleMapeado === "Master"
          ? { "*": ["*"] }
          : ((escolhido.varasPermitidas && typeof escolhido.varasPermitidas === "object") ? escolhido.varasPermitidas : {});

        return {
          autorizado: true,
          role: roleMapeado,
          nomeUsuario: String(escolhido.nomeUsuario || "").trim(),
          subsecoesPermitidas: subsPerm,
          varasPermitidas: varasPerm,
          varaFixa: escolhido.varaFixa ? normalizarNumeroVara(escolhido.varaFixa) : null
        };
      }
    } catch (e) {}

    if (exigirCpf) {
      return {
        autorizado: false,
        erro: "Acesso restrito: este CPF não está cadastrado na governança. Solicite ao Administrador Master o cadastro na aba Controle de Acessos."
      };
    }

    return {
      autorizado: true,
      role: "Editor",
      nomeUsuario: "",
      subsecoesPermitidas: [subId],
      varasPermitidas: {},
      varaFixa: null
    };
  }

  async function validarPinGovernança(pin, cpfUsuario, subId, projectId) {
    if (!pin || !String(pin).trim()) {
      return { valido: false, erro: "Informe o PIN de ativação." };
    }
    const clean = String(pin).trim();
    const cpfLimpo = String(cpfUsuario || "").replace(/\D/g, "");

    let govDoc = null;
    const cacheKey = `maestro_mobile_gov_${projectId}`;

    if (projectId && !projectId.includes("exemplo")) {
      const urls = [
        `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/databases/(default)/documents/subsecoes/GOVERNANCA_PERMISSOES`,
        `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/databases/(default)/documents/subsecoes/PERMISSOES_${encodeURIComponent(subId)}`
      ];
      for (const url of urls) {
        try {
          const resp = await fetch(url, { method: "GET", cache: "no-cache" });
          if (resp.status === 200) {
            const json = await resp.json();
            const f = json.fields || {};
            govDoc = {
              pinHash: f.pinHash?.stringValue || "",
              pinSalt: f.pinSalt?.stringValue || "",
              pinAtivacao: f.pinAtivacao?.stringValue || "",
              masterHash: f.masterHash?.stringValue || "",
              masterSalt: f.masterSalt?.stringValue || "",
              senhaMaster: f.senhaMaster?.stringValue || "",
              exigirCpfMobile: Boolean(f.exigirCpfMobile && f.exigirCpfMobile.booleanValue === true),
              cpfsBloqueadosJson: f.cpfsBloqueadosJson?.stringValue || "[]",
              editoresJson: f.editoresJson?.stringValue || "[]",
              mastersCpfsJson: f.mastersCpfsJson?.stringValue || "[]"
            };
            try {
              localStorage.setItem(cacheKey, JSON.stringify({
                pinHash: govDoc.pinHash,
                pinSalt: govDoc.pinSalt,
                masterHash: govDoc.masterHash,
                masterSalt: govDoc.masterSalt,
                exigirCpfMobile: govDoc.exigirCpfMobile,
                cpfsBloqueadosJson: govDoc.cpfsBloqueadosJson,
                editoresJson: govDoc.editoresJson,
                mastersCpfsJson: govDoc.mastersCpfsJson
              }));
            } catch (e) {}
            break;
          }
        } catch (e) {}
      }
    }

    if (!govDoc && ehAmbienteExtensaoChrome()) {
      try {
        const st = await chrome.storage.local.get(["maestroGovernancaPermissoes"]);
        if (st && st.maestroGovernancaPermissoes) {
          govDoc = st.maestroGovernancaPermissoes;
        }
      } catch (e) {}
    }

    if (!govDoc) {
      try {
        const cachedRaw = localStorage.getItem(cacheKey);
        if (cachedRaw) govDoc = JSON.parse(cachedRaw);
      } catch (e) {}
    }

    if (govDoc) {
      // 1. Bloqueio absoluto por CPF
      try {
        const bloqueadosRaw = Array.isArray(govDoc.cpfsBloqueados)
          ? govDoc.cpfsBloqueados
          : JSON.parse(govDoc.cpfsBloqueadosJson || "[]");
        const bloqueados = (Array.isArray(bloqueadosRaw) ? bloqueadosRaw : []).map((c) => String(c || "").replace(/\D/g, ""));
        if (cpfLimpo.length === 11 && bloqueados.includes(cpfLimpo)) {
          return { valido: false, erro: "Este CPF encontra-se bloqueado na governança institucional." };
        }
      } catch (e) {}

      // 2. Autenticação direta via Senha Mestra de Administrador
      if (govDoc.masterHash && govDoc.masterSalt) {
        if (await verificarHashPBKDF2Mobile(clean, govDoc.masterHash, govDoc.masterSalt)) {
          return {
            valido: true,
            role: "Master",
            authPorSenhaMaster: true,
            nomeUsuario: "",
            subsecoesPermitidas: ["*"],
            varasPermitidas: { "*": ["*"] },
            varaFixa: null
          };
        }
      } else if (govDoc.senhaMaster && clean === govDoc.senhaMaster.trim()) {
        return {
          valido: true,
          role: "Master",
          authPorSenhaMaster: true,
          nomeUsuario: "",
          subsecoesPermitidas: ["*"],
          varasPermitidas: { "*": ["*"] },
          varaFixa: null
        };
      }

      // 3. Validação do PIN de Ativação
      let pinOk = false;
      let temPinConfigurado = false;
      if (govDoc.pinHash && govDoc.pinSalt) {
        temPinConfigurado = true;
        pinOk = await verificarHashPBKDF2Mobile(clean, govDoc.pinHash, govDoc.pinSalt);
      } else if (govDoc.pinAtivacao) {
        temPinConfigurado = true;
        pinOk = (clean === govDoc.pinAtivacao.trim());
      }

      if (temPinConfigurado) {
        if (!pinOk) {
          return { valido: false, erro: registrarFalhaLoginMobile() };
        }

        const escopo = resolverPermissaoMobileDoc(govDoc, cpfUsuario, subId);
        if (!escopo.autorizado) {
          return { valido: false, erro: escopo.erro };
        }

        return {
          valido: true,
          role: escopo.role,
          authPorSenhaMaster: false,
          nomeUsuario: escopo.nomeUsuario || "",
          subsecoesPermitidas: escopo.subsecoesPermitidas,
          varasPermitidas: escopo.varasPermitidas,
          varaFixa: escopo.varaFixa
        };
      }
    }

    return {
      valido: false,
      erro: "Governança em nuvem ainda não inicializada. Configure o PIN e a Senha Master no Maestro Desktop (Aba Acessos) antes de entrar pelo celular."
    };
  }

  function exibirErroLogin(msg) {
    const msgBox = document.getElementById("loginMsg");
    msgBox.textContent = "⚠️ " + msg;
    msgBox.className = "alert-box alert-danger";
    msgBox.style.display = "block";
  }

  window.fazerLogout = function () {
    if (confirm("Deseja realmente sair? Será necessário autenticar novamente com o PIN da sua Subseção.")) {
      pararAutoRefreshDia();
      localStorage.removeItem("maestro_mobile_session");
      localStorage.removeItem("maestro_mobile_key_saved");
      try { sessionStorage.removeItem("maestro_mobile_key"); } catch (e) {}
      sessaoUsuario = null;
      todasPautas = [];
      todasPericiasPje = [];
      bancoPeritosMobile = [];
      pautasParaImportar = [];
      exibirTelaLogin();
    }
  };

  // =========================================================================
  // 5. INICIALIZAÇÃO DA ÁREA LOGADA & RESTRIÇÃO DE ESCOPO
  // =========================================================================
  function aplicarEscopoSessaoNaUI() {
    if (!sessaoUsuario) return;

    const subId = sessaoUsuario.subsecaoId;
    const subInfo = SUBSECOES_MAP[subId] || { nome: sessaoUsuario.subsecaoNome || subId, varas: [] };
    const varasAuth = resolverVarasAutorizadasSubsecao(sessaoUsuario, subId);
    const subsAuth = obterSubsecoesAutorizadasSessao(sessaoUsuario);
    const podeEnviar = podeEnviarPautasNaSessao(sessaoUsuario);
    const labelVaras = obterLabelEscopoVaras(sessaoUsuario, subId);
    const ehVaraUnicaRestrita = sessaoUsuario.role !== "Master" && varasAuth.length === 1 && (subInfo.varas?.length || 0) > 1;

    // 1. Seletor rápido de Subseção no cabeçalho para Masters/Gestores com >1 subseção
    const lblNomeSub = document.getElementById("lblNomeSubsecao");
    const selHeaderSub = document.getElementById("selectHeaderSubsecao");
    if (selHeaderSub && lblNomeSub) {
      if (subsAuth.length > 1) {
        selHeaderSub.innerHTML = subsAuth.map((id) => {
          const s = SUBSECOES_MAP[id];
          return `<option value="${escapeHtml(id)}" ${id === subId ? "selected" : ""}>${escapeHtml(s ? s.nome : id)}</option>`;
        }).join("");
        selHeaderSub.style.display = "inline-block";
        lblNomeSub.style.display = "none";
      } else {
        selHeaderSub.style.display = "none";
        lblNomeSub.style.display = "inline";
        lblNomeSub.textContent = subInfo.nome;
      }
    }

    // 2. Identificação do usuário e perfil
    const cpfMask = mascararCpfMobile(sessaoUsuario.usuarioCpf);
    const lblUsuario = document.getElementById("lblUsuarioNome");
    if (lblUsuario) {
      lblUsuario.textContent = sessaoUsuario.usuarioNome
        ? `${sessaoUsuario.usuarioNome}${cpfMask ? ` (${cpfMask})` : ""}`
        : (cpfMask || "Servidor Autorizado");
    }

    const lblRole = document.getElementById("lblPerfilRole");
    if (lblRole) {
      lblRole.className = "badge-role";
      if (sessaoUsuario.role === "Master") {
        lblRole.textContent = "👑 Master";
        lblRole.classList.add("badge-role-master");
      } else if (!podeEnviar) {
        lblRole.textContent = sessaoUsuario.role === "Observador" ? "👁️ Observador" : "🎧 Leitor";
        lblRole.classList.add("badge-role-restrito");
      } else if (ehVaraUnicaRestrita) {
        lblRole.textContent = `✍️ ${varasAuth[0]}ª VF`;
        lblRole.classList.add("badge-role-leitor");
      } else if (subsAuth.length > 1 || varasAuth.length > 1) {
        lblRole.textContent = "✍️ Gestor";
      } else {
        lblRole.textContent = "✍️ Editor";
      }
    }

    const badgePerm = document.getElementById("badgePermissaoEnvioWpp");
    if (badgePerm) {
      badgePerm.textContent = `${sessaoUsuario.role} (${subInfo.nome} • ${labelVaras})`;
    }

    let escopoMsg = "";
    if (sessaoUsuario.role === "Master") {
      escopoMsg = `👑 Acesso Master (${subInfo.nome}: Todas as Varas)`;
    } else if (!podeEnviar) {
      escopoMsg = `👁️ Somente Leitura • ${subInfo.nome} (${labelVaras})`;
    } else if (ehVaraUnicaRestrita) {
      escopoMsg = `🔒 Acesso Exclusivo: ${varasAuth[0]}ª Vara Federal (${subInfo.nome})`;
    } else {
      const prefixoGestor = subsAuth.length > 1 ? `Gestor (${subsAuth.length} Subseções)` : `Subseção de ${subInfo.nome}`;
      escopoMsg = `🔓 ${prefixoGestor} • Varas: ${labelVaras}`;
    }

    document.getElementById("lblEscopoRestricao").textContent = escopoMsg;
    document.getElementById("lblRelatorioSubsecao").textContent = ehVaraUnicaRestrita ? `${subInfo.nome} • ${varasAuth[0]}ª VF` : subInfo.nome;
    document.getElementById("lblSubsecaoEscopoFiltro").textContent = ehVaraUnicaRestrita ? `${subInfo.nome} (${varasAuth[0]}ª VF)` : `Subseção: ${subInfo.nome}`;

    // 3. Ocultar/bloquear aba de envio WhatsApp para perfis somente leitura
    const btnTabWpp = document.querySelector(".main-tabs .tab-btn[data-tab='tabWhatsapp']");
    const btnQuickWpp = document.getElementById("btnQuickWhatsapp");
    if (btnTabWpp) btnTabWpp.style.display = podeEnviar ? "flex" : "none";
    if (btnQuickWpp) btnQuickWpp.style.display = podeEnviar ? "inline-flex" : "none";
    if (!podeEnviar && document.getElementById("tabWhatsapp")?.classList.contains("active")) {
      window.trocarAba("tabDashboard");
    }

    popularFiltroVaras(varasAuth);
    popularFiltroVarasPorDia(varasAuth);
    popularVaraPadraoWpp(varasAuth);
  }

  function trocarSubsecaoMobile(novaSubId) {
    if (!sessaoUsuario || !novaSubId || !SUBSECOES_MAP[novaSubId]) return;
    const subsAuth = obterSubsecoesAutorizadasSessao(sessaoUsuario);
    if (!subsAuth.includes(novaSubId)) {
      alert(`🔒 Você não possui acesso à subseção "${SUBSECOES_MAP[novaSubId]?.nome || novaSubId}".`);
      aplicarEscopoSessaoNaUI();
      return;
    }

    const subInfo = SUBSECOES_MAP[novaSubId];
    sessaoUsuario.subsecaoId = novaSubId;
    sessaoUsuario.subsecaoNome = subInfo.nome;
    sessaoUsuario.subsecaoDesc = subInfo.descricao;

    localStorage.setItem("maestro_mobile_session", JSON.stringify(sessaoUsuario));

    todasPericiasPje = [];
    pautasParaImportar = [];
    const areaPrev = document.getElementById("areaPreviewImportWpp");
    if (areaPrev) areaPrev.style.display = "none";

    aplicarEscopoSessaoNaUI();
    carregarBancoPeritosCache(novaSubId);
    atualizarBannerFilaOffline();
    window.sincronizarPautas(obterChaveNuvemSessao());
  }

  function iniciarAplicativoComSessao(chaveTemporaria = "") {
    if (!sessaoUsuario) return;

    document.getElementById("screenLogin").classList.remove("active");
    document.getElementById("screenApp").classList.add("active");

    aplicarEscopoSessaoNaUI();
    carregarBancoPeritosCache(sessaoUsuario.subsecaoId);
    atualizarBannerFilaOffline();

    window.sincronizarPautas(chaveTemporaria);

    if (textoCompartilhadoPendente) {
      const recebido = textoCompartilhadoPendente;
      textoCompartilhadoPendente = null;
      try { sessionStorage.removeItem("maestro_mobile_shared_pending"); } catch (e) {}
      if (podeEnviarPautasNaSessao()) {
        window.trocarAba("tabWhatsapp");
        const txtEl = document.getElementById("txtConversaWhatsApp");
        if (txtEl) txtEl.value = recebido;
        interpretarTextoWhatsApp();
      } else {
        alert("👁️ Seu perfil é Somente Leitura e não possui permissão para importar pautas.");
      }
    }
  }

  function preencherSelectFiltroVaras(selectId, varas) {
    const select = document.getElementById(selectId);
    if (!select) return;
    const lista = Array.isArray(varas) ? varas : [];
    if (lista.length === 1) {
      select.innerHTML = `<option value="${escapeHtml(lista[0])}">${escapeHtml(lista[0])}ª Vara (Exclusiva)</option>`;
      select.value = lista[0];
      select.disabled = true;
      select.title = `Acesso exclusivo à ${lista[0]}ª Vara Federal`;
      return;
    }
    select.disabled = false;
    select.title = "";
    select.innerHTML = '<option value="">Todas as Varas</option>';
    lista.forEach((v) => {
      const opt = document.createElement("option");
      opt.value = v;
      opt.textContent = `${v}ª Vara`;
      select.appendChild(opt);
    });
  }

  function popularFiltroVaras(varas) {
    preencherSelectFiltroVaras("filtroVara", varas);
    preencherSelectFiltroVaras("filtroVaraDashboard", varas);
    preencherSelectFiltroVaras("relFiltroVara", varas);
  }

  function popularFiltroVarasPorDia(varas) {
    preencherSelectFiltroVaras("filtroVaraPorDia", varas);
  }

  function popularVaraPadraoWpp(varas) {
    const sel = document.getElementById("selVaraPadraoWpp");
    if (!sel) return;
    sel.innerHTML = "";
    const lista = Array.isArray(varas) && varas.length > 0 ? varas : ["19", "31", "18"];
    lista.forEach((v) => {
      const opt = document.createElement("option");
      opt.value = v;
      opt.textContent = `${v}ª Vara Federal`;
      sel.appendChild(opt);
    });
    if (lista.length === 1) {
      sel.value = lista[0];
      sel.disabled = true;
      sel.title = `Travado na ${lista[0]}ª Vara Federal pelo Administrador Master`;
    } else {
      sel.disabled = false;
      sel.title = "";
      if (lista.includes("19")) sel.value = "19";
    }
  }

  function carregarBancoPeritosCache(subId) {
    try {
      const raw = localStorage.getItem(`maestro_mobile_peritos_${subId}`);
      if (raw) {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) {
          bancoPeritosMobile = parsed;
          popularDatalistPeritosMobile();
        }
      }
    } catch (e) {}
  }

  function salvarBancoPeritosCache(subId, lista) {
    try {
      localStorage.setItem(`maestro_mobile_peritos_${subId}`, JSON.stringify(lista || []));
    } catch (e) {}
  }

  function popularDatalistPeritosMobile() {
    const dl = document.getElementById("datalistPeritosMobile");
    if (!dl) return;
    const nomesSet = new Set();
    (bancoPeritosMobile || []).forEach((p) => {
      if (p && p.nome) nomesSet.add(String(p.nome).trim());
    });
    if (Parser && Parser.MAPA_NOMES_OFICIAIS) {
      Object.values(Parser.MAPA_NOMES_OFICIAIS).forEach((n) => {
        if (n) nomesSet.add(n);
      });
    }
    const ordenados = Array.from(nomesSet).sort((a, b) => a.localeCompare(b, "pt-BR", { sensitivity: "base" }));
    dl.innerHTML = ordenados.map((n) => `<option value="${escapeHtml(n)}"></option>`).join("");
  }

  // =========================================================================
  // 6. SINCRONIZAÇÃO DE PAUTAS & PERITOS (FIRESTORE E2EE + FALLBACK LOCAL)
  // =========================================================================
  function removerAcentosLowerMobile(str) {
    return String(str || "")
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "")
      .toLowerCase()
      .trim();
  }

  function extrairDataIsoPericiaMobile(item) {
    if (!item || typeof item !== "object") return "";
    const rawIso = String(item.dataPericiaIso || item.dataIso || item.data || "").trim();
    const mIso = rawIso.match(/^(\d{4})-(\d{1,2})-(\d{1,2})/);
    if (mIso) {
      return `${mIso[1]}-${mIso[2].padStart(2, "0")}-${mIso[3].padStart(2, "0")}`;
    }
    const rawBr = String(item.dataPericia || item.dataRealizacao || rawIso).trim();
    const mBr = rawBr.match(/^(\d{1,2})\/(\d{1,2})\/(\d{2,4})/);
    if (mBr) {
      let ano = mBr[3];
      if (ano.length === 2) ano = `20${ano}`;
      return `${ano}-${mBr[2].padStart(2, "0")}-${mBr[1].padStart(2, "0")}`;
    }
    return "";
  }

  function ehPericiaPjeCanceladaOuInvalidaMobile(item) {
    if (!item || typeof item !== "object") return true;
    if (item.cancelada === true || item.cancelada === "true") return true;
    const txt = removerAcentosLowerMobile(
      `${item.status || ""} ${item.situacao || ""} ${item.situacaoPje || ""} ${item.motivo || ""} ${item.objeto || ""}`
    );
    if (/cancelad|cancelamento|prejudicad|redesignad|suspens|desmarcad|anulad|sem\s*efeito|excluid/i.test(txt)) return true;
    const proc = String(item.processoLimpo || item.processo || "").replace(/\D/g, "");
    if (proc.length < 15) return true;
    return false;
  }

  function extrairVaraNumeroPericiaMobile(varaStr) {
    const raw = String(varaStr || "").trim();
    if (!raw) return "";
    const m = raw.match(/(\d+)\s*[ªa°]?/i);
    return m ? normalizarNumeroVara(m[1]) : normalizarNumeroVara(raw);
  }

  function normalizarPericiaPjeMobile(raw, subIdFallback = "sobral") {
    if (!raw || typeof raw !== "object") return null;
    if (ehPericiaPjeCanceladaOuInvalidaMobile(raw)) return null;
    const dataPericiaIso = extrairDataIsoPericiaMobile(raw);
    if (!dataPericiaIso) return null;
    const processo = String(raw.processo || raw.processoLimpo || "").trim();
    const processoLimpo = processo.replace(/\D/g, "");
    const horaRaw = String(raw.horaPericia || raw.hora || "").trim();
    const mHora = horaRaw.match(/(\d{1,2}):(\d{2})/);
    const horaPericia = mHora ? `${mHora[1].padStart(2, "0")}:${mHora[2]}` : (horaRaw || "--:--");
    const vara = String(raw.vara || raw.varaPericia || "").trim();
    const varaNum = extrairVaraNumeroPericiaMobile(vara);

    return {
      processo: processo || processoLimpo,
      processoLimpo,
      dataPericiaIso,
      horaPericia,
      perito: String(raw.perito || raw.nomePerito || "Perito não informado").trim(),
      especialidade: String(raw.especialidade || raw.tipoPericia || "").trim(),
      vara: vara || (varaNum ? `${varaNum}ª Vara Federal` : ""),
      varaNum,
      periciado: String(raw.periciado || raw.autor || raw.nomePericiado || "Periciando").trim(),
      statusAtendimento: String(raw.statusAtendimento || "AGUARDANDO_CHEGADA").trim().toUpperCase(),
      presencaConfirmada: Boolean(raw.presencaConfirmada),
      urgenciaMedica: Boolean(raw.urgenciaMedica),
      horarioCheckin: String(raw.horarioCheckin || "").trim(),
      sala: String(raw.sala || "").trim(),
      ultimaChamadaHora: String(raw.ultimaChamadaHora || "").trim(),
      subsecaoId: String(raw.subsecaoId || subIdFallback || "sobral").trim().toLowerCase()
    };
  }

  function aplicarFiltroRestritoPericiasPje(lista, subIdAutorizada) {
    const subNorm = String(subIdAutorizada || "").trim().toLowerCase();
    const subInfo = SUBSECOES_MAP[subNorm];
    const varasSub = Array.isArray(subInfo?.varas) ? subInfo.varas.map(normalizarNumeroVara) : [];
    const varasAuth = resolverVarasAutorizadasSubsecao(sessaoUsuario, subNorm);
    const acessoIrrestritoSub = !sessaoUsuario || sessaoUsuario.role === "Master" || varasAuth.length >= varasSub.length;

    return (lista || []).filter((p) => {
      if (!p || ehPericiaPjeCanceladaOuInvalidaMobile(p)) return false;
      if (p.subsecaoId && subNorm && String(p.subsecaoId).toLowerCase() !== subNorm) return false;
      const vNum = p.varaNum || extrairVaraNumeroPericiaMobile(p.vara);
      if (vNum) {
        if (varasSub.length > 0 && !varasSub.includes(vNum)) return false;
        if (sessaoUsuario && !isVaraAutorizadaNaSessao(vNum, sessaoUsuario, subNorm)) return false;
        return true;
      }
      return acessoIrrestritoSub;
    });
  }

  function carregarPericiasPjeCache(subId, bloquear = false) {
    if (bloquear) return [];
    try {
      const raw = localStorage.getItem(`maestro_pericias_pje_${subId}`);
      if (raw) {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) return parsed;
      }
    } catch (e) {}
    return [];
  }

  function salvarPericiasPjeCache(subId, lista) {
    try {
      localStorage.setItem(`maestro_pericias_pje_${subId}`, JSON.stringify(lista || []));
    } catch (e) {}
  }

  async function carregarBasePericiasPjeNuvemMobile(projectId, subId, chaveNuvem, docSubsecaoFields = null) {
    if (!projectId || !subId || projectId.includes("exemplo")) {
      return { itens: [], timestamp: 0 };
    }
    let itensBrutos = null;
    let timestamp = 0;

    try {
      const urlChamada = `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/databases/(default)/documents/subsecoes/${encodeURIComponent(subId)}_CHAMADA`;
      const respChamada = await fetch(urlChamada, { method: "GET", cache: "no-store" });
      if (respChamada.ok) {
        const doc = await respChamada.json();
        const f = doc.fields || {};
        timestamp = parseInt(f.timestampAtualizacaoBase?.integerValue || "0", 10) || 0;
        const shardingAtivo = f.shardingAtivo?.booleanValue === true;
        const totalShards = parseInt(f.totalShards?.integerValue || "0", 10) || 0;

        if (shardingAtivo && totalShards > 0) {
          let shardIds = [];
          if (f.shardIdsJson?.stringValue) {
            try {
              const parsedIds = JSON.parse(f.shardIdsJson.stringValue);
              if (Array.isArray(parsedIds)) {
                shardIds = parsedIds.filter((s) => typeof s === "string" && s.trim()).slice(0, totalShards);
              }
            } catch (e) {}
          }
          if (shardIds.length === 0) {
            shardIds = Array.from({ length: totalShards }, (_, idx) => `${subId}_CHAMADA_SHARD_${idx}`);
          }

          const shardsDocs = await Promise.all(shardIds.map(async (sId) => {
            try {
              const urlS = `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/databases/(default)/documents/subsecoes/${encodeURIComponent(sId)}`;
              const rS = await fetch(urlS, { method: "GET", cache: "no-store" });
              if (!rS.ok) return null;
              return await rS.json();
            } catch (e) {
              return null;
            }
          }));

          const acum = [];
          for (const shardDoc of shardsDocs) {
            const sf = shardDoc?.fields;
            if (!sf?.payloadJson?.stringValue) continue;
            const decShard = await decodificarOuDecifrarDadoNuvemMobile(
              sf.payloadJson.stringValue,
              sf.ivPayload?.stringValue,
              sf.saltPayload?.stringValue,
              chaveNuvem
            );
            if (Array.isArray(decShard)) {
              acum.push(...decShard);
            }
          }
          if (acum.length > 0) {
            itensBrutos = acum;
          }
        }

        if ((!Array.isArray(itensBrutos) || itensBrutos.length === 0) && f.basePericiasJson?.stringValue) {
          const decInline = await decodificarOuDecifrarDadoNuvemMobile(
            f.basePericiasJson.stringValue,
            f.ivBasePericias?.stringValue,
            f.saltBasePericias?.stringValue,
            chaveNuvem
          );
          if (Array.isArray(decInline)) {
            itensBrutos = decInline;
          }
        }
      }
    } catch (eChamada) {
      console.warn("[Maestro Mobile] Falha ao ler _CHAMADA:", eChamada.message);
    }

    if ((!Array.isArray(itensBrutos) || itensBrutos.length === 0) && docSubsecaoFields?.basePericiasJson?.stringValue) {
      try {
        const decSub = await decodificarOuDecifrarDadoNuvemMobile(
          docSubsecaoFields.basePericiasJson.stringValue,
          docSubsecaoFields.ivBasePericias?.stringValue,
          docSubsecaoFields.saltBasePericias?.stringValue,
          chaveNuvem
        );
        if (Array.isArray(decSub)) {
          itensBrutos = decSub;
          if (!timestamp) {
            timestamp = parseInt(docSubsecaoFields.timestampBasePericias?.integerValue || "0", 10) || 0;
          }
        }
      } catch (eSub) {}
    }

    const normalizados = Array.isArray(itensBrutos)
      ? itensBrutos.map((raw) => normalizarPericiaPjeMobile(raw, subId)).filter(Boolean)
      : [];

    return { itens: normalizados, timestamp };
  }

  window.sincronizarPautas = async function (chaveExplicita = "") {
    if (!sessaoUsuario) return;

    mostrarFeedbackCarregamento(true);

    try {
      let pautasCarregadas = [];
      let periciasPjeCarregadas = [];
      let peritosCarregados = [];
      const chaveNuvem = chaveExplicita || obterChaveNuvemSessao();
      const subId = sessaoUsuario.subsecaoId;

      let erroDecifragemChave = false;
      let tombstonesNuvem = {};
      let docSubsecaoFields = null;

      // 1. Tenta carregar do Firestore se houver Project ID configurado
      if (sessaoUsuario.projectId && sessaoUsuario.projectId.trim() && !sessaoUsuario.projectId.includes("exemplo")) {
        try {
          const url = `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(sessaoUsuario.projectId)}/databases/(default)/documents/subsecoes/${encodeURIComponent(subId)}`;
          const resp = await fetch(url, { method: "GET", cache: "no-cache" });
          if (resp.ok) {
            const doc = await resp.json();
            const fields = doc.fields || {};
            docSubsecaoFields = fields;

            if (fields.bancoPeritosJson?.stringValue) {
              try {
                const parsedPeritos = await decodificarOuDecifrarDadoNuvemMobile(
                  fields.bancoPeritosJson.stringValue,
                  fields.ivPeritos?.stringValue || fields.iv?.stringValue,
                  fields.saltPeritos?.stringValue || fields.salt?.stringValue,
                  chaveNuvem
                );
                if (Array.isArray(parsedPeritos) && parsedPeritos.length > 0) {
                  peritosCarregados = parsedPeritos;
                }
              } catch (ePer) {}
            }

            if (fields.escalaTombstonesJson?.stringValue) {
              try {
                const decTomb = await decodificarOuDecifrarDadoNuvemMobile(
                  fields.escalaTombstonesJson.stringValue,
                  fields.ivTombstones?.stringValue,
                  fields.saltTombstones?.stringValue,
                  chaveNuvem
                );
                if (decTomb && typeof decTomb === "object") {
                  tombstonesNuvem = decTomb;
                }
              } catch (eTomb) {}
            }

            if (fields.escalaPautasJson?.stringValue) {
              let parsedEscala = null;
              try {
                parsedEscala = await decodificarOuDecifrarDadoNuvemMobile(
                  fields.escalaPautasJson.stringValue,
                  fields.ivEscala?.stringValue || fields.iv?.stringValue,
                  fields.saltEscala?.stringValue || fields.salt?.stringValue,
                  chaveNuvem
                );
              } catch (eEsc) {
                erroDecifragemChave = true;
              }
              if (parsedEscala === null) {
                erroDecifragemChave = true;
              } else if (Array.isArray(parsedEscala)) {
                pautasCarregadas = converterPautasFirestore(parsedEscala).filter((item) => {
                  const k = gerarChaveUnicaPauta(item);
                  const tomb = tombstonesNuvem[k] || (item.id && tombstonesNuvem[String(item.id)]);
                  if (!tomb) return true;
                  const delTs = Number(tomb.deletedAt || tomb || 0);
                  const updTs = Number(item.updatedAt || item.createdAt || 0);
                  return updTs > delTs;
                });
              }
            }
          }
        } catch (eNuvem) {
          console.warn("Nuvem indisponível:", eNuvem.message);
        }

        if (!erroDecifragemChave) {
          try {
            const pjeRes = await carregarBasePericiasPjeNuvemMobile(
              sessaoUsuario.projectId,
              subId,
              chaveNuvem,
              docSubsecaoFields
            );
            if (Array.isArray(pjeRes.itens) && pjeRes.itens.length > 0) {
              periciasPjeCarregadas = pjeRes.itens;
            }
            if (pjeRes.timestamp) {
              ultimaSyncPautaPjeTs = pjeRes.timestamp;
            }
          } catch (ePjeNuvem) {
            console.warn("[Maestro Mobile] Pauta PJe nuvem:", ePjeNuvem.message);
          }
        }
      }

      if (erroDecifragemChave) {
        alert(
          "⚠️ Chave AES-256 incorreta ou alterada no Desktop.\n\n" +
          "Não foi possível decifrar as pautas da nuvem com a chave atual. Confira a chave no Maestro Desktop e atualize seu login."
        );
      }

      // 2. Fallback para chrome.storage.local se aberto como janela da extensão
      if (ehAmbienteExtensaoChrome()) {
        try {
          const baseKeySub = `basePericiasPje_${subId}`;
          const store = await chrome.storage.local.get([`escalaPautas_${subId}`, `bancoPeritos_${subId}`, baseKeySub, "basePericiasPje"]);
          if ((!pautasCarregadas || pautasCarregadas.length === 0) && Array.isArray(store[`escalaPautas_${subId}`])) {
            pautasCarregadas = converterPautasFirestore(store[`escalaPautas_${subId}`]);
          }
          if ((!peritosCarregados || peritosCarregados.length === 0) && Array.isArray(store[`bancoPeritos_${subId}`])) {
            peritosCarregados = store[`bancoPeritos_${subId}`];
          }
          if (!periciasPjeCarregadas || periciasPjeCarregadas.length === 0) {
            const rawLocalPje = Array.isArray(store[baseKeySub]) ? store[baseKeySub] : store.basePericiasPje;
            const arrLocalPje = Array.isArray(rawLocalPje) ? rawLocalPje : (rawLocalPje?.listaFinal || []);
            if (Array.isArray(arrLocalPje) && arrLocalPje.length > 0) {
              periciasPjeCarregadas = arrLocalPje.map((raw) => normalizarPericiaPjeMobile(raw, subId)).filter(Boolean);
            }
          }
        } catch (eExt) {}
      }

      if (peritosCarregados.length > 0) {
        bancoPeritosMobile = peritosCarregados;
        salvarBancoPeritosCache(subId, bancoPeritosMobile);
        popularDatalistPeritosMobile();
      } else {
        popularDatalistPeritosMobile();
      }

      if (!pautasCarregadas || pautasCarregadas.length === 0) {
        pautasCarregadas = carregarPautasLocaisSubsecao(subId, erroDecifragemChave);
      }

      if (!periciasPjeCarregadas || periciasPjeCarregadas.length === 0) {
        periciasPjeCarregadas = carregarPericiasPjeCache(subId, erroDecifragemChave);
      }

      todasPautas = aplicarFiltroRestritoSubsecao(pautasCarregadas, subId);
      todasPericiasPje = aplicarFiltroRestritoPericiasPje(periciasPjeCarregadas, subId);
      ultimaSyncEscalaTs = Date.now();
      if (!erroDecifragemChave) {
        salvarCacheLocal(subId, todasPautas);
        salvarPericiasPjeCache(subId, todasPericiasPje);
      }
      atualizarIndicadorSync();
      atualizarInterfaceCompleta();
    } catch (err) {
      console.error("Erro na sincronização:", err);
      mostrarToast("Erro ao sincronizar pautas: " + err.message, "error", 4200);
    } finally {
      mostrarFeedbackCarregamento(false);
    }
  };

  function carregarPautasLocaisSubsecao(subId, bloquearMock = false) {
    try {
      const cache = localStorage.getItem(`maestro_pautas_${subId}`);
      if (cache) {
        const parsed = JSON.parse(cache);
        if (Array.isArray(parsed) && parsed.length > 0) return parsed;
      }
    } catch (e) {}

    if (bloquearMock) {
      return [];
    }

    if (subId === "sobral") {
      return RAW_PAUTAS_SOBRAL_BASE.map((p, idx) => converterItemUnicoCanonico({
        id: `pauta_sobral_${idx}`,
        peritoNome: p[0],
        especialidade: p[1],
        local: p[2],
        data: p[3],
        vara: String(p[4]),
        quantidade: Number(p[5]) || 1,
        horaInicio: p[6] || "08:00",
        intervaloMin: Number(p[7]) || 15,
        situacao: p[8] || "Marcado",
        observacoes: p[9] || ""
      }));
    }

    const subInfo = SUBSECOES_MAP[subId] || { varas: ["1"] };
    const primeiraVara = subInfo.varas[0] || "1";
    return [
      converterItemUnicoCanonico({
        id: `pauta_${subId}_1`,
        peritoNome: "Perito Oficial Designado",
        especialidade: "Clínica Médica Geral / Ortopedia",
        local: "Justiça Federal",
        data: new Date().toISOString().slice(0, 10),
        vara: primeiraVara,
        quantidade: 20,
        horaInicio: "08:00",
        intervaloMin: 15,
        situacao: "Marcado",
        observacoes: "Pauta Geral"
      })
    ];
  }

  function converterItemUnicoCanonico(p, idxFallback = 0) {
    const qty = Number(p.quantidade !== undefined ? p.quantidade : (p.vagas || 20)) || 1;
    const hora = p.horaInicio || p.hora || "08:00";
    const intervalo = Number(p.intervaloMin !== undefined ? p.intervaloMin : (p.duracao || 10)) || 10;
    const obs = p.observacoes !== undefined ? p.observacoes : (p.observacao || "");
    const nomePerito = p.peritoNome || p.perito || "Perito";
    const esp = p.especialidade || p.obs || "";
    const horaTermino = p.horaTermino || (Parser ? Parser.calcularHorarioTermino(hora, intervalo, qty) : "");
    const dataLimite = p.dataLimite || (Parser && p.data ? Parser.calcularDataLimite8DiasUteis(p.data) : "");
    const prazoDias = p.prazoDias !== undefined ? p.prazoDias : (Parser && dataLimite ? Parser.calcularPrazoDias(dataLimite) : null);

    return {
      ...p,
      id: p.id || `pauta_nuvem_${idxFallback}`,
      peritoNome: nomePerito,
      especialidade: esp,
      local: p.local || "Justiça Federal",
      endereco: p.endereco || "",
      data: p.data || "",
      vara: String(p.vara || "19"),
      quantidade: qty,
      horaInicio: hora,
      intervaloMin: intervalo,
      horaTermino,
      dataLimite,
      prazoDias,
      situacao: normalizarSituacao(p.situacao || p.status),
      observacoes: obs,
      // Aliases para compatibilidade com gráficos e cards mobile
      vagas: qty,
      hora,
      duracao: intervalo,
      observacao: obs,
      subsecaoId: sessaoUsuario?.subsecaoId || p.subsecaoId || "sobral",
      categoria: classificarCategoria(nomePerito, esp)
    };
  }

  function converterPautasFirestore(lista) {
    return (lista || []).map((p, idx) => converterItemUnicoCanonico(p, idx));
  }

  function normalizarSituacao(st) {
    if (!st) return "Não marcado";
    const norm = String(st).toLowerCase();
    if (norm.includes("em marca")) return "Em marcação";
    if (norm.includes("nao marc") || norm.includes("não marc") || norm.includes("pend") || norm.includes("abert") || norm.includes("reserv")) return "Não marcado";
    if (norm.includes("canc")) return "Cancelado";
    if (norm.includes("marc")) return "Marcado";
    return st;
  }

  function ehSituacaoPendente(situacao) {
    const s = String(situacao || "").toLowerCase();
    return s.includes("pend") || s.includes("não marc") || s.includes("nao marc") || s.includes("em marca");
  }

  function classificarCategoria(nome, esp) {
    const texto = `${nome || ""} ${esp || ""}`.toLowerCase();
    if (texto.includes("social") || texto.includes("assist") || texto.includes("loas")) return "social";
    if (texto.includes("engenharia") || texto.includes("contabil") || texto.includes("grafotec")) return "outras";
    return "medica";
  }

  function aplicarFiltroRestritoSubsecao(lista, subIdAutorizada) {
    return (lista || []).filter((p) => {
      if (p.subsecaoId && p.subsecaoId !== subIdAutorizada) return false;
      const subInfo = SUBSECOES_MAP[subIdAutorizada];
      if (subInfo && subInfo.varas && subInfo.varas.length > 0) {
        const varaPauta = normalizarNumeroVara(p.vara);
        if (varaPauta && !subInfo.varas.includes(varaPauta)) {
          return false;
        }
      }
      if (sessaoUsuario && !isVaraAutorizadaNaSessao(p.vara, sessaoUsuario, subIdAutorizada)) {
        return false;
      }
      return true;
    });
  }

  function salvarCacheLocal(subId, lista) {
    try {
      localStorage.setItem(`maestro_pautas_${subId}`, JSON.stringify(lista));
    } catch (e) {}
  }

  function mostrarFeedbackCarregamento(carregando) {
    const btn = document.getElementById("btnHeaderSyncPautas");
    if (btn) {
      btn.style.opacity = carregando ? "0.4" : "1";
    }
  }

  // =========================================================================
  // 7. FLUXO DE IMPORTAÇÃO DO WHATSAPP → PLANILHA (ESCALA & CALENDÁRIO)
  // =========================================================================
  function gerarChaveUnicaPauta(p) {
    const d = String(p?.data || "").trim();
    const n = (Parser ? Parser.removerAcentos(p?.peritoNome || "") : String(p?.peritoNome || "")).toLowerCase().trim();
    const vRaw = String(p?.vara || "").trim();
    const vNum = vRaw.replace(/\D/g, "");
    const v = (vNum || vRaw).toLowerCase();
    const h = String(p?.horaInicio || p?.hora || "").trim();
    return `${d}_${n}_${v}_${h}`;
  }

  function estaExcluidaPorTombstoneMobile(p, tombstones) {
    if (!p || !tombstones || typeof tombstones !== "object") return false;
    const k = gerarChaveUnicaPauta(p);
    const tomb = (k && k !== "___" ? tombstones[k] : null) || (p.id ? tombstones[String(p.id)] : null);
    if (!tomb) return false;
    const delTs = Number(tomb.deletedAt || tomb || 0);
    const updTs = Number(p.updatedAt || p.createdAt || 0);
    return updTs <= delTs;
  }

  function mesclarListasEscala(listaBase, listaNovas, tombstones = null) {
    const base = Array.isArray(listaBase) ? listaBase : [];
    const novas = Array.isArray(listaNovas) ? listaNovas : [];
    const mapa = new Map();

    base.forEach((item) => {
      if (!item || estaExcluidaPorTombstoneMobile(item, tombstones)) return;
      const k = gerarChaveUnicaPauta(item);
      if (k && k !== "___") {
        mapa.set(k, { ...item });
      } else if (item.id) {
        mapa.set(String(item.id), { ...item });
      }
    });

    let adicionadas = 0;
    let atualizadas = 0;

    novas.forEach((nova) => {
      if (!nova) return;
      const itemComTs = {
        ...nova,
        updatedAt: Number(nova.updatedAt || nova.createdAt || Date.now())
      };
      if (estaExcluidaPorTombstoneMobile(itemComTs, tombstones)) return;
      const k = gerarChaveUnicaPauta(itemComTs);
      if (k && k !== "___" && mapa.has(k)) {
        const existente = mapa.get(k);
        mapa.set(k, {
          ...existente,
          ...itemComTs,
          id: existente.id || itemComTs.id
        });
        atualizadas++;
      } else if (itemComTs.id && mapa.has(String(itemComTs.id))) {
        const existente = mapa.get(String(itemComTs.id));
        mapa.set(String(itemComTs.id), {
          ...existente,
          ...itemComTs,
          id: existente.id || itemComTs.id
        });
        atualizadas++;
      } else {
        const keyFinal = (k && k !== "___") ? k : String(itemComTs.id || `mob_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`);
        mapa.set(keyFinal, itemComTs);
        adicionadas++;
      }
    });

    return {
      listaFinal: Array.from(mapa.values()),
      adicionadas,
      atualizadas
    };
  }

  async function colarTextoWhatsApp() {
    const txtArea = document.getElementById("txtConversaWhatsApp");
    try {
      if (navigator.clipboard && typeof navigator.clipboard.readText === "function") {
        const clipText = await navigator.clipboard.readText();
        if (clipText && clipText.trim()) {
          if (txtArea) txtArea.value = clipText;
          interpretarTextoWhatsApp();
          return;
        }
        alert("📋 A área de transferência está vazia.\n\nCopie uma mensagem de pauta no WhatsApp e toque neste botão novamente.");
        return;
      }
    } catch (err) {
      // Alguns navegadores Android pedem colagem direta pelo toque no textarea
    }
    if (txtArea) {
      txtArea.focus();
      alert("Toque e segure dentro da caixa de texto abaixo e selecione 'Colar', depois toque em 'Interpretar Pauta(s)'.");
    }
  }

  function preencherExemploWhatsApp() {
    const txtArea = document.getElementById("txtConversaWhatsApp");
    if (!txtArea) return;
    txtArea.value = [
      "[24/11 09:40] Dra. Bárbara Duarte: Olá! Posso atender dias 07/12 e 14/12 às 08h30 (15 vagas), 19ª Vara, na Justiça Federal.",
      "[24/11 09:52] Dr. Pedro Wisley Hardy: Pessoal, para o dia 16/12 na 31ª Vara posso fazer 10 perícias às 08h na Clínica Própria (Rua Cel. Mont'Alverne, 450 - Sobral)."
    ].join("\n");
    interpretarTextoWhatsApp();
  }

  function limparEntradaWhatsApp() {
    const txtArea = document.getElementById("txtConversaWhatsApp");
    if (txtArea) txtArea.value = "";
    pautasParaImportar = [];
    const areaPrev = document.getElementById("areaPreviewImportWpp");
    if (areaPrev) areaPrev.style.display = "none";
    const msgBox = document.getElementById("msgResultadoImportWpp");
    if (msgBox) msgBox.style.display = "none";
  }

  function atualizarResumoPadraoPeritoMobile() {
    const infoEl = document.getElementById("wppMobilePadraoPeritoInfo");
    const inp = document.getElementById("inpPeritoPadraoWpp");
    if (!infoEl || !inp || !Parser) return;
    const nomeRaw = String(inp.value || "").trim();
    if (!nomeRaw) {
      infoEl.style.display = "none";
      infoEl.innerHTML = "";
      return;
    }
    const match = Parser.encontrarPeritoNoTexto(nomeRaw, bancoPeritosMobile);
    if (!match || !match.peritoObj) {
      infoEl.style.display = "block";
      infoEl.innerHTML = `<div class="wpp-alert-pill">👤 Perito padrão: <b>${escapeHtml(match?.nome || nomeRaw)}</b> (regras gerais padrão)</div>`;
      return;
    }
    const varaPadrao = document.getElementById("selVaraPadraoWpp")?.value || "";
    const r = Parser.obterRegrasVaraPerito(match.peritoObj, varaPadrao);
    const pp = r.padraoPauta || {};
    const modoDesc = pp.turnosPadrao === "manha_tarde"
      ? `Manhã (${escapeHtml(pp.horaInicioManha || "08:00")}, ${pp.vagasManha || r.procsPorPauta}v) + Tarde (${escapeHtml(pp.horaInicioTarde || "auto")}, ${pp.vagasTarde || pp.vagasManha || r.procsPorPauta}v)`
      : `1 turno (${escapeHtml(pp.horaInicioManha || "08:00")}, ${pp.vagasManha || r.procsPorPauta}v)`;
    infoEl.style.display = "block";
    infoEl.innerHTML = `<div class="wpp-alert-pill">⚡ <b>${escapeHtml(match.nome)}</b>: ${modoDesc} • ${r.intervaloMin} min${r.localExternoPadrao ? ` • 🏥 ${escapeHtml(r.localExternoPadrao)}` : ""}</div>`;
  }


  function interpretarTextoWhatsApp() {
    if (!podeEnviarPautasNaSessao()) {
      alert("👁️ Seu perfil é Somente Leitura e não possui permissão para importar pautas.");
      return;
    }
    const txtArea = document.getElementById("txtConversaWhatsApp");
    const rawText = (txtArea?.value || "").trim();
    if (!rawText) {
      alert("⚠️ Cole ou digite o texto da conversa do WhatsApp antes de interpretar.");
      if (txtArea) txtArea.focus();
      return;
    }
    if (!Parser || typeof Parser.parsearConversaWhatsApp !== "function") {
      alert("❌ Módulo whatsapp-parser.js não carregado.");
      return;
    }

    const subId = sessaoUsuario?.subsecaoId || "sobral";
    const varasAuth = resolverVarasAutorizadasSubsecao(sessaoUsuario, subId);
    const varaPadrao = document.getElementById("selVaraPadraoWpp")?.value || varasAuth[0] || "19";
    const situacaoPadrao = document.getElementById("selSituacaoPadraoWpp")?.value || "Não marcado";
    const peritoPadrao = document.getElementById("inpPeritoPadraoWpp")?.value.trim() || "";
    const modoTurnos = document.getElementById("selModoTurnosWpp")?.value || "padrao_perito";

    const resultado = Parser.parsearConversaWhatsApp(rawText, {
      bancoPeritos: bancoPeritosMobile,
      varaPadrao,
      subsecaoVaras: varasAuth,
      subsecaoId: subId,
      situacaoPadrao,
      peritoPadrao,
      modoTurnos
    });

    const avisos = [...(resultado.avisos || [])];
    let qtdForaEscopo = 0;

    pautasParaImportar = (resultado.pautas || []).map((p) => {
      if (!p._meta) p._meta = {};
      const autorizada = isVaraAutorizadaNaSessao(p.vara, sessaoUsuario, subId);
      if (!autorizada) {
        p._meta.selecionada = false;
        qtdForaEscopo++;
      } else if (typeof p._meta.selecionada !== "boolean") {
        p._meta.selecionada = true;
      }
      return p;
    });

    if (qtdForaEscopo > 0) {
      avisos.unshift(`🔒 ${qtdForaEscopo} pauta(s) detectada(s) em Vara fora do seu escopo (${obterLabelEscopoVaras(sessaoUsuario, subId)}) foram desmarcadas. Ajuste a Vara ou remova o card antes de enviar.`);
    }

    renderizarCardsImportacaoWpp(avisos);

    const msgBox = document.getElementById("msgResultadoImportWpp");
    if (msgBox) msgBox.style.display = "none";

    const areaPrev = document.getElementById("areaPreviewImportWpp");
    if (areaPrev && pautasParaImportar.length > 0) {
      areaPrev.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  function adicionarPautaManualWpp() {
    if (!podeEnviarPautasNaSessao()) {
      alert("👁️ Seu perfil é Somente Leitura e não possui permissão para criar pautas.");
      return;
    }
    if (!Parser) return;
    const subId = sessaoUsuario?.subsecaoId || "sobral";
    const varasAuth = resolverVarasAutorizadasSubsecao(sessaoUsuario, subId);
    const varaPadrao = document.getElementById("selVaraPadraoWpp")?.value || varasAuth[0] || "19";
    const situacaoPadrao = document.getElementById("selSituacaoPadraoWpp")?.value || "Não marcado";

    const nova = Parser.prepararPautaCanonica({
      peritoNome: "",
      especialidade: "",
      data: new Date().toISOString().slice(0, 10),
      vara: varaPadrao,
      local: "Justiça Federal",
      endereco: "",
      quantidade: 20,
      intervaloMin: 10,
      horaInicio: "08:00",
      situacao: situacaoPadrao,
      observacoes: ""
    }, bancoPeritosMobile);

    nova._meta = {
      pendencias: Parser.calcularPendenciasPauta(nova),
      confianca: "media",
      trechoOrigem: "Adicionada manualmente",
      selecionada: true
    };
    pautasParaImportar.push(nova);
    renderizarCardsImportacaoWpp();
  }

  function alternarSelecaoTodasImportWpp() {
    if (pautasParaImportar.length === 0) return;
    const todasMarcadas = pautasParaImportar.every((p) => p._meta?.selecionada !== false);
    const novoEstado = !todasMarcadas;
    pautasParaImportar.forEach((p) => {
      if (!p._meta) p._meta = {};
      p._meta.selecionada = novoEstado && isVaraAutorizadaNaSessao(p.vara);
    });
    renderizarCardsImportacaoWpp();
  }

  function verificarConflitosImportacao(itens) {
    const chavesExistentes = new Set(todasPautas.map(gerarChaveUnicaPauta));
    const subId = sessaoUsuario?.subsecaoId || "sobral";
    const varasSub = resolverVarasAutorizadasSubsecao(sessaoUsuario, subId);

    return (itens || []).map((p, idx) => {
      const chave = gerarChaveUnicaPauta(p);
      const duplicata = Boolean(p.data && p.peritoNome && chavesExistentes.has(chave));

      let choqueSala = false;
      let totalSalasTurno = 0;
      if (Parser && p.data && Parser.ocupaSalasNoPredio(p.local)) {
        const h = parseInt((p.horaInicio || "08:00").split(":")[0], 10);
        const turno = h < 12 ? "manha" : "tarde";
        const anterioresMesmoTurno = itens
          .slice(0, idx)
          .filter((x) => x && x._meta?.selecionada !== false);
        const ocup = Parser.obterOcupacaoSalasTurno(p.data, turno, [...todasPautas, ...anterioresMesmoTurno]);
        const pNorm = Parser.removerAcentos(p.peritoNome || "").toLowerCase().trim();
        const jaTemSala = ocup.peritos.some((nm) => Parser.removerAcentos(nm).toLowerCase().trim() === pNorm);
        totalSalasTurno = ocup.totalSalas + (jaTemSala ? 0 : 1);
        if (!jaTemSala && totalSalasTurno > 4) {
          choqueSala = true;
        }
      }

      const pendencias = Parser ? [...Parser.calcularPendenciasPauta(p)] : [];
      if (!isVaraAutorizadaNaSessao(p.vara, sessaoUsuario, subId)) {
        pendencias.push("Vara não autorizada para seu perfil");
      }
      return { duplicata, choqueSala, totalSalasTurno, pendencias, varasSub };
    });
  }

  function renderizarCardsImportacaoWpp(avisosExtras = []) {
    const areaPrev = document.getElementById("areaPreviewImportWpp");
    const boxAlertas = document.getElementById("boxAlertasImportWpp");
    const listaEl = document.getElementById("listaCardsImportWpp");
    const lblResumo = document.getElementById("lblResumoImportWpp");
    const btnTodas = document.getElementById("btnSelecionarTodasImportWpp");

    if (!areaPrev || !listaEl) return;

    if (!pautasParaImportar || pautasParaImportar.length === 0) {
      areaPrev.style.display = "none";
      listaEl.innerHTML = "";
      return;
    }

    areaPrev.style.display = "block";
    const diagnosticos = verificarConflitosImportacao(pautasParaImportar);
    const totalSel = pautasParaImportar.filter((p) => p._meta?.selecionada !== false).length;

    if (lblResumo) {
      lblResumo.textContent = `${totalSel} de ${pautasParaImportar.length} pauta(s) marcada(s) para envio`;
    }
    if (btnTodas) {
      const todas = totalSel === pautasParaImportar.length;
      btnTodas.textContent = todas ? "☐ Desmarcar Todas" : "✓ Marcar Todas";
    }

    const todosAvisos = [...avisosExtras];
    const qtdDup = diagnosticos.filter((d) => d.duplicata).length;
    const qtdPend = diagnosticos.filter((d) => d.pendencias.length > 0).length;
    if (qtdDup > 0) todosAvisos.push(`⚠️ ${qtdDup} pauta(s) já existe(m) na planilha e atualizará(ão) o registro existente se mantida(s).`);
    if (qtdPend > 0) todosAvisos.push(`❗ ${qtdPend} pauta(s) com campos pendentes destacados em vermelho abaixo.`);

    if (boxAlertas) {
      if (todosAvisos.length > 0) {
        boxAlertas.style.display = "block";
        boxAlertas.innerHTML = todosAvisos.map((a) => `<div class="wpp-alert-pill">${escapeHtml(a)}</div>`).join("");
      } else {
        boxAlertas.style.display = "none";
        boxAlertas.innerHTML = "";
      }
    }

    const subId = sessaoUsuario?.subsecaoId || "sobral";
    const varasBase = resolverVarasAutorizadasSubsecao(sessaoUsuario, subId);

    listaEl.innerHTML = pautasParaImportar.map((p, idx) => {
      const diag = diagnosticos[idx];
      const selecionada = p._meta?.selecionada !== false;
      const ehFora = Parser ? Parser.ehLocalFora(p.local) : false;
      const varaNorm = normalizarNumeroVara(p.vara);
      const varaAutorizada = isVaraAutorizadaNaSessao(p.vara, sessaoUsuario, subId);
      const travarVaraSelect = varasBase.length === 1 && varaAutorizada;

      const cardClasses = [
        "wpp-pauta-edit-card",
        ehFora ? "is-fora" : "",
        diag.duplicata ? "is-duplicata" : "",
        diag.pendencias.length > 0 ? "has-pendencia" : "",
        !selecionada ? "is-unchecked" : ""
      ].filter(Boolean).join(" ");

      const badgesHtml = [
        ehFora ? '<span class="wpp-mini-badge fora">🏥 Fora do Prédio</span>' : '<span class="wpp-mini-badge ok">🏛️ Prédio</span>',
        diag.duplicata ? '<span class="wpp-mini-badge warn">⚠️ Já cadastrada</span>' : "",
        diag.choqueSala ? `<span class="wpp-mini-badge warn">🚨 ${diag.totalSalasTurno} salas no turno</span>` : "",
        diag.pendencias.length > 0 ? `<span class="wpp-mini-badge err">❗ ${escapeHtml(diag.pendencias.join(", "))}</span>` : ""
      ].filter(Boolean).join("");

      const optionsVaraLista = varasBase.map((v) =>
        `<option value="${escapeHtml(v)}" ${varaNorm === String(v) ? "selected" : ""}>${escapeHtml(v)}ª Vara Federal</option>`
      );
      if (!varaAutorizada && varaNorm) {
        optionsVaraLista.unshift(
          `<option value="${escapeHtml(varaNorm)}" selected>🔒 ${escapeHtml(varaNorm)}ª VF (Não autorizada)</option>`
        );
      }
      const optionsVaraHtml = optionsVaraLista.join("");

      const localTemNaLista = LOCAIS_PADRAO_OPTIONS.some((o) => o.value === p.local);
      const localOpts = localTemNaLista
        ? LOCAIS_PADRAO_OPTIONS
        : [{ value: p.local, label: p.local }, ...LOCAIS_PADRAO_OPTIONS];
      const optionsLocalHtml = localOpts.map((o) =>
        `<option value="${escapeHtml(o.value)}" ${p.local === o.value ? "selected" : ""}>${escapeHtml(o.label)}</option>`
      ).join("");

      const situacoesOpts = ["Não marcado", "Em marcação", "Marcado"];
      const optionsSituacaoHtml = situacoesOpts.map((s) =>
        `<option value="${escapeHtml(s)}" ${p.situacao === s ? "selected" : ""}>${escapeHtml(s)}</option>`
      ).join("");

      return `
        <div class="${cardClasses}" data-index="${idx}">
          <div class="wpp-card-top">
            <label class="wpp-card-check">
              <input type="checkbox" class="wpp-check-incluir" data-index="${idx}" ${selecionada ? "checked" : ""}>
              <span>Pauta #${idx + 1}</span>
            </label>
            <div class="wpp-card-badges">
              ${badgesHtml}
              <button type="button" class="wpp-btn-rm-card" data-action="remover" data-index="${idx}" title="Remover este card">✕</button>
            </div>
          </div>

          <div class="wpp-field">
            <label>Perito(a) Oficial *</label>
            <input type="text" list="datalistPeritosMobile" data-index="${idx}" data-field="peritoNome" value="${escapeHtml(p.peritoNome || "")}" placeholder="Nome completo do perito">
          </div>

          <div class="wpp-field">
            <label>Especialidade / Atuação</label>
            <input type="text" data-index="${idx}" data-field="especialidade" value="${escapeHtml(p.especialidade || "")}" placeholder="Ex: Clínica Geral / Ortopedia">
          </div>

          <div class="wpp-card-grid-2">
            <div class="wpp-field">
              <label>Data *</label>
              <input type="date" data-index="${idx}" data-field="data" value="${escapeHtml(p.data || "")}">
            </div>
            <div class="wpp-field">
              <label>Hora Início *</label>
              <input type="time" data-index="${idx}" data-field="horaInicio" value="${escapeHtml(p.horaInicio || "08:00")}">
            </div>
          </div>

          <div class="wpp-card-grid-3">
            <div class="wpp-field">
              <label>Vagas</label>
              <input type="number" min="1" max="200" data-index="${idx}" data-field="quantidade" value="${escapeHtml(p.quantidade || 20)}">
            </div>
            <div class="wpp-field">
              <label>Interv. (min)</label>
              <input type="number" min="1" max="120" data-index="${idx}" data-field="intervaloMin" value="${escapeHtml(p.intervaloMin || 10)}">
            </div>
            <div class="wpp-field">
              <label>Vara *</label>
              <select data-index="${idx}" data-field="vara" ${travarVaraSelect ? 'disabled title="Vara travada pelo Administrador Master"' : ""}>${optionsVaraHtml}</select>
            </div>
          </div>

          <div class="wpp-card-grid-2">
            <div class="wpp-field">
              <label>Local da Perícia *</label>
              <select data-index="${idx}" data-field="local">${optionsLocalHtml}</select>
            </div>
            <div class="wpp-field">
              <label>Situação</label>
              <select data-index="${idx}" data-field="situacao">${optionsSituacaoHtml}</select>
            </div>
          </div>

          <div class="wpp-endereco-box" style="display: ${ehFora ? "block" : "none"};">
            <div class="wpp-field" style="margin-bottom: 0;">
              <label>📍 Endereço da Perícia (Local Externo / Fora) *</label>
              <input type="text" data-index="${idx}" data-field="endereco" value="${escapeHtml(p.endereco || "")}" placeholder="Rua / Av. / Clínica / Consultório">
            </div>
          </div>

          <div class="wpp-field">
            <label>Observações</label>
            <input type="text" data-index="${idx}" data-field="observacoes" value="${escapeHtml(p.observacoes || "")}" placeholder="Opcional">
          </div>

          <div class="wpp-calc-strip" data-calc-strip="${idx}">
            <span>⏰ Término: <b data-calc-termino="${idx}">${escapeHtml(p.horaTermino || "--:--")}</b></span>
            <span>📅 Limite (8d úteis): <b data-calc-limite="${idx}">${escapeHtml(formatarDataBr(p.dataLimite) || "-")}</b></span>
            <span>⏳ Prazo: <b data-calc-prazo="${idx}">${p.prazoDias !== null && p.prazoDias !== undefined ? `${p.prazoDias}d` : "-"}</b></span>
          </div>

          ${p._meta?.trechoOrigem ? `<div class="wpp-origin-snippet" title="${escapeHtml(p._meta.trechoOrigem)}">💬 "${escapeHtml(p._meta.trechoOrigem)}"</div>` : ""}
        </div>
      `;
    }).join("");
  }

  function atualizarCalculosCardNaTela(idx) {
    const item = pautasParaImportar[idx];
    if (!item || !Parser) return;
    const canon = Parser.prepararPautaCanonica(item, bancoPeritosMobile);
    item.horaTermino = canon.horaTermino;
    item.dataLimite = canon.dataLimite;
    item.prazoDias = canon.prazoDias;

    const elTerm = document.querySelector(`[data-calc-termino="${idx}"]`);
    const elLim = document.querySelector(`[data-calc-limite="${idx}"]`);
    const elPrazo = document.querySelector(`[data-calc-prazo="${idx}"]`);
    if (elTerm) elTerm.textContent = item.horaTermino || "--:--";
    if (elLim) elLim.textContent = formatarDataBr(item.dataLimite) || "-";
    if (elPrazo) elPrazo.textContent = (item.prazoDias !== null && item.prazoDias !== undefined) ? `${item.prazoDias}d` : "-";
  }

  function onInputCardImportacaoWpp(e) {
    const target = e.target;
    if (!target || target.classList.contains("wpp-check-incluir")) return;
    const idx = parseInt(target.getAttribute("data-index"), 10);
    const field = target.getAttribute("data-field");
    if (isNaN(idx) || !field || !pautasParaImportar[idx]) return;

    const item = pautasParaImportar[idx];
    if (field === "quantidade" || field === "intervaloMin") {
      item[field] = parseInt(target.value, 10) || (field === "quantidade" ? 1 : 10);
    } else {
      item[field] = target.value;
    }

    if (field === "data" || field === "horaInicio" || field === "quantidade" || field === "intervaloMin") {
      atualizarCalculosCardNaTela(idx);
    }
  }

  function onChangeCardImportacaoWpp(e) {
    const target = e.target;
    if (!target) return;
    const idx = parseInt(target.getAttribute("data-index"), 10);
    if (isNaN(idx) || !pautasParaImportar[idx]) return;

    if (target.classList.contains("wpp-check-incluir")) {
      if (!pautasParaImportar[idx]._meta) pautasParaImportar[idx]._meta = {};
      pautasParaImportar[idx]._meta.selecionada = Boolean(target.checked);
      renderizarCardsImportacaoWpp();
      return;
    }

    const field = target.getAttribute("data-field");
    if (!field) return;

    const item = pautasParaImportar[idx];
    if (field === "quantidade" || field === "intervaloMin") {
      item[field] = parseInt(target.value, 10) || (field === "quantidade" ? 1 : 10);
    } else {
      item[field] = target.value;
    }

    // Autocomplete de regras/endereço quando alterar perito ou local
    if (field === "peritoNome" && Parser) {
      const match = Parser.encontrarPeritoNoTexto(item.peritoNome, bancoPeritosMobile);
      if (match.nome) {
        item.peritoNome = match.nome;
      }
      if (match.peritoObj) {
        const regras = Parser.obterRegrasVaraPerito(match.peritoObj, item.vara);
        if (!item.especialidade && regras.especialidade) item.especialidade = regras.especialidade;
        if (regras.atendeFora && !Parser.ehLocalFora(item.local)) {
          item.local = regras.localExternoPadrao || "Clínica Própria";
        }
        if (Parser.ehLocalFora(item.local) && !item.endereco && regras.endereco) {
          item.endereco = regras.endereco;
        }
      }
    } else if (field === "local" && Parser) {
      if (Parser.ehLocalFora(item.local) && !item.endereco) {
        const match = Parser.encontrarPeritoNoTexto(item.peritoNome, bancoPeritosMobile);
        const regras = Parser.obterRegrasVaraPerito(match.peritoObj, item.vara);
        if (regras.endereco) item.endereco = regras.endereco;
      } else if (!Parser.ehLocalFora(item.local)) {
        item.endereco = "";
      }
    }

    // Atualiza campos canônicos recalculados mantendo origem e meta
    if (Parser) {
      const metaOrig = item._meta;
      const canon = Parser.prepararPautaCanonica(item, bancoPeritosMobile);
      canon._meta = metaOrig;
      pautasParaImportar[idx] = canon;
    }

    renderizarCardsImportacaoWpp();
  }

  function onClickCardImportacaoWpp(e) {
    const btn = e.target.closest("[data-action='remover']");
    if (!btn) return;
    const idx = parseInt(btn.getAttribute("data-index"), 10);
    if (isNaN(idx)) return;
    pautasParaImportar.splice(idx, 1);
    renderizarCardsImportacaoWpp();
  }

  function obterChaveFilaOffline(subId) {
    return `maestro_mobile_fila_pendente_${subId}`;
  }

  function carregarFilaOffline(subId) {
    try {
      const raw = localStorage.getItem(obterChaveFilaOffline(subId));
      const parsed = raw ? JSON.parse(raw) : [];
      return Array.isArray(parsed) ? parsed : [];
    } catch (e) {
      return [];
    }
  }

  function salvarFilaOffline(subId, lista) {
    try {
      if (!lista || lista.length === 0) {
        localStorage.removeItem(obterChaveFilaOffline(subId));
      } else {
        localStorage.setItem(obterChaveFilaOffline(subId), JSON.stringify(lista));
      }
    } catch (e) {}
    atualizarBannerFilaOffline();
  }

  function atualizarBannerFilaOffline() {
    const banner = document.getElementById("bannerFilaPendenteMobile");
    const lbl = document.getElementById("lblQtdFilaOffline");
    if (!banner || !sessaoUsuario) return;
    const fila = carregarFilaOffline(sessaoUsuario.subsecaoId);
    if (fila.length > 0) {
      banner.style.display = "flex";
      if (lbl) lbl.textContent = `${fila.length} pauta(s) aguardando conexão com a nuvem`;
    } else {
      banner.style.display = "none";
    }
  }

  async function gravarEscalaNaNuvemComMerge(pautasNovasInput) {
    const subId = sessaoUsuario.subsecaoId;
    const pautasCanonic = (pautasNovasInput || []).map((p) => {
      const copia = Parser ? Parser.prepararPautaCanonica(p, bancoPeritosMobile) : { ...p };
      delete copia._meta;
      return copia;
    });

    let resultadoMergeFinal = null;
    let gravouNuvem = false;
    let gravouLocalExt = false;

    // 1. Gravação segura na Nuvem (Firestore READ -> MERGE -> Partial PATCH)
    const temProjetoNuvem = Boolean(
      sessaoUsuario.projectId &&
      sessaoUsuario.projectId.trim() &&
      !sessaoUsuario.projectId.includes("exemplo")
    );

    if (temProjetoNuvem) {
      if (typeof navigator !== "undefined" && navigator.onLine === false) {
        throw new Error("OFFLINE_DETECTADO");
      }

      let chaveNuvem = obterChaveNuvemSessao();
      if (!chaveNuvem) {
        const digitada = window.prompt("🔐 Informe a Chave / Senha AES-256 da Vara para cifrar e enviar as pautas com segurança:") || "";
        if (!digitada.trim()) {
          throw new Error("Chave AES-256 obrigatória para enviar dados à nuvem.");
        }
        chaveNuvem = digitada.trim();
        salvarChaveNuvemSessao(chaveNuvem, false);
      }

      const urlGet = `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(sessaoUsuario.projectId)}/databases/(default)/documents/subsecoes/${encodeURIComponent(subId)}`;
      const respGet = await fetch(urlGet, { method: "GET", cache: "no-cache" });

      let escalaNuvemAtual = [];
      let tombstonesNuvem = {};
      if (respGet.ok) {
        const doc = await respGet.json();
        const fields = doc.fields || {};

        if (fields.escalaTombstonesJson?.stringValue) {
          try {
            const decTomb = await decodificarOuDecifrarDadoNuvemMobile(
              fields.escalaTombstonesJson.stringValue,
              fields.ivTombstones?.stringValue || fields.ivEscala?.stringValue,
              fields.saltTombstones?.stringValue || fields.saltEscala?.stringValue,
              chaveNuvem
            );
            if (decTomb && typeof decTomb === "object" && !Array.isArray(decTomb)) {
              tombstonesNuvem = decTomb;
            }
          } catch (eTomb) {}
        }

        if (fields.escalaPautasJson?.stringValue) {
          let dec = null;
          try {
            dec = await decodificarOuDecifrarDadoNuvemMobile(
              fields.escalaPautasJson.stringValue,
              fields.ivEscala?.stringValue || fields.iv?.stringValue,
              fields.saltEscala?.stringValue || fields.salt?.stringValue,
              chaveNuvem
            );
          } catch (eDec) {
            throw new Error("⚠️ Chave AES-256 incorreta ou dados corrompidos na nuvem. Envio cancelado para proteger a escala existente.");
          }
          if (!Array.isArray(dec)) {
            throw new Error("⚠️ Não foi possível decifrar a escala existente na nuvem com esta chave AES-256. Confira a chave no Desktop e tente novamente.");
          }
          escalaNuvemAtual = dec;
        }
      } else if (respGet.status !== 404) {
        throw new Error(`Falha ao consultar a nuvem (HTTP ${respGet.status}).`);
      }

      const mesclado = mesclarListasEscala(escalaNuvemAtual, pautasCanonic, tombstonesNuvem);
      resultadoMergeFinal = mesclado;

      const encoderUtf8 = new TextEncoder();
      const escalaStr = JSON.stringify(mesclado.listaFinal);
      const bytesBruto = encoderUtf8.encode(escalaStr).length;
      const estimativaCifrado = Math.ceil(bytesBruto * 1.34);
      let opcoesCripto = estimativaCifrado >= 400000
        ? { comprimirGzip: true }
        : { autoGzipAcimaBytes: 131072 };

      let resEscala = await cifrarTextoAESMobile(escalaStr, chaveNuvem, opcoesCripto);
      const now = Date.now();

      const updateFields = [
        "subsecaoId",
        "encrypted",
        "escalaPautasJson",
        "ivEscala",
        "saltEscala",
        "timestamp",
        "atualizadoPor"
      ];
      const maskQuery = updateFields.map((f) => `updateMask.fieldPaths=${encodeURIComponent(f)}`).join("&");
      const urlPatch = `${urlGet}?${maskQuery}`;

      const montarBodyPatch = (encObj) => ({
        fields: {
          subsecaoId: { stringValue: subId },
          encrypted: { booleanValue: true },
          escalaPautasJson: { stringValue: encObj.data },
          ivEscala: { stringValue: encObj.iv },
          saltEscala: { stringValue: encObj.salt },
          timestamp: { integerValue: String(now) },
          atualizadoPor: { stringValue: `Maestro Mobile (${sessaoUsuario.usuarioCpf || "WhatsApp"})` }
        }
      });

      let payloadPatch = montarBodyPatch(resEscala);
      let payloadBytes = encoderUtf8.encode(JSON.stringify(payloadPatch)).length;
      if (payloadBytes >= 850000 && !opcoesCripto.comprimirGzip) {
        opcoesCripto = { comprimirGzip: true };
        resEscala = await cifrarTextoAESMobile(escalaStr, chaveNuvem, opcoesCripto);
        payloadPatch = montarBodyPatch(resEscala);
        payloadBytes = encoderUtf8.encode(JSON.stringify(payloadPatch)).length;
      }
      if (payloadBytes >= 980000) {
        throw new Error(`Tamanho do pacote (${Math.round(payloadBytes / 1024)} KB) excede o limite de 1 MB do Firestore. Exporte ou arquive meses antigos no Desktop.`);
      }

      const respPatch = await fetch(urlPatch, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payloadPatch)
      });

      if (!respPatch.ok) {
        throw new Error(`Falha ao gravar na nuvem (HTTP ${respPatch.status}).`);
      }
      gravouNuvem = true;
    }

    // 2. Se aberto como módulo interno da extensão Chrome, reflete imediatamente no chrome.storage.local
    if (ehAmbienteExtensaoChrome()) {
      try {
        const keyEscala = `escalaPautas_${subId}`;
        const st = await chrome.storage.local.get({ [keyEscala]: [] });
        const atualExt = Array.isArray(st[keyEscala]) ? st[keyEscala] : [];
        const baseParaMerge = resultadoMergeFinal ? resultadoMergeFinal.listaFinal : mesclarListasEscala(atualExt, pautasCanonic).listaFinal;
        await chrome.storage.local.set({ [keyEscala]: baseParaMerge });
        if (!resultadoMergeFinal) {
          resultadoMergeFinal = mesclarListasEscala(atualExt, pautasCanonic);
        }
        gravouLocalExt = true;
      } catch (eExt) {}
    }

    return {
      gravouNuvem,
      gravouLocalExt,
      adicionadas: resultadoMergeFinal ? resultadoMergeFinal.adicionadas : pautasCanonic.length,
      atualizadas: resultadoMergeFinal ? resultadoMergeFinal.atualizadas : 0,
      listaFinal: resultadoMergeFinal ? resultadoMergeFinal.listaFinal : pautasCanonic
    };
  }

  function mostrarMensagemImportWpp(texto, tipo = "success") {
    const msgBox = document.getElementById("msgResultadoImportWpp");
    if (!msgBox) return;
    msgBox.textContent = texto;
    msgBox.className = tipo === "success" ? "alert-box alert-success" : "alert-box alert-danger";
    msgBox.style.display = "block";
  }

  async function enviarPautasImportadasParaPlanilha() {
    if (!sessaoUsuario) return;
    if (!podeEnviarPautasNaSessao()) {
      alert("🔒 Seu usuário possui perfil Somente Leitura e não pode enviar pautas à planilha.");
      return;
    }

    const selecionadas = pautasParaImportar.filter((p) => p._meta?.selecionada !== false);
    if (selecionadas.length === 0) {
      alert("⚠️ Selecione ao menos 1 pauta para enviar para a planilha.");
      return;
    }

    const foraEscopo = selecionadas.filter((p) => !isVaraAutorizadaNaSessao(p.vara));
    if (foraEscopo.length > 0) {
      alert(
        `🔒 Envio bloqueado por restrição de Vara:\n\n` +
        `${foraEscopo.length} pauta(s) selecionada(s) aponta(m) para Vara(s) fora do seu escopo autorizado (${obterLabelEscopoVaras()}).\n\n` +
        `Ajuste a Vara para sua unidade ou desmarque o(s) card(s) antes de enviar.`
      );
      return;
    }

    // Validação obrigatória dos campos
    for (let i = 0; i < pautasParaImportar.length; i++) {
      const p = pautasParaImportar[i];
      if (p._meta?.selecionada === false) continue;
      const pend = Parser ? Parser.calcularPendenciasPauta(p) : [];
      if (pend.length > 0) {
        alert(`⚠️ Complete os campos obrigatórios da Pauta #${i + 1}:\n• ${pend.join("\n• ")}`);
        const cardEl = document.querySelector(`.wpp-pauta-edit-card[data-index="${i}"]`);
        if (cardEl) cardEl.scrollIntoView({ behavior: "smooth", block: "center" });
        return;
      }
    }

    const diagnosticos = verificarConflitosImportacao(pautasParaImportar);
    const comChoque = diagnosticos.filter((d, i) => pautasParaImportar[i]._meta?.selecionada !== false && d.choqueSala);
    if (comChoque.length > 0) {
      const conf = confirm(
        `🚨 Atenção: ${comChoque.length} pauta(s) marcada(s) no prédio ultrapassa(m) o limite padrão de 4 salas físicas no mesmo turno.\n\nDeseja enviar mesmo assim?`
      );
      if (!conf) return;
    }

    const btnEnviar = document.getElementById("btnEnviarPautasNuvemWpp");
    if (btnEnviar) {
      btnEnviar.disabled = true;
      btnEnviar.innerHTML = "<span>⏳ Cifrando e enviando para a planilha...</span>";
    }

    try {
      const res = await gravarEscalaNaNuvemComMerge(selecionadas);

      // Atualiza estado em memória do app mobile
      todasPautas = aplicarFiltroRestritoSubsecao(converterPautasFirestore(res.listaFinal), sessaoUsuario.subsecaoId);
      salvarCacheLocal(sessaoUsuario.subsecaoId, todasPautas);
      atualizarInterfaceCompleta();

      // Mantém apenas eventuais cards não selecionados na prévia
      pautasParaImportar = pautasParaImportar.filter((p) => p._meta?.selecionada === false);
      renderizarCardsImportacaoWpp();
      if (pautasParaImportar.length === 0) {
        const txtArea = document.getElementById("txtConversaWhatsApp");
        if (txtArea) txtArea.value = "";
      }

      const detalheDestino = res.gravouNuvem
        ? "Sincronizadas na nuvem (AES-256) para todos os computadores da Vara."
        : "Gravadas localmente na extensão.";

      mostrarMensagemImportWpp(
        `✅ ${selecionadas.length} pauta(s) enviada(s) (${res.adicionadas} nova(s), ${res.atualizadas} atualizada(s))! ${detalheDestino}`,
        "success"
      );
      alert(
        `✅ Pauta(s) enviada(s) com sucesso para a planilha Escala & Calendário!\n\n` +
        `• Novas: ${res.adicionadas}\n` +
        `• Atualizadas: ${res.atualizadas}\n\n` +
        `${detalheDestino}`
      );
    } catch (err) {
      const msg = String(err?.message || err || "");
      if (msg === "OFFLINE_DETECTADO" || msg.includes("Failed to fetch") || msg.includes("NetworkError")) {
        const filaAtual = carregarFilaOffline(sessaoUsuario.subsecaoId);
        const combinada = mesclarListasEscala(filaAtual, selecionadas).listaFinal;
        salvarFilaOffline(sessaoUsuario.subsecaoId, combinada);
        mostrarMensagemImportWpp(
          `⏳ Sem conexão com a internet no momento. ${selecionadas.length} pauta(s) foi(ram) salva(s) na fila offline para reenvio assim que a rede voltar.`,
          "error"
        );
      } else {
        mostrarMensagemImportWpp("❌ Erro ao enviar: " + msg, "error");
        alert("❌ Não foi possível enviar as pautas:\n\n" + msg);
      }
    } finally {
      if (btnEnviar) {
        btnEnviar.disabled = false;
        btnEnviar.innerHTML = "<span>☁️ Enviar para a Planilha da Extensão</span>";
      }
    }
  }

  async function reenviarFilaOffline() {
    if (!sessaoUsuario) return;
    if (!podeEnviarPautasNaSessao()) {
      alert("🔒 Seu usuário possui perfil Somente Leitura e não pode enviar pautas da fila.");
      return;
    }
    const subId = sessaoUsuario.subsecaoId;
    const fila = carregarFilaOffline(subId).filter((p) => isVaraAutorizadaNaSessao(p.vara, sessaoUsuario, subId));
    if (fila.length === 0) {
      salvarFilaOffline(subId, []);
      atualizarBannerFilaOffline();
      return;
    }

    const btn = document.getElementById("btnReenviarFilaOffline");
    if (btn) {
      btn.disabled = true;
      btn.textContent = "⏳...";
    }

    try {
      const res = await gravarEscalaNaNuvemComMerge(fila);
      salvarFilaOffline(subId, []);
      todasPautas = aplicarFiltroRestritoSubsecao(converterPautasFirestore(res.listaFinal), subId);
      salvarCacheLocal(subId, todasPautas);
      atualizarInterfaceCompleta();
      alert(`✅ Fila offline sincronizada! ${fila.length} pauta(s) enviada(s) para a planilha.`);
    } catch (err) {
      alert("⚠️ Ainda não foi possível conectar com a nuvem: " + err.message);
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = "🔄 Reenviar";
      }
    }
  }

  // =========================================================================
  // 8. ATUALIZAÇÃO DA INTERFACE & KPIS (MARCADAS E PENDENTES)
  // =========================================================================
  function atualizarInterfaceCompleta() {
    atualizarLabelPeriodo();
    sincronizarMesRelatorioPadrao();
    atualizarKpisDoMes();
    window.filtrarPautas();
    renderizarAbaPorDia();
    atualizarResumoFiltroRelatorio();
  }

  function atualizarLabelPeriodo() {
    document.getElementById("lblMesAtual").textContent = MESES_NOMES[mesAtivo];
    document.getElementById("lblAnoAtual").textContent = anoAtivo;
  }

  function sincronizarMesRelatorioPadrao() {
    const inp = document.getElementById("relFiltroMesInput");
    if (!inp) return;
    const mesIso = `${anoAtivo}-${String(mesAtivo + 1).padStart(2, "0")}`;
    const valorAnterior = inp.value;

    const mesesAbrev = ["Jan", "Fev", "Mar", "Abr", "Mai", "Jun", "Jul", "Ago", "Set", "Out", "Nov", "Dez"];
    const mesesSet = new Set([mesIso]);

    (todasPautas || []).forEach((p) => {
      const m = String(p?.data || "").match(/^(\d{4}-\d{2})-/);
      if (m) mesesSet.add(m[1]);
    });

    const baseHoje = new Date();
    for (let delta = -3; delta <= 12; delta++) {
      const d = new Date(baseHoje.getFullYear(), baseHoje.getMonth() + delta, 1);
      mesesSet.add(`${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`);
    }

    const ordenados = Array.from(mesesSet).sort();
    inp.innerHTML = ordenados.map((ym) => {
      const [anoStr, mesStr] = ym.split("-");
      const idx = (parseInt(mesStr, 10) || 1) - 1;
      const label = `${mesesAbrev[idx] || mesStr}/${anoStr}`;
      return `<option value="${escapeHtml(ym)}">${escapeHtml(label)}</option>`;
    }).join("");

    if (inp.dataset.manual === "true" && valorAnterior && mesesSet.has(valorAnterior)) {
      inp.value = valorAnterior;
    } else {
      inp.value = mesIso;
    }
  }


  window.alterarMes = function (delta) {
    mesAtivo += delta;
    if (mesAtivo > 11) {
      mesAtivo = 0;
      anoAtivo++;
    } else if (mesAtivo < 0) {
      mesAtivo = 11;
      anoAtivo--;
    }
    const inp = document.getElementById("relFiltroMesInput");
    if (inp) inp.dataset.manual = "false";
    atualizarInterfaceCompleta();
  };

  function obterPautasDoMesAtivo(varaFiltro = "") {
    const mesIso = `${anoAtivo}-${String(mesAtivo + 1).padStart(2, "0")}`;
    const vNorm = varaFiltro ? normalizarNumeroVara(varaFiltro) : "";
    return todasPautas.filter((p) => {
      if (!p.data || !p.data.startsWith(mesIso)) return false;
      if (vNorm && normalizarNumeroVara(p.vara) !== vNorm) return false;
      return true;
    });
  }

  function atualizarKpisDoMes() {
    const selVaraDash = document.getElementById("filtroVaraDashboard");
    const varaAtivaDash = selVaraDash ? selVaraDash.value : filtroVaraDashboard;
    filtroVaraDashboard = varaAtivaDash || "";
    const pautasMes = obterPautasDoMesAtivo(varaAtivaDash);

    let totalVagas = 0;
    let marcadas = 0;
    let pendentes = 0;
    let catMedica = 0;
    let catSocial = 0;
    let catOutras = 0;
    const varasMap = {};

    pautasMes.forEach((p) => {
      const vagas = Number(p.vagas !== undefined ? p.vagas : p.quantidade) || 1;
      totalVagas += vagas;

      if (p.situacao === "Marcado") marcadas += vagas;
      else if (ehSituacaoPendente(p.situacao)) pendentes += vagas;

      if (p.categoria === "social") catSocial += vagas;
      else if (p.categoria === "outras") catOutras += vagas;
      else catMedica += vagas;

      const vNum = normalizarNumeroVara(p.vara);
      const vLabel = vNum ? `${vNum}ª Vara` : "Vara Única";
      if (!varasMap[vLabel]) varasMap[vLabel] = { varaNum: vNum, marcadas: 0, pendentes: 0, total: 0 };
      varasMap[vLabel].total += vagas;
      if (p.situacao === "Marcado") varasMap[vLabel].marcadas += vagas;
      else if (ehSituacaoPendente(p.situacao)) varasMap[vLabel].pendentes += vagas;
    });

    const taxa = totalVagas > 0 ? Math.round((marcadas / totalVagas) * 100) : 0;

    document.getElementById("kpiTotalVagas").textContent = totalVagas;
    const varaLabelHint = varaAtivaDash ? ` (${normalizarNumeroVara(varaAtivaDash)}ª VF)` : "";
    document.getElementById("kpiTotalPautas").textContent = `${pautasMes.length} pautas em ${MESES_NOMES[mesAtivo]}${varaLabelHint}`;
    document.getElementById("kpiMarcadas").textContent = marcadas;
    document.getElementById("kpiPendentes").textContent = pendentes;
    document.getElementById("kpiTaxaOcupacao").textContent = `${taxa}%`;

    const pctMarcadas = totalVagas > 0 ? (marcadas / totalVagas) * 100 : 0;
    const pctPendentes = totalVagas > 0 ? (pendentes / totalVagas) * 100 : 0;
    document.getElementById("barMarcadas").style.width = `${pctMarcadas}%`;
    document.getElementById("barPendentes").style.width = `${pctPendentes}%`;

    document.getElementById("countCatMedica").textContent = `${catMedica} vagas`;
    document.getElementById("countCatSocial").textContent = `${catSocial} vagas`;
    document.getElementById("countCatOutras").textContent = `${catOutras} vagas`;

    // Alertas de prazo crítico (<= 5 dias úteis ou vencido) nas pautas pendentes da Vara selecionada
    const cardAlerta = document.getElementById("cardAlertasPrazoDashboard");
    const lblAlerta = document.getElementById("lblResumoAlertasPrazo");
    if (cardAlerta && lblAlerta) {
      const vNorm = varaAtivaDash ? normalizarNumeroVara(varaAtivaDash) : "";
      const criticas = (todasPautas || []).filter((p) => {
        if (vNorm && normalizarNumeroVara(p.vara) !== vNorm) return false;
        const info = resolverPrazoInfoPauta(p);
        return Boolean(info && info.prazoDias <= 5);
      });
      if (criticas.length > 0) {
        const vencidas = criticas.filter((p) => resolverPrazoInfoPauta(p).prazoDias < 0).length;
        lblAlerta.textContent = vencidas > 0
          ? `${criticas.length} pauta(s) pendente(s) com prazo crítico (${vencidas} já vencida(s))`
          : `${criticas.length} pauta(s) pendente(s) com prazo limite ≤ 5 dias`;
        cardAlerta.style.display = "flex";
      } else {
        cardAlerta.style.display = "none";
      }
    }

    renderizarVarasKpi(varasMap);
  }

  function renderizarVarasKpi(varasMap) {
    const container = document.getElementById("listaVarasKpi");
    container.innerHTML = "";

    const keys = Object.keys(varasMap);
    document.getElementById("lblQtdVaras").textContent = `${keys.length} Vara(s) Ativa(s)`;

    if (keys.length === 0) {
      container.innerHTML = '<div class="text-sm text-muted" style="padding: 10px; text-align: center;">Nenhuma perícia agendada para este mês neste filtro.</div>';
      return;
    }

    keys.sort().forEach((vara) => {
      const info = varasMap[vara];
      const div = document.createElement("div");
      div.className = "vara-row is-clickable";
      div.setAttribute("data-vara-drill", info.varaNum || "");
      div.title = "Toque para filtrar esta Vara na Lista";
      div.innerHTML = `
        <span class="vara-title">${escapeHtml(vara)} ➔</span>
        <div class="vara-counts">
          <span class="badge-count badge-count-green" title="Marcadas">${escapeHtml(info.marcadas)} marcadas</span>
          <span class="badge-count badge-count-yellow" title="Pendentes">${escapeHtml(info.pendentes)} pendentes</span>
          <strong title="Total de Vagas">(${escapeHtml(info.total)})</strong>
        </div>
      `;
      container.appendChild(div);
    });
  }

  function abrirListaComFiltros(opts = {}) {
    if (opts.texto !== undefined) {
      const inp = document.getElementById("filtroTexto");
      if (inp) inp.value = String(opts.texto || "");
    }
    if (opts.vara !== undefined) {
      const selVara = document.getElementById("filtroVara");
      if (selVara && !selVara.disabled) selVara.value = opts.vara ? normalizarNumeroVara(opts.vara) : "";
    }
    if (opts.periodo !== undefined) {
      const selPer = document.getElementById("filtroPeriodoPautas");
      if (selPer) selPer.value = opts.periodo || "todos";
    }
    if (opts.local !== undefined) {
      const selLoc = document.getElementById("filtroLocalPautas");
      if (selLoc) selLoc.value = opts.local || "";
    }
    if (opts.categoria !== undefined) {
      const selCat = document.getElementById("filtroCategoria");
      if (selCat) selCat.value = opts.categoria || "";
    }
    if (opts.ordenacao !== undefined) {
      const selOrd = document.getElementById("filtroOrdenacaoPautas");
      if (selOrd) selOrd.value = opts.ordenacao || "data_asc";
    }

    const sit = opts.situacao || "todos";
    const pillEl = document.querySelector(`#tabPautas .filter-pills .pill[data-filtro='${sit}']`)
      || document.querySelector("#tabPautas .filter-pills .pill[data-filtro='todos']");
    window.setFiltroSituacao(sit, pillEl);
    window.trocarAba("tabPautas");
  }

  function renderizarAcoesCardPautaHtml(p) {
    if (!p || !podeEnviarPautasNaSessao()) return "";
    if (!isVaraAutorizadaNaSessao(p.vara, sessaoUsuario, sessaoUsuario?.subsecaoId)) return "";

    const clsSit = classificarSituacaoFiltro(p.situacao);
    let labelCiclo = "🟡 ➔ Em marcação";
    if (clsSit === "em_marcacao") labelCiclo = "🟢 ➔ Marcar";
    else if (clsSit === "marcado") labelCiclo = "⚪ ➔ Não marcado";

    const idAttr = escapeHtml(p.id || "");
    const keyAttr = escapeHtml(gerarChaveUnicaPauta(p));

    return `
      <div class="pauta-card-actions">
        <button type="button" class="btn-card-action" data-pauta-action="ciclar-situacao" data-pauta-id="${idAttr}" data-pauta-key="${keyAttr}">${labelCiclo}</button>
        <button type="button" class="btn-card-action" data-pauta-action="editar" data-pauta-id="${idAttr}" data-pauta-key="${keyAttr}">✏️ Editar</button>
        <button type="button" class="btn-card-action btn-card-danger" data-pauta-action="excluir" data-pauta-id="${idAttr}" data-pauta-key="${keyAttr}" title="Excluir pauta">🗑️</button>
      </div>
    `;
  }

  // =========================================================================
  // 8B. VISUALIZAÇÃO DIÁRIA ("📅 POR DIA" — ESCALA DE PERITOS + PAUTA PJE)
  // =========================================================================
  const DIAS_SEMANA_PT = [
    "Domingo", "Segunda-feira", "Terça-feira", "Quarta-feira",
    "Quinta-feira", "Sexta-feira", "Sábado"
  ];

  function somarDiasIso(isoStr, delta) {
    const parts = String(isoStr || "").split("-");
    if (parts.length !== 3) return obterHojeIsoLocal();
    const d = new Date(Number(parts[0]), Number(parts[1]) - 1, Number(parts[2]) + Number(delta || 0));
    const y = d.getFullYear();
    const m = String(d.getMonth() + 1).padStart(2, "0");
    const day = String(d.getDate()).padStart(2, "0");
    return `${y}-${m}-${day}`;
  }

  function formatarCabecalhoDia(isoStr) {
    const hojeIso = obterHojeIsoLocal();
    const parts = String(isoStr || "").split("-");
    if (parts.length !== 3) {
      return { diaSemana: "Data", dataBr: "-", ehHoje: false };
    }
    const d = new Date(Number(parts[0]), Number(parts[1]) - 1, Number(parts[2]));
    const diaSemana = DIAS_SEMANA_PT[d.getDay()] || "";
    const dataBr = `${parts[2]}/${parts[1]}/${parts[0]}`;
    const ehHoje = isoStr === hojeIso;
    const prefixo = ehHoje ? "Hoje • " : (isoStr === somarDiasIso(hojeIso, 1) ? "Amanhã • " : "");
    return {
      diaSemana: `${prefixo}${diaSemana}`,
      dataBr,
      ehHoje
    };
  }

  function selecionarDataPorDia(novaDataIso) {
    if (!novaDataIso || !/^\d{4}-\d{2}-\d{2}$/.test(novaDataIso)) return;
    dataSelecionadaPorDia = novaDataIso;
    const parts = novaDataIso.split("-");
    calDiaAno = Number(parts[0]);
    calDiaMes = Number(parts[1]) - 1;
    renderizarAbaPorDia();
  }

  function alterarDiaPorDia(delta) {
    selecionarDataPorDia(somarDiasIso(dataSelecionadaPorDia, delta));
  }

  function alterarMesCalendarioDia(delta) {
    calDiaMes += delta;
    if (calDiaMes > 11) {
      calDiaMes = 0;
      calDiaAno++;
    } else if (calDiaMes < 0) {
      calDiaMes = 11;
      calDiaAno--;
    }
    renderizarCalendarioPorDia();
  }

  function alternarCalendarioPorDia() {
    calendarioDiaVisivel = !calendarioDiaVisivel;
    const box = document.getElementById("boxCalendarioPorDia");
    const btn = document.getElementById("btnToggleCalendarioDia");
    if (box) box.style.display = calendarioDiaVisivel ? "block" : "none";
    if (btn) btn.textContent = calendarioDiaVisivel ? "🗓️ Ocultar" : "🗓️ Cal.";
  }

  function pararAutoRefreshDia() {
    if (autoRefreshDiaTimer) {
      clearInterval(autoRefreshDiaTimer);
      autoRefreshDiaTimer = null;
    }
    autoRefreshDiaAtivo = false;
    const btn = document.getElementById("btnAutoRefreshDia");
    if (btn) btn.textContent = "🔄 Auto: OFF";
  }

  function alternarAutoRefreshDia() {
    if (autoRefreshDiaAtivo) {
      pararAutoRefreshDia();
      mostrarToast("Atualização automática desativada.", "info", 1800);
      return;
    }
    autoRefreshDiaAtivo = true;
    const btn = document.getElementById("btnAutoRefreshDia");
    if (btn) btn.textContent = "🟢 Auto: 60s";
    autoRefreshDiaTimer = setInterval(() => {
      if (!sessaoUsuario || document.hidden) return;
      const tabDiaAtiva = document.getElementById("tabPorDia")?.classList.contains("active");
      if (!tabDiaAtiva) return;
      if (typeof navigator !== "undefined" && navigator.onLine === false) return;
      window.sincronizarPautas(obterChaveNuvemSessao());
    }, 60000);
    mostrarToast("Auto-atualização ativada (a cada 60s na aba Por Dia).", "success", 2400);
  }

  function irParaProximoDiaComAtividade() {
    const varaFiltro = document.getElementById("filtroVaraPorDia")?.value || "";
    const vNorm = varaFiltro ? normalizarNumeroVara(varaFiltro) : "";
    const datasSet = new Set();
    (todasPautas || []).forEach((p) => {
      if (!p.data) return;
      if (vNorm && normalizarNumeroVara(p.vara) !== vNorm) return;
      datasSet.add(p.data);
    });
    (todasPericiasPje || []).forEach((p) => {
      if (!p.dataPericiaIso) return;
      if (vNorm && (p.varaNum || extrairVaraNumeroPericiaMobile(p.vara)) !== vNorm) return;
      datasSet.add(p.dataPericiaIso);
    });

    const ordenadas = Array.from(datasSet).sort();
    if (ordenadas.length === 0) {
      mostrarToast("Nenhuma pauta ou perícia encontrada para a subseção/vara selecionada.", "warn");
      return;
    }
    const proxima = ordenadas.find((d) => d > dataSelecionadaPorDia) || ordenadas.find((d) => d >= dataSelecionadaPorDia) || ordenadas[0];
    selecionarDataPorDia(proxima);
  }

  function construirMapaAtividadeMensal(ano, mes, varaFiltro = "") {
    const prefix = `${ano}-${String(mes + 1).padStart(2, "0")}-`;
    const mapa = {};
    const vNormFiltro = varaFiltro ? normalizarNumeroVara(varaFiltro) : "";

    (todasPautas || []).forEach((p) => {
      if (!p.data || !p.data.startsWith(prefix)) return;
      if (vNormFiltro && normalizarNumeroVara(p.vara) !== vNormFiltro) return;
      if (!mapa[p.data]) mapa[p.data] = { escala: 0, pauta: 0 };
      mapa[p.data].escala++;
    });

    (todasPericiasPje || []).forEach((p) => {
      if (!p.dataPericiaIso || !p.dataPericiaIso.startsWith(prefix)) return;
      if (vNormFiltro && (p.varaNum || extrairVaraNumeroPericiaMobile(p.vara)) !== vNormFiltro) return;
      if (!mapa[p.dataPericiaIso]) mapa[p.dataPericiaIso] = { escala: 0, pauta: 0 };
      mapa[p.dataPericiaIso].pauta++;
    });

    return mapa;
  }

  function renderizarCalendarioPorDia() {
    const lblMes = document.getElementById("lblCalDiaMesAno");
    const grid = document.getElementById("gridCalendarioPorDia");
    if (!grid || !lblMes) return;

    lblMes.textContent = `${MESES_NOMES[calDiaMes]} ${calDiaAno}`;
    const varaFiltro = document.getElementById("filtroVaraPorDia")?.value || "";
    const mapaAtiv = construirMapaAtividadeMensal(calDiaAno, calDiaMes, varaFiltro);

    const primeiroDiaSemana = new Date(calDiaAno, calDiaMes, 1).getDay();
    const totalDiasMes = new Date(calDiaAno, calDiaMes + 1, 0).getDate();
    const hojeIso = obterHojeIsoLocal();
    const cells = [];

    for (let i = 0; i < primeiroDiaSemana; i++) {
      cells.push('<div class="dia-cal-cell is-empty" aria-hidden="true"></div>');
    }

    for (let dia = 1; dia <= totalDiasMes; dia++) {
      const iso = `${calDiaAno}-${String(calDiaMes + 1).padStart(2, "0")}-${String(dia).padStart(2, "0")}`;
      const dow = new Date(calDiaAno, calDiaMes, dia).getDay();
      const ativ = mapaAtiv[iso];
      const classes = ["dia-cal-cell"];
      if (dow === 0 || dow === 6) classes.push("is-weekend");
      if (iso === hojeIso) classes.push("is-today");
      if (iso === dataSelecionadaPorDia) classes.push("is-selected");

      const dots = [];
      if (ativ && ativ.escala > 0) dots.push('<span class="dia-dot dia-dot-escala"></span>');
      if (ativ && ativ.pauta > 0) dots.push('<span class="dia-dot dia-dot-pauta"></span>');

      const tooltip = ativ
        ? `${formatarDataBr(iso)}: ${ativ.escala} escala(s), ${ativ.pauta} perícia(s) PJe`
        : formatarDataBr(iso);

      cells.push(
        `<button type="button" class="${classes.join(" ")}" data-date="${escapeHtml(iso)}" title="${escapeHtml(tooltip)}">` +
          `<span>${dia}</span>` +
          `<span class="dia-cal-dots">${dots.join("")}</span>` +
        `</button>`
      );
    }

    grid.innerHTML = cells.join("");
  }

  function obterBadgeStatusAtendimentoMobile(p) {
    const st = String(p?.statusAtendimento || "").toUpperCase();
    if (st === "CONCLUIDO") return { label: "✅ Concluído", cls: "st-concluido" };
    if (st === "EM_ATENDIMENTO") return { label: "🩺 Em Atendimento", cls: "st-atendimento" };
    if (st === "CHAMADO") return { label: "📢 Chamado", cls: "st-chamado" };
    if (st === "AUSENTE_CHAMADO") return { label: "❌ Ausente", cls: "st-ausente" };
    if (st === "PRESENTE" || p?.presencaConfirmada) return { label: "🟢 Presente", cls: "st-presente" };
    return { label: "⏳ Aguardando", cls: "st-aguardando" };
  }

  function obterItensFiltradosPorDia() {
    const txtBusca = removerAcentosLowerMobile(document.getElementById("filtroTextoPorDia")?.value || "");
    const varaFiltro = document.getElementById("filtroVaraPorDia")?.value || "";
    const vNormFiltro = varaFiltro ? normalizarNumeroVara(varaFiltro) : "";
    const sitFiltro = document.getElementById("filtroSituacaoPorDia")?.value || "todos";
    const statusPjeFiltro = document.getElementById("filtroStatusPjePorDia")?.value || "todos";

    const escalaDoDia = (todasPautas || []).filter((p) => {
      if (p.data !== dataSelecionadaPorDia) return false;
      if (vNormFiltro && normalizarNumeroVara(p.vara) !== vNormFiltro) return false;
      if (!correspondeFiltroSituacao(p, sitFiltro)) return false;
      if (txtBusca) {
        const hay = removerAcentosLowerMobile(`${p.peritoNome} ${p.especialidade} ${p.vara} ${p.local} ${p.endereco || ""} ${p.observacoes || ""}`);
        if (!hay.includes(txtBusca)) return false;
      }
      return true;
    }).sort((a, b) => (a.horaInicio || "08:00").localeCompare(b.horaInicio || "08:00"));

    const pautaDoDia = (todasPericiasPje || []).filter((p) => {
      if (p.dataPericiaIso !== dataSelecionadaPorDia) return false;
      if (vNormFiltro && (p.varaNum || extrairVaraNumeroPericiaMobile(p.vara)) !== vNormFiltro) return false;
      if (statusPjeFiltro !== "todos") {
        const st = String(p.statusAtendimento || "AGUARDANDO_CHEGADA").toUpperCase();
        if (statusPjeFiltro === "PRESENTE") {
          if (st !== "PRESENTE" && !(p.presencaConfirmada && st === "AGUARDANDO_CHEGADA")) return false;
        } else if (st !== statusPjeFiltro) {
          return false;
        }
      }
      if (txtBusca) {
        const hay = removerAcentosLowerMobile(`${p.perito} ${p.periciado} ${p.processo} ${p.especialidade} ${p.vara} ${p.sala || ""}`);
        if (!hay.includes(txtBusca)) return false;
      }
      return true;
    }).sort((a, b) => {
      const cmpHora = (a.horaPericia || "99:99").localeCompare(b.horaPericia || "99:99");
      if (cmpHora !== 0) return cmpHora;
      return (a.perito || "").localeCompare(b.perito || "", "pt-BR");
    });

    return { escalaDoDia, pautaDoDia, txtBusca, varaFiltro };
  }

  function compartilharResumoDiaWhatsApp() {
    if (!sessaoUsuario) return;
    const cab = formatarCabecalhoDia(dataSelecionadaPorDia);
    const { escalaDoDia, pautaDoDia, varaFiltro } = obterItensFiltradosPorDia();
    if (escalaDoDia.length === 0 && pautaDoDia.length === 0) {
      mostrarToast("Nenhuma escala ou perícia para compartilhar neste dia.", "warn");
      return;
    }

    const subInfo = SUBSECOES_MAP[sessaoUsuario.subsecaoId] || { nome: sessaoUsuario.subsecaoNome };
    const varaLabel = varaFiltro ? ` (${normalizarNumeroVara(varaFiltro)}ª VF)` : "";

    let txt = `⚖️ *MAESTRO PJE - PAUTA DO DIA*\n`;
    txt += `📅 *Data:* ${cab.dataBr} (${cab.diaSemana.replace(/^(Hoje|Amanhã)\s*•\s*/, "")})\n`;
    txt += `📍 *Subseção:* ${subInfo.nome}${varaLabel}\n\n`;

    if (escalaDoDia.length > 0) {
      txt += `🗓️ *ESCALA DE PERITOS (${escalaDoDia.length} bloco(s)):*\n`;
      escalaDoDia.forEach((p) => {
        const vagas = p.vagas !== undefined ? p.vagas : p.quantidade;
        const hora = p.horaInicio || p.hora || "08:00";
        const loc = p.endereco ? `${p.local} (${p.endereco})` : (p.local || "JF");
        txt += `• *${hora}* — ${p.peritoNome} | ${p.vara}ª VF | ${vagas} vagas | _${p.situacao}_ | ${loc}\n`;
      });
      txt += "\n";
    }

    if (pautaDoDia.length > 0) {
      const porPerito = {};
      pautaDoDia.forEach((p) => {
        const k = p.perito || "Perito";
        porPerito[k] = (porPerito[k] || 0) + 1;
      });
      txt += `📋 *PAUTA PJE (${pautaDoDia.length} perícia(s)):*\n`;
      Object.keys(porPerito).sort().forEach((per) => {
        txt += `• ${per}: ${porPerito[per]} periciando(s)\n`;
      });
    }

    if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
      navigator.clipboard.writeText(txt).then(() => {
        mostrarToast("Resumo do dia copiado! Abrindo opções de envio...", "success", 2400);
      }).catch(() => {});
    }
    if (confirm("Resumo do dia copiado para a área de transferência.\n\nDeseja abrir no WhatsApp agora?")) {
      window.open(`https://api.whatsapp.com/send?text=${encodeURIComponent(txt)}`, "_blank");
    }
  }

  function renderizarAbaPorDia() {
    if (!sessaoUsuario) return;

    const cab = formatarCabecalhoDia(dataSelecionadaPorDia);
    const elTitulo = document.getElementById("lblDiaSelecionadoTitulo");
    const elSub = document.getElementById("lblDiaSelecionadoSubtitulo");
    const elInput = document.getElementById("inputDataPorDia");
    if (elTitulo) elTitulo.textContent = cab.diaSemana;
    if (elSub) elSub.textContent = cab.dataBr;
    if (elInput && elInput.value !== dataSelecionadaPorDia) elInput.value = dataSelecionadaPorDia;

    renderizarCalendarioPorDia();

    const { escalaDoDia, pautaDoDia, txtBusca } = obterItensFiltradosPorDia();
    const btnLimpar = document.getElementById("btnLimparBuscaPorDia");
    if (btnLimpar) btnLimpar.style.display = txtBusca ? "block" : "none";

    // Faixa de ocupação de salas físicas no prédio (Manhã e Tarde)
    const salasStrip = document.getElementById("diaSalasStrip");
    if (salasStrip) {
      if (Parser && typeof Parser.obterOcupacaoSalasTurno === "function") {
        const ocupManha = Parser.obterOcupacaoSalasTurno(dataSelecionadaPorDia, "manha", todasPautas);
        const ocupTarde = Parser.obterOcupacaoSalasTurno(dataSelecionadaPorDia, "tarde", todasPautas);
        const mOver = ocupManha.totalSalas > 4;
        const tOver = ocupTarde.totalSalas > 4;
        salasStrip.style.display = "flex";
        salasStrip.innerHTML = `
          <div class="dia-sala-pill ${mOver ? "is-over" : ""}" title="${escapeHtml(ocupManha.peritos.join(", "))}">
            <span>☀️ Salas Manhã</span>
            <strong>${ocupManha.totalSalas}/4 ${mOver ? "🚨" : ""}</strong>
          </div>
          <div class="dia-sala-pill ${tOver ? "is-over" : ""}" title="${escapeHtml(ocupTarde.peritos.join(", "))}">
            <span>🌙 Salas Tarde</span>
            <strong>${ocupTarde.totalSalas}/4 ${tOver ? "🚨" : ""}</strong>
          </div>
        `;
      } else {
        salasStrip.style.display = "none";
      }
    }

    // KPIs e contadores do dia
    const totalVagasEscala = escalaDoDia.reduce((acc, p) => acc + (Number(p.vagas !== undefined ? p.vagas : p.quantidade) || 0), 0);
    const totalPresentes = pautaDoDia.filter((p) => p.presencaConfirmada || ["PRESENTE", "CHAMADO", "EM_ATENDIMENTO", "CONCLUIDO"].includes(p.statusAtendimento)).length;
    const totalChamados = pautaDoDia.filter((p) => ["CHAMADO", "EM_ATENDIMENTO", "CONCLUIDO"].includes(p.statusAtendimento)).length;
    let qtdPredio = 0;
    let qtdFora = 0;
    escalaDoDia.forEach((p) => {
      if (Parser && Parser.ehLocalFora(p.local)) qtdFora++;
      else qtdPredio++;
    });

    const elKpiEscala = document.getElementById("diaKpiEscala");
    const elKpiPauta = document.getElementById("diaKpiPautaPje");
    const elKpiPres = document.getElementById("diaKpiPresentes");
    const elKpiLoc = document.getElementById("diaKpiLocais");
    if (elKpiEscala) elKpiEscala.textContent = `${escalaDoDia.length} bl. • ${totalVagasEscala}v`;
    if (elKpiPauta) elKpiPauta.textContent = `${pautaDoDia.length} perícia(s)`;
    if (elKpiPres) elKpiPres.textContent = `${totalPresentes} / ${totalChamados}`;
    if (elKpiLoc) elKpiLoc.textContent = escalaDoDia.length > 0 ? `🏛️ ${qtdPredio} • 🏥 ${qtdFora}` : "-";

    const elPillEsc = document.getElementById("diaCountEscalaPill");
    const elPillPauta = document.getElementById("diaCountPautaPill");
    const elBadgeEsc = document.getElementById("lblCountEscalaDia");
    const elBadgePauta = document.getElementById("lblCountPautaPjeDia");
    if (elPillEsc) elPillEsc.textContent = String(escalaDoDia.length);
    if (elPillPauta) elPillPauta.textContent = String(pautaDoDia.length);
    if (elBadgeEsc) elBadgeEsc.textContent = `${escalaDoDia.length} bloco(s)`;
    if (elBadgePauta) elBadgePauta.textContent = `${pautaDoDia.length} perícia(s)`;

    const secEscala = document.getElementById("secaoEscalaDoDia");
    const secPauta = document.getElementById("secaoPautaPjeDoDia");
    if (secEscala) secEscala.style.display = (modoVisualizacaoDia === "pauta") ? "none" : "block";
    if (secPauta) secPauta.style.display = (modoVisualizacaoDia === "escala") ? "none" : "block";

    // Mapa cruzado PJe por perito neste dia (reconciliado via nome oficial quando disponível)
    const contagemPjePorPerito = {};
    pautaDoDia.forEach((p) => {
      const k = normalizarChavePeritoReconcil(p.perito);
      if (k) contagemPjePorPerito[k] = (contagemPjePorPerito[k] || 0) + 1;
    });

    // Renderizar Escala do Dia
    const containerEscala = document.getElementById("listaEscalaDoDia");
    if (containerEscala) {
      if (escalaDoDia.length === 0) {
        containerEscala.innerHTML = `
          <div class="section-card" style="text-align: center; padding: 18px;">
            <p class="text-sm text-muted" style="margin-bottom: 10px;">Nenhuma escala de perito para ${escapeHtml(cab.dataBr)} com os filtros atuais.</p>
            <button type="button" class="btn btn-outline btn-sm" data-action="proximo-dia-atividade">⏭️ Ir para próximo dia com pauta</button>
          </div>
        `;
      } else {
        containerEscala.innerHTML = escalaDoDia.map((p) => {
          const clsSit = classificarSituacaoFiltro(p.situacao);
          const statusClass = clsSit === "marcado" ? "status-marcado" : (clsSit === "em_marcacao" ? "status-em-marcacao" : "status-pendente");
          const badgeClass = clsSit === "marcado" ? "status-badge-marcado" : (clsSit === "em_marcacao" ? "status-badge-em-marcacao" : "status-badge-pendente");
          const vagasNum = p.vagas !== undefined ? p.vagas : p.quantidade;
          const horaTxt = p.horaInicio || p.hora || "08:00";
          const hInt = parseInt(horaTxt.split(":")[0], 10);
          const turnoBadge = !isNaN(hInt)
            ? `<span class="dia-turno-badge">${hInt < 12 ? "☀️ Manhã" : "🌙 Tarde"}</span>`
            : "";
          const qtdPje = contagemPjePorPerito[normalizarChavePeritoReconcil(p.peritoNome)] || 0;
          const reconcilBadge = qtdPje > 0
            ? `<span class="dia-escala-reconcil-badge">📋 ${qtdPje}/${vagasNum} no PJe</span>`
            : "";
          const obsTxt = p.observacoes || p.observacao || "";
          const prazoBadgeHtml = obterBadgePrazoPautaHtml(p);
          const actionsHtml = renderizarAcoesCardPautaHtml(p);

          return `
            <div class="pauta-card ${statusClass}">
              <div class="pauta-header">
                <div class="pauta-date-badge">
                  <span>⏰ ${escapeHtml(horaTxt)}${p.horaTermino ? ` – ${escapeHtml(p.horaTermino)}` : ""}</span>
                  ${turnoBadge}
                </div>
                <span class="status-badge ${badgeClass}">${escapeHtml(p.situacao)}</span>
              </div>
              <div class="pauta-perito">${escapeHtml(p.peritoNome)} ${reconcilBadge}</div>
              <div class="pauta-esp">${escapeHtml(p.especialidade || "-")}</div>
              <div class="pauta-details-grid">
                <div class="detail-item"><span>Vara:</span><strong>${escapeHtml(normalizarNumeroVara(p.vara) || p.vara)}ª Federal</strong></div>
                <div class="detail-item"><span>Vagas:</span><strong>${escapeHtml(vagasNum)} perícias</strong></div>
                <div class="detail-item"><span>Local:</span><strong>${escapeHtml(p.local || "JF")}</strong></div>
              </div>
              ${p.endereco ? `<div class="pauta-obs" style="margin-bottom:4px;">📍 ${escapeHtml(p.endereco)}</div>` : ""}
              ${obsTxt ? `<div class="pauta-obs">💡 ${escapeHtml(obsTxt)}</div>` : ""}
              ${prazoBadgeHtml}
              ${actionsHtml}
            </div>
          `;
        }).join("");
      }
    }

    // Renderizar Pauta PJe do Dia agrupada por Perito
    const containerPauta = document.getElementById("listaPautaPjeDoDia");
    if (containerPauta) {
      if (pautaDoDia.length === 0) {
        const msgExtra = todasPericiasPje.length === 0
          ? "Sincronize a pauta na aba \"Chamada de Perícias\" ou \"Pautas Marcadas\" no Maestro Desktop com a nuvem ativa para visualizar os periciandos no celular."
          : `Nenhuma perícia do PJe para ${escapeHtml(cab.dataBr)} com os filtros atuais.`;
        containerPauta.innerHTML = `
          <div class="section-card" style="text-align: center; padding: 18px;">
            <p class="text-sm text-muted" style="margin-bottom: 10px;">${msgExtra}</p>
            ${todasPericiasPje.length > 0 ? '<button type="button" class="btn btn-outline btn-sm" data-action="proximo-dia-atividade">⏭️ Ir para próximo dia com pauta</button>' : ""}
          </div>
        `;
      } else {
        const gruposMap = new Map();
        pautaDoDia.forEach((p) => {
          const chave = p.perito || "Perito não informado";
          if (!gruposMap.has(chave)) gruposMap.set(chave, []);
          gruposMap.get(chave).push(p);
        });

        containerPauta.innerHTML = Array.from(gruposMap.entries()).map(([nomePerito, itens]) => {
          const salaGrupo = itens.find((x) => x.sala)?.sala || "";
          const presGrupo = itens.filter((x) => x.presencaConfirmada || ["PRESENTE", "CHAMADO", "EM_ATENDIMENTO", "CONCLUIDO"].includes(x.statusAtendimento)).length;

          const rowsHtml = itens.map((item) => {
            const st = obterBadgeStatusAtendimentoMobile(item);
            const urgBadge = item.urgenciaMedica ? '<span class="dia-status-pill" style="background:rgba(239,68,68,0.16);color:#DC2626;">🚨 Prioridade</span>' : "";
            return `
              <div class="dia-pericia-row ${item.urgenciaMedica ? "is-urgencia" : ""}">
                <div class="dia-pericia-top">
                  <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
                    <span class="dia-hora-pill">${escapeHtml(item.horaPericia || "--:--")}</span>
                    ${item.sala ? `<span class="dia-turno-badge">🚪 ${escapeHtml(item.sala)}</span>` : ""}
                    ${urgBadge}
                  </div>
                  <span class="dia-status-pill ${st.cls}">${escapeHtml(st.label)}</span>
                </div>
                <div class="dia-periciando-nome">${escapeHtml(item.periciado)}</div>
                <div class="dia-proc-row">
                  <span class="dia-proc-num">📄 ${escapeHtml(item.processo)}</span>
                  <button type="button" class="btn-copy-proc" data-copy-proc="${escapeHtml(item.processo)}">📋 Copiar</button>
                </div>
                <div class="dia-pericia-meta">
                  ${item.vara ? `<span>⚖️ ${escapeHtml(item.vara)}</span>` : ""}
                  ${item.especialidade ? `<span>• 🩺 ${escapeHtml(item.especialidade)}</span>` : ""}
                  ${item.horarioCheckin ? `<span>• 🕒 Check-in ${escapeHtml(item.horarioCheckin)}</span>` : ""}
                </div>
              </div>
            `;
          }).join("");

          return `
            <div class="dia-pauta-group">
              <div class="dia-pauta-group-head">
                <div>
                  <div class="dia-pauta-group-title">👨‍⚕️ ${escapeHtml(nomePerito)}</div>
                  <div class="dia-pauta-group-sub">
                    ${itens.length} perícia(s)${presGrupo > 0 ? ` • ${presGrupo} presente(s)` : ""}${salaGrupo ? ` • ${escapeHtml(salaGrupo)}` : ""}
                  </div>
                </div>
              </div>
              <div class="dia-pauta-items">${rowsHtml}</div>
            </div>
          `;
        }).join("");
      }
    }
  }

  // =========================================================================
  // 9. LISTAGEM & FILTROS COMPLETOS DAS PAUTAS (VARA, SITUAÇÃO, PERÍODO)
  // =========================================================================
  window.setFiltroSituacao = function (filtro, elem) {
    filtroSituacaoAtivo = filtro || "todos";
    document.querySelectorAll("#tabPautas .filter-pills .pill").forEach((p) => p.classList.remove("active"));
    const targetPill = elem || document.querySelector(`#tabPautas .filter-pills .pill[data-filtro='${filtroSituacaoAtivo}']`);
    if (targetPill) targetPill.classList.add("active");
    window.filtrarPautas();
  };

  window.limparBusca = function () {
    const input = document.getElementById("filtroTexto");
    if (input) input.value = "";
    const btn = document.getElementById("btnLimparBusca");
    if (btn) btn.style.display = "none";
    window.filtrarPautas();
  };

  function resetarFiltrosListaPautas() {
    const inp = document.getElementById("filtroTexto");
    const selVara = document.getElementById("filtroVara");
    const selPer = document.getElementById("filtroPeriodoPautas");
    const selLoc = document.getElementById("filtroLocalPautas");
    const selCat = document.getElementById("filtroCategoria");
    const selOrd = document.getElementById("filtroOrdenacaoPautas");
    if (inp) inp.value = "";
    if (selVara && !selVara.disabled) selVara.value = "";
    if (selPer) selPer.value = "todos";
    if (selLoc) selLoc.value = "";
    if (selCat) selCat.value = "";
    if (selOrd) selOrd.value = "data_asc";
    window.setFiltroSituacao("todos");
  }

  window.filtrarPautas = function () {
    const txtBusca = removerAcentosLowerMobile(document.getElementById("filtroTexto")?.value || "");
    const varaFiltro = document.getElementById("filtroVara")?.value || "";
    const vNormFiltro = varaFiltro ? normalizarNumeroVara(varaFiltro) : "";
    const periodoFiltro = document.getElementById("filtroPeriodoPautas")?.value || "todos";
    const localFiltro = document.getElementById("filtroLocalPautas")?.value || "";
    const catFiltro = document.getElementById("filtroCategoria")?.value || "";
    const ordenacaoFiltro = document.getElementById("filtroOrdenacaoPautas")?.value || "data_asc";
    const btnLimpar = document.getElementById("btnLimparBusca");
    const btnReset = document.getElementById("btnResetFiltrosPautas");

    if (btnLimpar) btnLimpar.style.display = txtBusca ? "block" : "none";

    const temFiltroAtivo = Boolean(
      txtBusca ||
      (varaFiltro && !document.getElementById("filtroVara")?.disabled) ||
      periodoFiltro !== "todos" ||
      localFiltro ||
      catFiltro ||
      filtroSituacaoAtivo !== "todos" ||
      ordenacaoFiltro !== "data_asc"
    );
    if (btnReset) btnReset.style.display = temFiltroAtivo ? "inline-flex" : "none";

    const hojeIso = obterHojeIsoLocal();
    const mesIsoAtivo = `${anoAtivo}-${String(mesAtivo + 1).padStart(2, "0")}`;

    // Base filtrada por Vara/Período/Local/Categoria/Busca (antes da pílula de Situação)
    const baseSemSituacao = (todasPautas || []).filter((p) => {
      if (vNormFiltro && normalizarNumeroVara(p.vara) !== vNormFiltro) return false;
      if (periodoFiltro === "proximas" && (!p.data || p.data < hojeIso)) return false;
      if (periodoFiltro === "mes_atual" && (!p.data || !p.data.startsWith(mesIsoAtivo))) return false;
      if (periodoFiltro === "prazo_critico") {
        const prazoInfo = resolverPrazoInfoPauta(p);
        if (!prazoInfo || prazoInfo.prazoDias > 5) return false;
      }
      if (localFiltro === "predio" && Parser && Parser.ehLocalFora(p.local)) return false;
      if (localFiltro === "fora" && (!Parser || !Parser.ehLocalFora(p.local))) return false;
      if (catFiltro && p.categoria !== catFiltro) return false;
      if (txtBusca) {
        const conteudo = removerAcentosLowerMobile(`${p.peritoNome} ${p.especialidade} ${p.vara} ${p.data} ${p.local} ${p.endereco || ""} ${p.observacoes || ""}`);
        if (!conteudo.includes(txtBusca)) return false;
      }
      return true;
    });

    let countTotal = 0;
    let countMarc = 0;
    let countNaoMarc = 0;
    let countEmMarc = 0;
    let countPend = 0;

    baseSemSituacao.forEach((p) => {
      countTotal++;
      const cls = classificarSituacaoFiltro(p.situacao);
      if (cls === "marcado") countMarc++;
      else if (cls === "nao_marcado") { countNaoMarc++; countPend++; }
      else if (cls === "em_marcacao") { countEmMarc++; countPend++; }
    });

    const setTxt = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = String(val); };
    setTxt("pillCountTodos", countTotal);
    setTxt("pillCountMarcadas", countMarc);
    setTxt("pillCountNaoMarcadas", countNaoMarc);
    setTxt("pillCountEmMarcacao", countEmMarc);
    setTxt("pillCountPendentes", countPend);

    pautasFiltradas = baseSemSituacao.filter((p) => correspondeFiltroSituacao(p, filtroSituacaoAtivo));

    pautasFiltradas.sort((a, b) => {
      if (ordenacaoFiltro === "data_desc") {
        return (b.data || "").localeCompare(a.data || "") || (a.horaInicio || "").localeCompare(b.horaInicio || "");
      }
      if (ordenacaoFiltro === "perito_asc") {
        return (a.peritoNome || "").localeCompare(b.peritoNome || "", "pt-BR") || (a.data || "").localeCompare(b.data || "");
      }
      if (ordenacaoFiltro === "vagas_desc") {
        const va = Number(a.vagas !== undefined ? a.vagas : a.quantidade) || 0;
        const vb = Number(b.vagas !== undefined ? b.vagas : b.quantidade) || 0;
        return vb - va || (a.data || "").localeCompare(b.data || "");
      }
      if (ordenacaoFiltro === "prazo_asc") {
        const pa = resolverPrazoInfoPauta(a)?.prazoDias ?? 9999;
        const pb = resolverPrazoInfoPauta(b)?.prazoDias ?? 9999;
        return pa - pb || (a.data || "").localeCompare(b.data || "");
      }
      return (a.data || "").localeCompare(b.data || "") || (a.horaInicio || "").localeCompare(b.horaInicio || "");
    });

    renderizarCardsPautas();
  };

  function renderizarCardsPautas() {
    const container = document.getElementById("listaPautasCards");
    const lblCount = document.getElementById("lblQtdPautasFiltradas");

    if (!container || !lblCount) return;
    container.innerHTML = "";

    const totalVagasFilt = pautasFiltradas.reduce((acc, p) => acc + (Number(p.vagas !== undefined ? p.vagas : p.quantidade) || 0), 0);
    lblCount.textContent = `Exibindo ${pautasFiltradas.length} pauta(s) (${totalVagasFilt} vagas)`;

    if (pautasFiltradas.length === 0) {
      container.innerHTML = `
        <div class="section-card" style="text-align: center; padding: 30px;">
          <div style="font-size: 32px; margin-bottom: 8px;">🔍</div>
          <h5>Nenhuma pauta encontrada</h5>
          <p class="text-sm text-muted">Ajuste os filtros de Vara, Situação ou Período, ou importe novas pautas na aba WhatsApp.</p>
        </div>
      `;
      return;
    }

    pautasFiltradas.forEach((p) => {
      const dataFmt = formatarDataBr(p.data);
      const clsSit = classificarSituacaoFiltro(p.situacao);
      const statusClass = clsSit === "marcado" ? "status-marcado" : (clsSit === "em_marcacao" ? "status-em-marcacao" : "status-pendente");
      const badgeClass = clsSit === "marcado" ? "status-badge-marcado" : (clsSit === "em_marcacao" ? "status-badge-em-marcacao" : "status-badge-pendente");
      const vagasNum = p.vagas !== undefined ? p.vagas : p.quantidade;
      const horaTxt = p.horaInicio || p.hora || "08:00";
      const obsTxt = p.observacoes || p.observacao || "";
      const prazoBadgeHtml = obterBadgePrazoPautaHtml(p);
      const actionsHtml = renderizarAcoesCardPautaHtml(p);

      const card = document.createElement("div");
      card.className = `pauta-card ${statusClass}`;
      card.innerHTML = `
        <div class="pauta-header">
          <div class="pauta-date-badge${p.data ? " is-clickable" : ""}" ${p.data ? `data-abrir-dia="${escapeHtml(p.data)}" title="Ver Escala e Pauta PJe deste dia"` : ""}>
            <span>📅</span>
            <span>${escapeHtml(dataFmt)} • ${escapeHtml(horaTxt)}</span>
          </div>
          <span class="status-badge ${badgeClass}">${escapeHtml(p.situacao)}</span>
        </div>

        <div class="pauta-perito">${escapeHtml(p.peritoNome)}</div>
        <div class="pauta-esp">${escapeHtml(p.especialidade || "-")}</div>

        <div class="pauta-details-grid">
          <div class="detail-item">
            <span>Vara:</span>
            <strong>${escapeHtml(normalizarNumeroVara(p.vara) || p.vara)}ª Federal</strong>
          </div>
          <div class="detail-item">
            <span>Vagas:</span>
            <strong>${escapeHtml(vagasNum)} perícias</strong>
          </div>
          <div class="detail-item">
            <span>Local:</span>
            <strong>${escapeHtml(p.local || "JF")}</strong>
          </div>
        </div>

        ${p.endereco ? `<div class="pauta-obs" style="margin-bottom:4px;">📍 ${escapeHtml(p.endereco)}</div>` : ""}
        ${obsTxt ? `<div class="pauta-obs">💡 ${escapeHtml(obsTxt)}</div>` : ""}
        ${prazoBadgeHtml}
        ${actionsHtml}
      `;
      container.appendChild(card);
    });
  }

  function formatarDataBr(isoDate) {
    if (!isoDate) return "-";
    const parts = String(isoDate).split("-");
    if (parts.length === 3) return `${parts[2]}/${parts[1]}/${parts[0]}`;
    return isoDate;
  }

  // =========================================================================
  // 9B. EDIÇÃO RÁPIDA, ALTERAÇÃO DE SITUAÇÃO & EXCLUSÃO NA NUVEM (E2EE)
  // =========================================================================
  function encontrarPautaLocalPorIdentificador(idParam, keyParam) {
    return (todasPautas || []).find((p) => {
      if (idParam && String(p.id || "") === String(idParam)) return true;
      if (keyParam && gerarChaveUnicaPauta(p) === keyParam) return true;
      return false;
    }) || null;
  }

  function tratarCliqueAcaoPautaCard(e) {
    const btn = e.target.closest("[data-pauta-action]");
    if (!btn) return;
    const action = btn.getAttribute("data-pauta-action");
    const idParam = btn.getAttribute("data-pauta-id") || "";
    const keyParam = btn.getAttribute("data-pauta-key") || "";
    const pauta = encontrarPautaLocalPorIdentificador(idParam, keyParam);
    if (!pauta) {
      mostrarToast("Pauta não localizada na memória atual. Sincronize e tente novamente.", "warn");
      return;
    }

    if (action === "ciclar-situacao") {
      alternarSituacaoRapidaPauta(pauta, btn);
    } else if (action === "editar") {
      abrirModalEditarPauta(pauta);
    } else if (action === "excluir") {
      confirmarExcluirPauta(pauta, btn);
    }
  }

  async function gravarMutacaoPautaEscalaNuvem({ modo, pautaOriginal, pautaNova = null }) {
    if (!sessaoUsuario) throw new Error("Sessão não inicializada.");
    if (!podeEnviarPautasNaSessao()) throw new Error("Perfil Somente Leitura não possui permissão para alterar a escala.");
    const subId = sessaoUsuario.subsecaoId;
    if (!isVaraAutorizadaNaSessao(pautaOriginal?.vara, sessaoUsuario, subId)) {
      throw new Error("A Vara desta pauta não está autorizada para seu perfil.");
    }
    if (pautaNova && !isVaraAutorizadaNaSessao(pautaNova.vara, sessaoUsuario, subId)) {
      throw new Error("A Vara selecionada não está autorizada para seu perfil.");
    }

    const chaveOrig = gerarChaveUnicaPauta(pautaOriginal);
    const idOrig = pautaOriginal?.id ? String(pautaOriginal.id) : "";
    const now = Date.now();
    let listaFinalNuvem = null;

    const temProjetoNuvem = Boolean(
      sessaoUsuario.projectId &&
      sessaoUsuario.projectId.trim() &&
      !sessaoUsuario.projectId.includes("exemplo")
    );

    if (temProjetoNuvem) {
      if (typeof navigator !== "undefined" && navigator.onLine === false) {
        throw new Error("Edição e exclusão direta exigem conexão com a internet para sincronizar com a nuvem.");
      }

      let chaveNuvem = obterChaveNuvemSessao();
      if (!chaveNuvem) {
        const digitada = window.prompt("🔐 Informe a Chave / Senha AES-256 da Vara para salvar a alteração com segurança:") || "";
        if (!digitada.trim()) throw new Error("Chave AES-256 obrigatória para gravar na nuvem.");
        chaveNuvem = digitada.trim();
        salvarChaveNuvemSessao(chaveNuvem, false);
      }

      const urlGet = `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(sessaoUsuario.projectId)}/databases/(default)/documents/subsecoes/${encodeURIComponent(subId)}`;
      const respGet = await fetch(urlGet, { method: "GET", cache: "no-cache" });

      let escalaNuvemAtual = [];
      let tombstonesNuvem = {};
      if (respGet.ok) {
        const doc = await respGet.json();
        const fields = doc.fields || {};

        if (fields.escalaTombstonesJson?.stringValue) {
          try {
            const decTomb = await decodificarOuDecifrarDadoNuvemMobile(
              fields.escalaTombstonesJson.stringValue,
              fields.ivTombstones?.stringValue || fields.ivEscala?.stringValue,
              fields.saltTombstones?.stringValue || fields.saltEscala?.stringValue,
              chaveNuvem
            );
            if (decTomb && typeof decTomb === "object" && !Array.isArray(decTomb)) {
              tombstonesNuvem = decTomb;
            }
          } catch (eTomb) {}
        }

        if (fields.escalaPautasJson?.stringValue) {
          let dec = null;
          try {
            dec = await decodificarOuDecifrarDadoNuvemMobile(
              fields.escalaPautasJson.stringValue,
              fields.ivEscala?.stringValue || fields.iv?.stringValue,
              fields.saltEscala?.stringValue || fields.salt?.stringValue,
              chaveNuvem
            );
          } catch (eDec) {
            throw new Error("Chave AES-256 incorreta. Operação cancelada para proteger os dados da nuvem.");
          }
          if (!Array.isArray(dec)) {
            throw new Error("Não foi possível decifrar a escala da nuvem com a chave atual.");
          }
          escalaNuvemAtual = dec;
        }
      } else if (respGet.status !== 404) {
        throw new Error(`Falha ao ler nuvem (HTTP ${respGet.status}).`);
      }

      const correspondeItem = (item) => {
        if (!item) return false;
        if (idOrig && item.id && String(item.id) === idOrig) return true;
        return gerarChaveUnicaPauta(item) === chaveOrig;
      };

      if (modo === "editar" && pautaNova) {
        const copiaLimpa = Parser ? Parser.prepararPautaCanonica(pautaNova, bancoPeritosMobile) : { ...pautaNova };
        delete copiaLimpa._meta;
        copiaLimpa.id = idOrig || copiaLimpa.id || `pauta_mob_${now}`;
        copiaLimpa.updatedAt = now;
        const idxMatch = escalaNuvemAtual.findIndex(correspondeItem);
        if (idxMatch >= 0) {
          escalaNuvemAtual[idxMatch] = { ...escalaNuvemAtual[idxMatch], ...copiaLimpa };
        } else {
          escalaNuvemAtual.push(copiaLimpa);
        }
        const chaveNova = gerarChaveUnicaPauta(copiaLimpa);
        if (tombstonesNuvem[chaveOrig]) delete tombstonesNuvem[chaveOrig];
        if (tombstonesNuvem[chaveNova]) delete tombstonesNuvem[chaveNova];
        if (idOrig && tombstonesNuvem[idOrig]) delete tombstonesNuvem[idOrig];
      } else if (modo === "excluir") {
        escalaNuvemAtual = escalaNuvemAtual.filter((item) => !correspondeItem(item));
        const tombReg = {
          deletedAt: now,
          deletedBy: sessaoUsuario.usuarioCpf || "mobile",
          id: idOrig
        };
        if (chaveOrig && chaveOrig !== "___") tombstonesNuvem[chaveOrig] = tombReg;
        if (idOrig) tombstonesNuvem[idOrig] = tombReg;
      }

      listaFinalNuvem = escalaNuvemAtual;

      const encoderUtf8 = new TextEncoder();
      const escalaStr = JSON.stringify(escalaNuvemAtual);
      const bytesBruto = encoderUtf8.encode(escalaStr).length;
      const opcoesCripto = Math.ceil(bytesBruto * 1.34) >= 400000
        ? { comprimirGzip: true }
        : { autoGzipAcimaBytes: 131072 };

      const resEscala = await cifrarTextoAESMobile(escalaStr, chaveNuvem, opcoesCripto);
      const resTomb = await cifrarTextoAESMobile(JSON.stringify(tombstonesNuvem), chaveNuvem, { autoGzipAcimaBytes: 65536 });

      const updateFields = [
        "subsecaoId",
        "encrypted",
        "escalaPautasJson",
        "ivEscala",
        "saltEscala",
        "escalaTombstonesJson",
        "ivTombstones",
        "saltTombstones",
        "timestamp",
        "atualizadoPor"
      ];
      const maskQuery = updateFields.map((f) => `updateMask.fieldPaths=${encodeURIComponent(f)}`).join("&");
      const payloadPatch = {
        fields: {
          subsecaoId: { stringValue: subId },
          encrypted: { booleanValue: true },
          escalaPautasJson: { stringValue: resEscala.data },
          ivEscala: { stringValue: resEscala.iv },
          saltEscala: { stringValue: resEscala.salt },
          escalaTombstonesJson: { stringValue: resTomb.data },
          ivTombstones: { stringValue: resTomb.iv },
          saltTombstones: { stringValue: resTomb.salt },
          timestamp: { integerValue: String(now) },
          atualizadoPor: { stringValue: `Maestro Mobile (${sessaoUsuario.usuarioCpf || "Edição"})` }
        }
      };

      const respPatch = await fetch(`${urlGet}?${maskQuery}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payloadPatch)
      });
      if (!respPatch.ok) {
        throw new Error(`Falha ao gravar alteração na nuvem (HTTP ${respPatch.status}).`);
      }
    } else {
      const correspondeLocal = (item) => {
        if (!item) return false;
        if (idOrig && item.id && String(item.id) === idOrig) return true;
        return gerarChaveUnicaPauta(item) === chaveOrig;
      };
      const baseLocal = [...(todasPautas || [])];
      if (modo === "editar" && pautaNova) {
        const copia = Parser ? Parser.prepararPautaCanonica(pautaNova, bancoPeritosMobile) : { ...pautaNova };
        delete copia._meta;
        copia.id = idOrig || copia.id || `pauta_mob_${now}`;
        copia.updatedAt = now;
        const idxM = baseLocal.findIndex(correspondeLocal);
        if (idxM >= 0) baseLocal[idxM] = { ...baseLocal[idxM], ...copia };
        else baseLocal.push(copia);
      } else if (modo === "excluir") {
        listaFinalNuvem = baseLocal.filter((x) => !correspondeLocal(x));
      }
      if (!listaFinalNuvem) listaFinalNuvem = baseLocal;
    }

    if (ehAmbienteExtensaoChrome() && Array.isArray(listaFinalNuvem)) {
      try {
        await chrome.storage.local.set({ [`escalaPautas_${subId}`]: listaFinalNuvem });
      } catch (eExt) {}
    }

    todasPautas = aplicarFiltroRestritoSubsecao(converterPautasFirestore(listaFinalNuvem || []), subId);
    salvarCacheLocal(subId, todasPautas);
    ultimaSyncEscalaTs = now;
    atualizarIndicadorSync();
    atualizarInterfaceCompleta();
  }

  async function alternarSituacaoRapidaPauta(pauta, btnEl = null) {
    const clsAtual = classificarSituacaoFiltro(pauta.situacao);
    let proxima = "Em marcação";
    if (clsAtual === "em_marcacao") proxima = "Marcado";
    else if (clsAtual === "marcado") proxima = "Não marcado";

    const origTxt = btnEl ? btnEl.textContent : "";
    if (btnEl) {
      btnEl.disabled = true;
      btnEl.textContent = "⏳...";
    }
    try {
      await gravarMutacaoPautaEscalaNuvem({
        modo: "editar",
        pautaOriginal: pauta,
        pautaNova: { ...pauta, situacao: proxima }
      });
      mostrarToast(`Situação atualizada para "${proxima}".`, "success");
    } catch (err) {
      mostrarToast("Erro ao atualizar situação: " + err.message, "error", 4200);
      if (btnEl) {
        btnEl.disabled = false;
        btnEl.textContent = origTxt;
      }
    }
  }

  async function confirmarExcluirPauta(pauta, btnEl = null) {
    const desc = `${pauta.peritoNome} (${formatarDataBr(pauta.data)} • ${pauta.horaInicio || "08:00"} • ${normalizarNumeroVara(pauta.vara) || pauta.vara}ª VF)`;
    if (!confirm(`🗑️ Deseja realmente excluir esta pauta da escala?\n\n${desc}\n\nA exclusão será sincronizada com todos os computadores.`)) {
      return;
    }
    if (btnEl) btnEl.disabled = true;
    try {
      await gravarMutacaoPautaEscalaNuvem({
        modo: "excluir",
        pautaOriginal: pauta
      });
      mostrarToast("Pauta excluída e sincronizada.", "success");
    } catch (err) {
      mostrarToast("Erro ao excluir pauta: " + err.message, "error", 4200);
      if (btnEl) btnEl.disabled = false;
    }
  }

  function atualizarVisibilidadeEnderecoModalEditar() {
    const localVal = document.getElementById("editLocal")?.value || "";
    const box = document.getElementById("boxEditEndereco");
    if (!box) return;
    const ehFora = Parser ? Parser.ehLocalFora(localVal) : false;
    box.style.display = ehFora ? "block" : "none";
  }

  function atualizarPreviewCalcModalEditar() {
    const dataVal = document.getElementById("editData")?.value || "";
    const horaVal = document.getElementById("editHoraInicio")?.value || "08:00";
    const qtdVal = parseInt(document.getElementById("editQuantidade")?.value || "20", 10) || 1;
    const intVal = parseInt(document.getElementById("editIntervaloMin")?.value || "10", 10) || 10;

    const term = Parser ? Parser.calcularHorarioTermino(horaVal, intVal, qtdVal) : "--:--";
    const limIso = (Parser && dataVal) ? Parser.calcularDataLimite8DiasUteis(dataVal) : "";
    const elTerm = document.getElementById("editCalcTermino");
    const elLim = document.getElementById("editCalcLimite");
    if (elTerm) elTerm.textContent = term || "--:--";
    if (elLim) elLim.textContent = limIso ? formatarDataBr(limIso) : "-";
  }

  function abrirModalEditarPauta(pauta) {
    if (!pauta || !podeEnviarPautasNaSessao()) return;
    pautaEmEdicaoModal = pauta;

    const modal = document.getElementById("modalEditarPautaMobile");
    const subId = sessaoUsuario?.subsecaoId || "sobral";
    const varasAuth = resolverVarasAutorizadasSubsecao(sessaoUsuario, subId);

    const selVara = document.getElementById("editVara");
    if (selVara) {
      const vNorm = normalizarNumeroVara(pauta.vara);
      selVara.innerHTML = varasAuth.map((v) =>
        `<option value="${escapeHtml(v)}" ${vNorm === v ? "selected" : ""}>${escapeHtml(v)}ª Vara Federal</option>`
      ).join("");
      selVara.disabled = varasAuth.length === 1;
    }

    const selLocal = document.getElementById("editLocal");
    if (selLocal) {
      const localAtual = pauta.local || "Justiça Federal";
      const opts = LOCAIS_PADRAO_OPTIONS.some((o) => o.value === localAtual)
        ? LOCAIS_PADRAO_OPTIONS
        : [{ value: localAtual, label: localAtual }, ...LOCAIS_PADRAO_OPTIONS];
      selLocal.innerHTML = opts.map((o) =>
        `<option value="${escapeHtml(o.value)}" ${localAtual === o.value ? "selected" : ""}>${escapeHtml(o.label)}</option>`
      ).join("");
    }

    const setVal = (id, v) => { const el = document.getElementById(id); if (el) el.value = v ?? ""; };
    setVal("editPautaId", pauta.id || "");
    setVal("editPautaChaveOrig", gerarChaveUnicaPauta(pauta));
    setVal("editPeritoNome", pauta.peritoNome || "");
    setVal("editEspecialidade", pauta.especialidade || "");
    setVal("editData", pauta.data || "");
    setVal("editHoraInicio", pauta.horaInicio || pauta.hora || "08:00");
    setVal("editQuantidade", pauta.quantidade !== undefined ? pauta.quantidade : (pauta.vagas || 20));
    setVal("editIntervaloMin", pauta.intervaloMin !== undefined ? pauta.intervaloMin : (pauta.duracao || 10));
    setVal("editSituacao", pauta.situacao || "Não marcado");
    setVal("editEndereco", pauta.endereco || "");
    setVal("editObservacoes", pauta.observacoes || pauta.observacao || "");

    atualizarVisibilidadeEnderecoModalEditar();
    atualizarPreviewCalcModalEditar();
    if (modal) modal.classList.add("open");
  }

  function fecharModalEditarPauta() {
    const modal = document.getElementById("modalEditarPautaMobile");
    if (modal) modal.classList.remove("open");
    pautaEmEdicaoModal = null;
  }

  async function salvarEdicaoPautaModal() {
    if (!pautaEmEdicaoModal) return;
    const getVal = (id) => String(document.getElementById(id)?.value || "").trim();

    const peritoNome = getVal("editPeritoNome");
    const data = getVal("editData");
    const horaInicio = getVal("editHoraInicio") || "08:00";
    const quantidade = Math.max(1, parseInt(getVal("editQuantidade"), 10) || 1);
    const intervaloMin = Math.max(1, parseInt(getVal("editIntervaloMin"), 10) || 10);
    const vara = normalizarNumeroVara(getVal("editVara"));
    const local = getVal("editLocal") || "Justiça Federal";
    const endereco = getVal("editEndereco");
    const situacao = getVal("editSituacao") || "Não marcado";
    const especialidade = getVal("editEspecialidade");
    const observacoes = getVal("editObservacoes");

    if (!peritoNome || !data || !vara) {
      mostrarToast("Preencha Perito, Data e Vara.", "warn");
      return;
    }
    if (Parser && Parser.ehLocalFora(local) && !endereco) {
      mostrarToast("Informe o endereço externo para perícias fora do prédio.", "warn");
      return;
    }

    const btnSalvar = document.getElementById("btnSalvarModalEditarPauta");
    if (btnSalvar) {
      btnSalvar.disabled = true;
      btnSalvar.textContent = "⏳ Salvando...";
    }

    try {
      await gravarMutacaoPautaEscalaNuvem({
        modo: "editar",
        pautaOriginal: pautaEmEdicaoModal,
        pautaNova: {
          ...pautaEmEdicaoModal,
          peritoNome,
          especialidade,
          data,
          horaInicio,
          hora: horaInicio,
          quantidade,
          vagas: quantidade,
          intervaloMin,
          duracao: intervaloMin,
          vara,
          local,
          endereco: (Parser && Parser.ehLocalFora(local)) ? endereco : "",
          situacao,
          observacoes,
          observacao: observacoes
        }
      });
      fecharModalEditarPauta();
      mostrarToast("Pauta atualizada e sincronizada!", "success");
    } catch (err) {
      mostrarToast("Erro ao salvar: " + err.message, "error", 4500);
    } finally {
      if (btnSalvar) {
        btnSalvar.disabled = false;
        btnSalvar.textContent = "☁️ Salvar Alterações";
      }
    }
  }

  // =========================================================================
  // 10. GERAÇÃO E EXPORTAÇÃO DE RELATÓRIOS (FILTRADOS POR VARA/SITUAÇÃO/MÊS)
  // =========================================================================
  function atualizarEstadoFiltrosRelatorio() {
    const selPer = document.getElementById("relFiltroPeriodo");
    const inpMes = document.getElementById("relFiltroMesInput");
    if (selPer && inpMes) {
      inpMes.disabled = selPer.value !== "mes_selecionado";
    }
    atualizarResumoFiltroRelatorio();
  }

  function obterPautasFiltradasRelatorio(forcarTodasDatas = false) {
    const periodo = forcarTodasDatas ? "todos" : (document.getElementById("relFiltroPeriodo")?.value || "mes_selecionado");
    const mesInput = document.getElementById("relFiltroMesInput")?.value || `${anoAtivo}-${String(mesAtivo + 1).padStart(2, "0")}`;
    const varaFiltro = document.getElementById("relFiltroVara")?.value || "";
    const vNormFiltro = varaFiltro ? normalizarNumeroVara(varaFiltro) : "";
    const sitFiltro = document.getElementById("relFiltroSituacao")?.value || "todos";
    const hojeIso = obterHojeIsoLocal();

    const lista = (todasPautas || []).filter((p) => {
      if (vNormFiltro && normalizarNumeroVara(p.vara) !== vNormFiltro) return false;
      if (!correspondeFiltroSituacao(p, sitFiltro)) return false;
      if (periodo === "mes_selecionado" && (!p.data || !p.data.startsWith(mesInput))) return false;
      if (periodo === "proximas" && (!p.data || p.data < hojeIso)) return false;
      return true;
    }).sort((a, b) => (a.data || "").localeCompare(b.data || "") || (a.horaInicio || "").localeCompare(b.horaInicio || ""));

    return { lista, periodo, mesInput, varaFiltro, sitFiltro };
  }

  function atualizarResumoFiltroRelatorio() {
    const el = document.getElementById("lblResumoFiltroRelatorio");
    if (!el || !sessaoUsuario) return;
    const { lista } = obterPautasFiltradasRelatorio(false);
    const totalVagas = lista.reduce((acc, p) => acc + (Number(p.vagas !== undefined ? p.vagas : p.quantidade) || 1), 0);
    el.textContent = `${lista.length} pauta(s) • ${totalVagas} vagas selecionadas para o relatório`;
  }

  function descreverFiltroSituacaoLabel(sit) {
    if (sit === "marcado") return "Somente Marcadas";
    if (sit === "nao_marcado") return "Somente Não marcadas";
    if (sit === "em_marcacao") return "Somente Em marcação";
    if (sit === "pendente") return "Somente Pendentes";
    return "Todas as situações";
  }

  function descreverMesInputBr(mesIso) {
    const pts = String(mesIso || "").split("-");
    if (pts.length === 2) {
      const mIdx = parseInt(pts[1], 10) - 1;
      return `${MESES_NOMES[mIdx] || pts[1]} de ${pts[0]}`;
    }
    return `${MESES_NOMES[mesAtivo]} de ${anoAtivo}`;
  }

  window.gerarRelatorioPdf = function (tipo) {
    if (!sessaoUsuario) return;
    const subInfo = SUBSECOES_MAP[sessaoUsuario.subsecaoId] || { nome: sessaoUsuario.subsecaoNome };
    const varasAuth = resolverVarasAutorizadasSubsecao(sessaoUsuario, sessaoUsuario.subsecaoId);
    const varasSub = subInfo.varas || [];
    const escopoTitulo = (sessaoUsuario.role !== "Master" && varasAuth.length < varasSub.length)
      ? `${subInfo.nome} • ${varasAuth.map((v) => `${v}ª VF`).join(", ")}`
      : subInfo.nome;

    const forcarTodas = tipo === "completo";
    const { lista, periodo, mesInput, varaFiltro, sitFiltro } = obterPautasFiltradasRelatorio(forcarTodas);

    const tituloPeriodoBase = periodo === "mes_selecionado"
      ? descreverMesInputBr(mesInput)
      : (periodo === "proximas" ? "A partir de hoje" : "Todas as Datas");
    const filtroVaraTxt = varaFiltro ? `${normalizarNumeroVara(varaFiltro)}ª Vara Federal` : "Todas as Varas";
    const filtroSitTxt = descreverFiltroSituacaoLabel(sitFiltro);

    let totalVagas = 0;
    let totalMarcadas = 0;
    let totalPendentes = 0;

    lista.forEach((p) => {
      const v = Number(p.vagas !== undefined ? p.vagas : p.quantidade) || 1;
      totalVagas += v;
      if (p.situacao === "Marcado") totalMarcadas += v;
      else if (ehSituacaoPendente(p.situacao)) totalPendentes += v;
    });

    const taxa = totalVagas > 0 ? Math.round((totalMarcadas / totalVagas) * 100) : 0;

    const linhasHtml = lista.map((p, idx) => `
      <tr>
        <td style="text-align: center;">${idx + 1}</td>
        <td><strong>${escapeHtml(formatarDataBr(p.data))}</strong><br><small>${escapeHtml(p.horaInicio || p.hora)}</small></td>
        <td><strong>${escapeHtml(p.peritoNome)}</strong><br><small>${escapeHtml(p.especialidade)}</small></td>
        <td style="text-align: center;">${escapeHtml(normalizarNumeroVara(p.vara) || p.vara)}ª VF</td>
        <td style="text-align: center; font-weight: bold;">${escapeHtml(p.vagas !== undefined ? p.vagas : p.quantidade)}</td>
        <td style="text-align: center;">
          <span style="font-weight: bold; color: ${p.situacao === "Marcado" ? "#059669" : "#D97706"};">
            ${escapeHtml(p.situacao)}
          </span>
        </td>
        <td>${escapeHtml(p.local || "-")}${p.endereco ? `<br><small>${escapeHtml(p.endereco)}</small>` : ""}<br><small>${escapeHtml(p.observacoes || p.observacao || "")}</small></td>
      </tr>
    `).join("");

    const previewArea = document.getElementById("areaPreviewRelatorio");
    const container = document.getElementById("conteudoRelatorioImpressao");

    container.innerHTML = `
      <div class="print-header">
        <div style="font-size: 13px; font-weight: bold; text-transform: uppercase; color: #334155;">
          PODER JUDICIÁRIO • JUSTIÇA FEDERAL DA 5ª REGIÃO
        </div>
        <div class="print-title" style="margin: 4px 0;">
          RELATÓRIO OFICIAL DE PAUTAS E PERÍCIAS JUDICIAIS
        </div>
        <div class="print-subtitle" style="font-weight: 600; color: #0284C7;">
          Subseção Judiciária de ${escapeHtml(escopoTitulo)} • Maestro PJe
        </div>
        <div style="font-size: 11px; color: #64748B; margin-top: 4px;">
          Período: <strong>${escapeHtml(tituloPeriodoBase)}</strong> • Vara: <strong>${escapeHtml(filtroVaraTxt)}</strong> • Situação: <strong>${escapeHtml(filtroSitTxt)}</strong>
        </div>
        <div style="font-size: 10.5px; color: #64748B; margin-top: 2px;">
          Emitido em: ${new Date().toLocaleDateString("pt-BR")} às ${new Date().toLocaleTimeString("pt-BR")}
        </div>
      </div>

      <div style="display: flex; flex-wrap: wrap; gap: 10px; justify-content: space-between; background: #F8FAFC; border: 1px solid #CBD5E1; padding: 12px; border-radius: 6px; margin-bottom: 16px; font-size: 12px;">
        <div><strong>Total de Vagas:</strong> ${totalVagas}</div>
        <div><strong style="color: #059669;">Perícias Marcadas:</strong> ${totalMarcadas} (${taxa}%)</div>
        <div><strong style="color: #D97706;">Perícias Pendentes:</strong> ${totalPendentes} (${100 - taxa}%)</div>
        <div><strong>Total de Blocos:</strong> ${lista.length} pautas</div>
      </div>

      <table class="print-table">
        <thead>
          <tr>
            <th style="width: 30px; text-align: center;">#</th>
            <th style="width: 80px;">Data/Hora</th>
            <th>Perito / Especialidade</th>
            <th style="width: 55px; text-align: center;">Vara</th>
            <th style="width: 50px; text-align: center;">Vagas</th>
            <th style="width: 75px; text-align: center;">Situação</th>
            <th>Local / Observações</th>
          </tr>
        </thead>
        <tbody>
          ${linhasHtml || '<tr><td colspan="7" style="text-align:center;padding:16px;">Nenhuma pauta encontrada com os filtros selecionados.</td></tr>'}
        </tbody>
      </table>

      <div style="margin-top: 24px; text-align: right; font-size: 10px; color: #64748B;">
        Documento gerado pelo Maestro PJe Mobile • Usuário: ${escapeHtml(sessaoUsuario.usuarioNome || mascararCpfMobile(sessaoUsuario.usuarioCpf))} (Escopo: ${escapeHtml(escopoTitulo)})
      </div>
    `;

    previewArea.style.display = "block";
    previewArea.scrollIntoView({ behavior: "smooth" });
  };

  function gerarRelatorioPdfPautaPjeDia() {
    if (!sessaoUsuario) return;
    const varaFiltro = document.getElementById("relFiltroVara")?.value || "";
    const vNormFiltro = varaFiltro ? normalizarNumeroVara(varaFiltro) : "";
    const listaDia = (todasPericiasPje || []).filter((p) => {
      if (p.dataPericiaIso !== dataSelecionadaPorDia) return false;
      if (vNormFiltro && (p.varaNum || extrairVaraNumeroPericiaMobile(p.vara)) !== vNormFiltro) return false;
      return true;
    }).sort((a, b) => (a.perito || "").localeCompare(b.perito || "", "pt-BR") || (a.horaPericia || "").localeCompare(b.horaPericia || ""));

    if (listaDia.length === 0) {
      mostrarToast(`Nenhuma perícia PJe encontrada para ${formatarDataBr(dataSelecionadaPorDia)} nesta Vara.`, "warn", 3500);
      return;
    }

    const subInfo = SUBSECOES_MAP[sessaoUsuario.subsecaoId] || { nome: sessaoUsuario.subsecaoNome };
    const varaTxt = vNormFiltro ? `${vNormFiltro}ª Vara Federal` : "Todas as Varas";

    const linhasHtml = listaDia.map((item, idx) => `
      <tr>
        <td style="text-align: center;">${idx + 1}</td>
        <td><strong>${escapeHtml(item.horaPericia || "--:--")}</strong>${item.sala ? `<br><small>${escapeHtml(item.sala)}</small>` : ""}</td>
        <td><strong>${escapeHtml(item.perito)}</strong><br><small>${escapeHtml(item.especialidade || "")}</small></td>
        <td><strong>${escapeHtml(item.periciado)}</strong>${item.urgenciaMedica ? "<br><small style='color:#DC2626;'>PRIORIDADE</small>" : ""}</td>
        <td style="font-family: monospace;">${escapeHtml(item.processo)}</td>
        <td style="text-align: center;">${escapeHtml(item.varaNum || item.vara || "-")}</td>
        <td>${escapeHtml(obterBadgeStatusAtendimentoMobile(item).label)}</td>
      </tr>
    `).join("");

    const previewArea = document.getElementById("areaPreviewRelatorio");
    const container = document.getElementById("conteudoRelatorioImpressao");
    container.innerHTML = `
      <div class="print-header">
        <div style="font-size: 13px; font-weight: bold; text-transform: uppercase; color: #334155;">
          PODER JUDICIÁRIO • JUSTIÇA FEDERAL DA 5ª REGIÃO
        </div>
        <div class="print-title" style="margin: 4px 0;">
          PAUTA DIÁRIA DE PERÍCIAS JUDICIAIS (PJE)
        </div>
        <div class="print-subtitle" style="font-weight: 600; color: #0284C7;">
          Subseção de ${escapeHtml(subInfo.nome)} • ${escapeHtml(varaTxt)}
        </div>
        <div style="font-size: 11px; color: #64748B; margin-top: 4px;">
          Data das Perícias: <strong>${escapeHtml(formatarDataBr(dataSelecionadaPorDia))}</strong> • Total: <strong>${listaDia.length} perícia(s)</strong>
        </div>
      </div>

      <table class="print-table">
        <thead>
          <tr>
            <th style="width: 28px; text-align: center;">#</th>
            <th style="width: 65px;">Horário</th>
            <th>Perito</th>
            <th>Periciando</th>
            <th>Processo</th>
            <th style="width: 45px; text-align: center;">Vara</th>
            <th style="width: 90px;">Status</th>
          </tr>
        </thead>
        <tbody>${linhasHtml}</tbody>
      </table>
    `;

    previewArea.style.display = "block";
    previewArea.scrollIntoView({ behavior: "smooth" });
  }

  window.fecharPreviewRelatorio = function () {
    const area = document.getElementById("areaPreviewRelatorio");
    if (area) area.style.display = "none";
  };

  window.exportarRelatorioCsv = function () {
    if (!sessaoUsuario) return;
    const subInfo = SUBSECOES_MAP[sessaoUsuario.subsecaoId] || { nome: sessaoUsuario.subsecaoNome };
    const { lista, periodo, mesInput, varaFiltro, sitFiltro } = obterPautasFiltradasRelatorio(false);

    let csv = "\uFEFF";
    csv += "Data;Hora;Perito;Especialidade;Vara;Vagas;Situacao;Local;Endereco;Observacoes;Subsecao\n";

    lista.forEach((p) => {
      const linha = [
        sanitizarCelulaCSV(formatarDataBr(p.data)),
        sanitizarCelulaCSV(p.horaInicio || p.hora || "08:00"),
        sanitizarCelulaCSV(p.peritoNome || ""),
        sanitizarCelulaCSV(p.especialidade || ""),
        sanitizarCelulaCSV(`${normalizarNumeroVara(p.vara) || p.vara}ª Vara Federal`),
        sanitizarCelulaCSV(p.vagas !== undefined ? p.vagas : (p.quantidade || 1)),
        sanitizarCelulaCSV(p.situacao || "Não marcado"),
        sanitizarCelulaCSV(p.local || ""),
        sanitizarCelulaCSV(p.endereco || ""),
        sanitizarCelulaCSV(p.observacoes || p.observacao || ""),
        sanitizarCelulaCSV(subInfo.nome)
      ].join(";");
      csv += linha + "\n";
    });

    const sufixoPer = periodo === "mes_selecionado" ? mesInput : periodo;
    const sufixoVara = varaFiltro ? `_Vara${normalizarNumeroVara(varaFiltro)}` : "";
    const sufixoSit = sitFiltro !== "todos" ? `_${sitFiltro}` : "";
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `Maestro_PJe_${sessaoUsuario.subsecaoId}_${sufixoPer}${sufixoVara}${sufixoSit}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    mostrarToast(`CSV exportado com ${lista.length} pauta(s).`, "success");
  };

  function gerarTextoResumoWhatsApp() {
    const subInfo = SUBSECOES_MAP[sessaoUsuario.subsecaoId] || { nome: sessaoUsuario.subsecaoNome };
    const varasAuth = resolverVarasAutorizadasSubsecao(sessaoUsuario, sessaoUsuario.subsecaoId);
    const varasSub = subInfo.varas || [];
    const escopoTxt = (sessaoUsuario.role !== "Master" && varasAuth.length < varasSub.length)
      ? `${subInfo.nome} (${varasAuth.map((v) => `${v}ª VF`).join(", ")})`
      : subInfo.nome;
    const { lista, periodo, mesInput, varaFiltro, sitFiltro } = obterPautasFiltradasRelatorio(false);

    let totalVagas = 0;
    let marcadas = 0;
    let pendentes = 0;
    const varasMap = {};

    lista.forEach((p) => {
      const v = Number(p.vagas !== undefined ? p.vagas : p.quantidade) || 1;
      totalVagas += v;
      if (p.situacao === "Marcado") marcadas += v;
      else if (ehSituacaoPendente(p.situacao)) pendentes += v;

      const vNome = `${normalizarNumeroVara(p.vara) || p.vara}ª VF`;
      if (!varasMap[vNome]) varasMap[vNome] = { m: 0, p: 0, tot: 0 };
      varasMap[vNome].tot += v;
      if (p.situacao === "Marcado") varasMap[vNome].m += v;
      else if (ehSituacaoPendente(p.situacao)) varasMap[vNome].p += v;
    });

    const taxa = totalVagas > 0 ? Math.round((marcadas / totalVagas) * 100) : 0;
    const perLabel = periodo === "mes_selecionado"
      ? descreverMesInputBr(mesInput)
      : (periodo === "proximas" ? "A partir de hoje" : "Todas as datas");

    let txt = `⚖️ *MAESTRO PJE - RESUMO DE PAUTAS*\n`;
    txt += `📍 *Subseção:* ${escopoTxt}${varaFiltro ? ` • ${normalizarNumeroVara(varaFiltro)}ª VF` : ""}\n`;
    txt += `📅 *Período:* ${perLabel}\n`;
    txt += `🎯 *Situação:* ${descreverFiltroSituacaoLabel(sitFiltro)}\n\n`;
    txt += `📊 *NÚMEROS GERAIS:*\n`;
    txt += `• *Total de Blocos:* ${lista.length} pautas\n`;
    txt += `• *Total de Vagas:* ${totalVagas} perícias\n`;
    txt += `• 🟢 *Perícias Marcadas:* ${marcadas} (${taxa}%)\n`;
    txt += `• 🟡 *Perícias Pendentes:* ${pendentes} (${100 - taxa}%)\n\n`;
    txt += `⚖️ *POR VARA FEDERAL:*\n`;
    Object.keys(varasMap).sort().forEach((v) => {
      txt += `• *${v}:* ${varasMap[v].tot} vagas (${varasMap[v].m} marcadas / ${varasMap[v].p} pendentes)\n`;
    });
    txt += `\n_Relatório gerado em ${new Date().toLocaleDateString("pt-BR")} via Maestro PJe Mobile_`;

    return txt;
  }

  window.copiarResumoWhatsApp = function () {
    const txt = gerarTextoResumoWhatsApp();
    navigator.clipboard.writeText(txt).then(() => {
      mostrarToast("Resumo copiado para a Área de Transferência!", "success");
    }).catch(() => {
      alert("Resumo:\n\n" + txt);
    });
  };

  window.compartilharWhatsAppDireto = function () {
    const txt = encodeURIComponent(gerarTextoResumoWhatsApp());
    window.open(`https://api.whatsapp.com/send?text=${txt}`, "_blank");
  };

  window.abrirRelatorioRapido = function () {
    window.trocarAba("tabRelatorios");
    window.gerarRelatorioPdf("filtrado");
  };

  // =========================================================================
  // 10B. MODAIS: DIRETÓRIO DE PERITOS & CONFIGURAÇÕES DA SESSÃO
  // =========================================================================
  function abrirModalPeritos() {
    const modal = document.getElementById("modalPeritosMobile");
    if (!modal) return;
    renderizarDiretorioPeritos();
    modal.classList.add("open");
  }

  function fecharModalPeritos() {
    document.getElementById("modalPeritosMobile")?.classList.remove("open");
  }

  function renderizarDiretorioPeritos() {
    const listaEl = document.getElementById("listaPeritosModal");
    const lblTotal = document.getElementById("lblTotalPeritosModal");
    if (!listaEl) return;

    const busca = removerAcentosLowerMobile(document.getElementById("filtroBuscaPeritosModal")?.value || "");
    const mapa = new Map();

    (bancoPeritosMobile || []).forEach((p) => {
      if (!p || !p.nome) return;
      const k = removerAcentosLowerMobile(p.nome);
      mapa.set(k, {
        nome: p.nome,
        especialidade: p.especialidade || p.atuacao || "",
        local: p.atendeFora ? (p.localExternoPadrao || "Clínica Própria") : "Justiça Federal",
        endereco: p.endereco || "",
        procsPorPauta: p.procsPorPauta || p.padraoPauta?.vagasManha || "",
        intervaloMin: p.intervaloMin || "",
        pautasCount: 0,
        pendentesCount: 0
      });
    });

    (todasPautas || []).forEach((p) => {
      if (!p || !p.peritoNome) return;
      const k = removerAcentosLowerMobile(p.peritoNome);
      if (!mapa.has(k)) {
        mapa.set(k, {
          nome: p.peritoNome,
          especialidade: p.especialidade || "",
          local: p.local || "Justiça Federal",
          endereco: p.endereco || "",
          procsPorPauta: p.quantidade || p.vagas || "",
          intervaloMin: p.intervaloMin || "",
          pautasCount: 0,
          pendentesCount: 0
        });
      }
      const reg = mapa.get(k);
      reg.pautasCount++;
      if (ehSituacaoPendente(p.situacao)) reg.pendentesCount++;
      if (!reg.especialidade && p.especialidade) reg.especialidade = p.especialidade;
      if (!reg.endereco && p.endereco) reg.endereco = p.endereco;
    });

    const itens = Array.from(mapa.values())
      .filter((item) => {
        if (!busca) return true;
        const hay = removerAcentosLowerMobile(`${item.nome} ${item.especialidade} ${item.local} ${item.endereco}`);
        return hay.includes(busca);
      })
      .sort((a, b) => a.nome.localeCompare(b.nome, "pt-BR"));

    if (lblTotal) lblTotal.textContent = `${itens.length} perito(s) encontrado(s)`;

    if (itens.length === 0) {
      listaEl.innerHTML = '<div class="text-sm text-muted" style="text-align:center;padding:20px;">Nenhum perito localizado.</div>';
      return;
    }

    listaEl.innerHTML = itens.map((item) => `
      <div class="perito-dir-card">
        <div class="perito-dir-top">
          <div class="perito-dir-nome">${escapeHtml(item.nome)}</div>
          <span class="badge-count ${item.pendentesCount > 0 ? "badge-count-yellow" : "badge-count-green"}">
            ${item.pautasCount} pauta(s)${item.pendentesCount > 0 ? ` • ${item.pendentesCount} pend.` : ""}
          </span>
        </div>
        <div class="perito-dir-meta">
          ${item.especialidade ? `🩺 ${escapeHtml(item.especialidade)}<br>` : ""}
          📍 ${escapeHtml(item.local)}${item.endereco ? ` — ${escapeHtml(item.endereco)}` : ""}
          ${item.procsPorPauta ? `<br>📋 Padrão: ${escapeHtml(item.procsPorPauta)} vagas${item.intervaloMin ? ` • ${escapeHtml(item.intervaloMin)} min` : ""}` : ""}
        </div>
        <button type="button" class="btn btn-outline btn-sm" data-ver-pautas-perito="${escapeHtml(item.nome)}">🔍 Ver pautas na Lista ➔</button>
      </div>
    `).join("");
  }

  function abrirModalConfig() {
    const modal = document.getElementById("modalConfigMobile");
    if (!modal || !sessaoUsuario) return;

    aplicarTemaMobile(temaAtualMobile);

    const inpChave = document.getElementById("cfgChaveNuvem");
    const chkLembrar = document.getElementById("chkCfgLembrarChave");
    const infoBox = document.getElementById("cfgInfoSistema");
    if (inpChave) inpChave.value = obterChaveNuvemSessao();
    if (chkLembrar) {
      try {
        chkLembrar.checked = Boolean(localStorage.getItem("maestro_mobile_key_saved"));
      } catch (e) {
        chkLembrar.checked = false;
      }
    }

    if (infoBox) {
      const hEsc = ultimaSyncEscalaTs ? new Date(ultimaSyncEscalaTs).toLocaleString("pt-BR") : "Ainda não sincronizado";
      const hPje = ultimaSyncPautaPjeTs ? new Date(ultimaSyncPautaPjeTs).toLocaleString("pt-BR") : "Sem base PJe";
      infoBox.innerHTML =
        `<div><b>Subseção:</b> ${escapeHtml(sessaoUsuario.subsecaoNome || sessaoUsuario.subsecaoId)}</div>` +
        `<div><b>Projeto Firebase:</b> ${escapeHtml(sessaoUsuario.projectId || "Local")}</div>` +
        `<div><b>Perfil / Varas:</b> ${escapeHtml(sessaoUsuario.role)} (${escapeHtml(obterLabelEscopoVaras())})</div>` +
        `<div><b>Última Sync Escala:</b> ${escapeHtml(hEsc)}</div>` +
        `<div><b>Última Sync Pauta PJe:</b> ${escapeHtml(hPje)}</div>` +
        `<div><b>Versão PWA:</b> Maestro PJe Mobile v2.5 (SW v10)</div>`;
    }

    modal.classList.add("open");
  }

  function fecharModalConfig() {
    document.getElementById("modalConfigMobile")?.classList.remove("open");
  }

  function aplicarCodigoConexaoNoModalConfig() {
    const inp = document.getElementById("cfgCodigoConexao");
    let raw = String(inp?.value || "").trim();
    if (!raw) {
      mostrarToast("Cole o código MAESTRO::... antes de aplicar.", "warn");
      return;
    }
    if (raw.startsWith("MAESTRO::")) raw = raw.slice("MAESTRO::".length);
    try {
      const payload = JSON.parse(decodeURIComponent(escape(atob(raw))));
      if (!payload || !payload.p) throw new Error("Project ID ausente no código.");
      if (sessaoUsuario) {
        sessaoUsuario.projectId = payload.p;
        if (payload.s && SUBSECOES_MAP[payload.s] && obterSubsecoesAutorizadasSessao(sessaoUsuario).includes(payload.s)) {
          sessaoUsuario.subsecaoId = payload.s;
          sessaoUsuario.subsecaoNome = SUBSECOES_MAP[payload.s].nome;
        }
        localStorage.setItem("maestro_mobile_session", JSON.stringify(sessaoUsuario));
      }
      if (payload.k) {
        const lembrar = Boolean(document.getElementById("chkCfgLembrarChave")?.checked);
        salvarChaveNuvemSessao(payload.k, lembrar);
        const cfgChave = document.getElementById("cfgChaveNuvem");
        if (cfgChave) cfgChave.value = payload.k;
      }
      if (inp) inp.value = "";
      aplicarEscopoSessaoNaUI();
      fecharModalConfig();
      mostrarToast("Parâmetros atualizados! Sincronizando...", "success");
      window.sincronizarPautas(payload.k || obterChaveNuvemSessao());
    } catch (err) {
      mostrarToast("Código inválido: " + err.message, "error", 4000);
    }
  }

  function salvarChaveNoModalConfig() {
    const chave = String(document.getElementById("cfgChaveNuvem")?.value || "").trim();
    const lembrar = Boolean(document.getElementById("chkCfgLembrarChave")?.checked);
    if (!chave) {
      mostrarToast("Informe a chave AES-256 antes de salvar.", "warn");
      return;
    }
    salvarChaveNuvemSessao(chave, lembrar);
    fecharModalConfig();
    mostrarToast("Chave AES atualizada. Sincronizando dados...", "success");
    window.sincronizarPautas(chave);
  }

  async function limparCachePwaERecarregar() {
    try {
      if ("caches" in window) {
        const keys = await caches.keys();
        await Promise.all(keys.map((k) => caches.delete(k)));
      }
      if ("serviceWorker" in navigator) {
        const regs = await navigator.serviceWorker.getRegistrations();
        await Promise.all(regs.map((r) => r.unregister()));
      }
    } catch (e) {}
    window.location.reload();
  }

  // =========================================================================
  // 11. NAVEGAÇÃO DE ABAS
  // =========================================================================
  window.trocarAba = function (tabId) {
    if (tabId === "tabWhatsapp" && !podeEnviarPautasNaSessao()) {
      alert("👁️ Seu perfil é Somente Leitura e não possui permissão para importar pautas.");
      return;
    }
    document.querySelectorAll(".tab-content").forEach((c) => c.classList.remove("active"));
    document.querySelectorAll(".main-tabs .tab-btn").forEach((b) => b.classList.remove("active"));

    const tab = document.getElementById(tabId);
    const btn = document.querySelector(`.main-tabs .tab-btn[data-tab='${tabId}']`);

    if (tab) tab.classList.add("active");
    if (btn) btn.classList.add("active");
    if (tabId === "tabPorDia") renderizarAbaPorDia();
    if (tabId === "tabRelatorios") atualizarResumoFiltroRelatorio();
  };

  // Service Worker apenas em origem HTTP/HTTPS (atualização discreta sem interromper edição)
  if ("serviceWorker" in navigator && (window.location.protocol === "https:" || window.location.protocol === "http:")) {
    const exibirBannerAtualizacaoPwa = () => {
      const banner = document.getElementById("bannerAtualizacaoPwa");
      if (banner) banner.style.display = "flex";
    };

    navigator.serviceWorker.addEventListener("controllerchange", () => {
      exibirBannerAtualizacaoPwa();
    });

    window.addEventListener("load", () => {
      navigator.serviceWorker.register("./sw.js")
        .then((reg) => {
          console.log("[Maestro Mobile] Service Worker registrado:", reg.scope);
          reg.addEventListener("updatefound", () => {
            const newWorker = reg.installing;
            if (!newWorker) return;
            newWorker.addEventListener("statechange", () => {
              if (newWorker.state === "installed" && navigator.serviceWorker.controller) {
                exibirBannerAtualizacaoPwa();
              }
            });
          });
        })
        .catch((err) => console.warn("[Maestro Mobile] Falha no Service Worker:", err));
    });
  }
})();