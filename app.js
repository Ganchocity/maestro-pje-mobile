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
  const agoraInicial = new Date();
  let sessaoUsuario = null; // { subsecaoId, subsecaoNome, usuarioCpf, role, projectId }
  let todasPautas = [];
  let pautasFiltradas = [];
  let bancoPeritosMobile = [];
  let pautasParaImportar = [];

  let anoAtivo = agoraInicial.getFullYear();
  let mesAtivo = agoraInicial.getMonth();
  let filtroSituacaoAtivo = "todos";
  let textoCompartilhadoPendente = null;

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

  // =========================================================================
  // 3. INICIALIZAÇÃO, EVENTOS (CSP-SAFE) E GERENCIAMENTO DE SESSÃO
  // =========================================================================
  document.addEventListener("DOMContentLoaded", () => {
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

    // Header
    document.getElementById("btnHeaderSyncPautas")?.addEventListener("click", () => window.sincronizarPautas());
    document.getElementById("btnHeaderLogout")?.addEventListener("click", () => window.fazerLogout());

    // Navegação de abas
    document.querySelectorAll(".main-tabs .tab-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        const tabId = btn.getAttribute("data-tab");
        if (tabId) window.trocarAba(tabId);
      });
    });

    // Visão Geral
    document.getElementById("btnMesAnterior")?.addEventListener("click", () => window.alterarMes(-1));
    document.getElementById("btnMesProximo")?.addEventListener("click", () => window.alterarMes(1));
    document.getElementById("btnQuickWhatsapp")?.addEventListener("click", () => window.trocarAba("tabWhatsapp"));
    document.getElementById("btnQuickRelatorio")?.addEventListener("click", () => window.abrirRelatorioRapido());
    document.getElementById("btnQuickVerPautas")?.addEventListener("click", () => window.trocarAba("tabPautas"));

    // Pautas (filtros)
    document.getElementById("filtroTexto")?.addEventListener("input", () => window.filtrarPautas());
    document.getElementById("btnLimparBusca")?.addEventListener("click", () => window.limparBusca());
    document.querySelectorAll(".filter-pills .pill").forEach((pill) => {
      pill.addEventListener("click", () => {
        const filtro = pill.getAttribute("data-filtro") || "todos";
        window.setFiltroSituacao(filtro, pill);
      });
    });
    document.getElementById("filtroVara")?.addEventListener("change", () => window.filtrarPautas());
    document.getElementById("filtroCategoria")?.addEventListener("change", () => window.filtrarPautas());

    // Aba WhatsApp
    document.getElementById("btnColarWhatsAppMobile")?.addEventListener("click", colarTextoWhatsApp);
    document.getElementById("btnExemploTextoWpp")?.addEventListener("click", preencherExemploWhatsApp);
    document.getElementById("btnLimparTextoWpp")?.addEventListener("click", limparEntradaWhatsApp);
    document.getElementById("btnInterpretarWpp")?.addEventListener("click", interpretarTextoWhatsApp);
    document.getElementById("btnAddPautaManualWpp")?.addEventListener("click", adicionarPautaManualWpp);
    document.getElementById("btnSelecionarTodasImportWpp")?.addEventListener("click", alternarSelecaoTodasImportWpp);
    document.getElementById("btnEnviarPautasNuvemWpp")?.addEventListener("click", enviarPautasImportadasParaPlanilha);
    document.getElementById("btnReenviarFilaOffline")?.addEventListener("click", reenviarFilaOffline);

    // Edição inline e delegação de eventos nos cards de importação WhatsApp
    const listaCardsWpp = document.getElementById("listaCardsImportWpp");
    if (listaCardsWpp) {
      listaCardsWpp.addEventListener("input", onInputCardImportacaoWpp);
      listaCardsWpp.addEventListener("change", onChangeCardImportacaoWpp);
      listaCardsWpp.addEventListener("click", onClickCardImportacaoWpp);
    }

    // Relatórios
    document.getElementById("btnRelPdfMes")?.addEventListener("click", () => window.gerarRelatorioPdf("mes"));
    document.getElementById("btnRelPdfCompleto")?.addEventListener("click", () => window.gerarRelatorioPdf("completo"));
    document.getElementById("btnRelCsv")?.addEventListener("click", () => window.exportarRelatorioCsv());
    document.getElementById("btnRelCopiarWpp")?.addEventListener("click", () => window.copiarResumoWhatsApp());
    document.getElementById("btnRelEnviarWpp")?.addEventListener("click", () => window.compartilharWhatsAppDireto());
    document.getElementById("btnImprimirPreviewRelatorio")?.addEventListener("click", () => window.print());
    document.getElementById("btnFecharPreviewRelatorio")?.addEventListener("click", () => window.fecharPreviewRelatorio());

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
        try {
          const cleanUrl = window.location.pathname + window.location.hash;
          window.history.replaceState({}, document.title, cleanUrl);
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
        if (sessaoUsuario && sessaoUsuario.subsecaoId) {
          iniciarAplicativoComSessao(obterChaveNuvemSessao());
          return;
        }
      }
    } catch (e) {
      console.warn("Erro ao carregar sessão anterior:", e);
    }
    exibirTelaLogin();
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
    const lembrarChave = document.getElementById("chkLembrarChaveMobile")?.checked !== false;
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

      const projectIdEfetivo = txtProj || "maestro-pje-trf5";
      const validacao = await validarPinGovernança(txtPin, txtCpf, selSub, projectIdEfetivo);
      if (!validacao.valido) {
        exibirErroLogin(validacao.erro || "PIN de ativação incorreto. Use o mesmo PIN configurado no Maestro PJe do seu computador.");
        return;
      }

      limparLockoutMobile();

      const isMaster = validacao.role === "Master";
      const subInfo = SUBSECOES_MAP[selSub] || { id: selSub, nome: selSub, varas: [] };

      if (txtChave) {
        salvarChaveNuvemSessao(txtChave, lembrarChave);
      }

      sessaoUsuario = {
        subsecaoId: selSub,
        subsecaoNome: subInfo.nome,
        subsecaoDesc: subInfo.descricao,
        usuarioCpf: txtCpf,
        role: isMaster ? "Master" : "Editor",
        subsecoesPermitidas: isMaster ? ["*"] : [selSub],
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
          const resp = await fetch(url, { method: "GET" });
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
              cpfsBloqueadosJson: f.cpfsBloqueadosJson?.stringValue || "[]"
            };
            try {
              localStorage.setItem(cacheKey, JSON.stringify({
                pinHash: govDoc.pinHash,
                pinSalt: govDoc.pinSalt,
                masterHash: govDoc.masterHash,
                masterSalt: govDoc.masterSalt,
                cpfsBloqueadosJson: govDoc.cpfsBloqueadosJson
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
      try {
        const bloqueados = Array.isArray(govDoc.cpfsBloqueados)
          ? govDoc.cpfsBloqueados
          : JSON.parse(govDoc.cpfsBloqueadosJson || "[]");
        if (cpfLimpo.length === 11 && Array.isArray(bloqueados) && bloqueados.includes(cpfLimpo)) {
          return { valido: false, erro: "Este CPF encontra-se bloqueado na governança institucional." };
        }
      } catch (e) {}

      if (govDoc.masterHash && govDoc.masterSalt) {
        if (await verificarHashPBKDF2Mobile(clean, govDoc.masterHash, govDoc.masterSalt)) {
          return { valido: true, role: "Master" };
        }
      } else if (govDoc.senhaMaster && clean === govDoc.senhaMaster.trim()) {
        return { valido: true, role: "Master" };
      }

      if (govDoc.pinHash && govDoc.pinSalt) {
        if (await verificarHashPBKDF2Mobile(clean, govDoc.pinHash, govDoc.pinSalt)) {
          return { valido: true, role: "Editor" };
        }
        return { valido: false, erro: registrarFalhaLoginMobile() };
      } else if (govDoc.pinAtivacao) {
        if (clean === govDoc.pinAtivacao.trim()) {
          return { valido: true, role: "Editor" };
        }
        return { valido: false, erro: registrarFalhaLoginMobile() };
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
      localStorage.removeItem("maestro_mobile_session");
      localStorage.removeItem("maestro_mobile_key_saved");
      try { sessionStorage.removeItem("maestro_mobile_key"); } catch (e) {}
      sessaoUsuario = null;
      todasPautas = [];
      bancoPeritosMobile = [];
      pautasParaImportar = [];
      exibirTelaLogin();
    }
  };

  // =========================================================================
  // 5. INICIALIZAÇÃO DA ÁREA LOGADA & RESTRIÇÃO DE ESCOPO
  // =========================================================================
  function iniciarAplicativoComSessao(chaveTemporaria = "") {
    if (!sessaoUsuario) return;

    document.getElementById("screenLogin").classList.remove("active");
    document.getElementById("screenApp").classList.add("active");

    const subInfo = SUBSECOES_MAP[sessaoUsuario.subsecaoId] || { nome: sessaoUsuario.subsecaoNome, varas: [] };

    document.getElementById("lblNomeSubsecao").textContent = subInfo.nome;
    document.getElementById("lblUsuarioNome").textContent = sessaoUsuario.usuarioCpf;
    document.getElementById("lblPerfilRole").textContent = sessaoUsuario.role;

    const badgePerm = document.getElementById("badgePermissaoEnvioWpp");
    if (badgePerm) {
      badgePerm.textContent = `${sessaoUsuario.role} (${subInfo.nome})`;
    }

    const escopoMsg = sessaoUsuario.role === "Master"
      ? `👑 Acesso Master (Subseção Ativa: ${subInfo.nome})`
      : `🔒 Restrito à Subseção de ${subInfo.nome} (${subInfo.varas ? subInfo.varas.map((v) => v + "ª").join(", ") : "Varas Cadastradas"})`;
    document.getElementById("lblEscopoRestricao").textContent = escopoMsg;
    document.getElementById("lblRelatorioSubsecao").textContent = subInfo.nome;
    document.getElementById("lblSubsecaoEscopoFiltro").textContent = "Subseção: " + subInfo.nome;

    popularFiltroVaras(subInfo.varas || []);
    popularVaraPadraoWpp(subInfo.varas || []);
    carregarBancoPeritosCache(sessaoUsuario.subsecaoId);
    atualizarBannerFilaOffline();

    window.sincronizarPautas(chaveTemporaria);

    if (textoCompartilhadoPendente) {
      const recebido = textoCompartilhadoPendente;
      textoCompartilhadoPendente = null;
      window.trocarAba("tabWhatsapp");
      const txtEl = document.getElementById("txtConversaWhatsApp");
      if (txtEl) txtEl.value = recebido;
      interpretarTextoWhatsApp();
    }
  }

  function popularFiltroVaras(varas) {
    const select = document.getElementById("filtroVara");
    if (!select) return;
    select.innerHTML = '<option value="">Todas as Varas</option>';
    varas.forEach((v) => {
      const opt = document.createElement("option");
      opt.value = v;
      opt.textContent = `${v}ª Vara Federal`;
      select.appendChild(opt);
    });
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
    if (lista.includes("19")) sel.value = "19";
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
  window.sincronizarPautas = async function (chaveExplicita = "") {
    if (!sessaoUsuario) return;

    mostrarFeedbackCarregamento(true);

    try {
      let pautasCarregadas = [];
      let peritosCarregados = [];
      const chaveNuvem = chaveExplicita || obterChaveNuvemSessao();
      const subId = sessaoUsuario.subsecaoId;

      // 1. Tenta carregar do Firestore se houver Project ID configurado
      if (sessaoUsuario.projectId && sessaoUsuario.projectId.trim() && !sessaoUsuario.projectId.includes("exemplo")) {
        try {
          const url = `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(sessaoUsuario.projectId)}/databases/(default)/documents/subsecoes/${encodeURIComponent(subId)}`;
          const resp = await fetch(url, { method: "GET", cache: "no-cache" });
          if (resp.ok) {
            const doc = await resp.json();
            const fields = doc.fields || {};

            const parsedPeritos = await decodificarOuDecifrarDadoNuvemMobile(
              fields.bancoPeritosJson?.stringValue,
              fields.ivPeritos?.stringValue || fields.iv?.stringValue,
              fields.saltPeritos?.stringValue || fields.salt?.stringValue,
              chaveNuvem
            );
            if (Array.isArray(parsedPeritos) && parsedPeritos.length > 0) {
              peritosCarregados = parsedPeritos;
            }

            const parsedEscala = await decodificarOuDecifrarDadoNuvemMobile(
              fields.escalaPautasJson?.stringValue,
              fields.ivEscala?.stringValue || fields.iv?.stringValue,
              fields.saltEscala?.stringValue || fields.salt?.stringValue,
              chaveNuvem
            );
            if (Array.isArray(parsedEscala) && parsedEscala.length > 0) {
              pautasCarregadas = converterPautasFirestore(parsedEscala);
            }
          }
        } catch (eNuvem) {
          console.warn("Nuvem indisponível ou chave AES divergente, recorrendo à base local:", eNuvem.message);
        }
      }

      // 2. Fallback para chrome.storage.local se aberto como janela da extensão
      if (ehAmbienteExtensaoChrome()) {
        try {
          const store = await chrome.storage.local.get([`escalaPautas_${subId}`, `bancoPeritos_${subId}`]);
          if ((!pautasCarregadas || pautasCarregadas.length === 0) && Array.isArray(store[`escalaPautas_${subId}`])) {
            pautasCarregadas = converterPautasFirestore(store[`escalaPautas_${subId}`]);
          }
          if ((!peritosCarregados || peritosCarregados.length === 0) && Array.isArray(store[`bancoPeritos_${subId}`])) {
            peritosCarregados = store[`bancoPeritos_${subId}`];
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
        pautasCarregadas = carregarPautasLocaisSubsecao(subId);
      }

      todasPautas = aplicarFiltroRestritoSubsecao(pautasCarregadas, subId);
      salvarCacheLocal(subId, todasPautas);
      atualizarInterfaceCompleta();
    } catch (err) {
      console.error("Erro na sincronização:", err);
      alert("Erro ao sincronizar pautas: " + err.message);
    } finally {
      mostrarFeedbackCarregamento(false);
    }
  };

  function carregarPautasLocaisSubsecao(subId) {
    try {
      const cache = localStorage.getItem(`maestro_pautas_${subId}`);
      if (cache) {
        const parsed = JSON.parse(cache);
        if (Array.isArray(parsed) && parsed.length > 0) return parsed;
      }
    } catch (e) {}

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
        const varaPauta = String(p.vara).replace(/\D/g, "");
        if (varaPauta && !subInfo.varas.includes(varaPauta)) {
          return false;
        }
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
    const v = String(p?.vara || "").toLowerCase().trim();
    const h = String(p?.horaInicio || p?.hora || "").trim();
    return `${d}_${n}_${v}_${h}`;
  }

  function mesclarListasEscala(listaBase, listaNovas) {
    const base = Array.isArray(listaBase) ? listaBase : [];
    const novas = Array.isArray(listaNovas) ? listaNovas : [];
    const mapa = new Map();

    base.forEach((item) => {
      if (!item) return;
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
      const k = gerarChaveUnicaPauta(nova);
      if (k && mapa.has(k)) {
        const existente = mapa.get(k);
        mapa.set(k, {
          ...existente,
          ...nova,
          id: existente.id || nova.id
        });
        atualizadas++;
      } else {
        const keyFinal = (k && k !== "___") ? k : String(nova.id || `mob_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`);
        mapa.set(keyFinal, { ...nova });
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

  function interpretarTextoWhatsApp() {
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
    const subInfo = SUBSECOES_MAP[subId] || { varas: ["19"] };
    const varaPadrao = document.getElementById("selVaraPadraoWpp")?.value || subInfo.varas[0] || "19";
    const situacaoPadrao = document.getElementById("selSituacaoPadraoWpp")?.value || "Não marcado";

    const resultado = Parser.parsearConversaWhatsApp(rawText, {
      bancoPeritos: bancoPeritosMobile,
      varaPadrao,
      subsecaoVaras: subInfo.varas,
      situacaoPadrao
    });

    pautasParaImportar = (resultado.pautas || []).map((p) => {
      if (!p._meta) p._meta = {};
      if (typeof p._meta.selecionada !== "boolean") p._meta.selecionada = true;
      return p;
    });

    renderizarCardsImportacaoWpp(resultado.avisos || []);

    const msgBox = document.getElementById("msgResultadoImportWpp");
    if (msgBox) msgBox.style.display = "none";

    const areaPrev = document.getElementById("areaPreviewImportWpp");
    if (areaPrev && pautasParaImportar.length > 0) {
      areaPrev.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  function adicionarPautaManualWpp() {
    if (!Parser) return;
    const subId = sessaoUsuario?.subsecaoId || "sobral";
    const subInfo = SUBSECOES_MAP[subId] || { varas: ["19"] };
    const varaPadrao = document.getElementById("selVaraPadraoWpp")?.value || subInfo.varas[0] || "19";
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
      p._meta.selecionada = novoEstado;
    });
    renderizarCardsImportacaoWpp();
  }

  function verificarConflitosImportacao(itens) {
    const chavesExistentes = new Set(todasPautas.map(gerarChaveUnicaPauta));
    const subId = sessaoUsuario?.subsecaoId || "sobral";
    const varasSub = (SUBSECOES_MAP[subId]?.varas) || ["18", "19", "31"];

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

      const pendencias = Parser ? Parser.calcularPendenciasPauta(p) : [];
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
    const varasBase = Array.from(new Set([...(SUBSECOES_MAP[subId]?.varas || ["18", "19", "31"])]));

    listaEl.innerHTML = pautasParaImportar.map((p, idx) => {
      const diag = diagnosticos[idx];
      const selecionada = p._meta?.selecionada !== false;
      const ehFora = Parser ? Parser.ehLocalFora(p.local) : false;

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

      const varasSelectOpts = Array.from(new Set([...varasBase, String(p.vara || "").trim()].filter(Boolean)));
      const optionsVaraHtml = varasSelectOpts.map((v) =>
        `<option value="${escapeHtml(v)}" ${String(p.vara) === String(v) ? "selected" : ""}>${escapeHtml(v)}ª Vara Federal</option>`
      ).join("");

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
              <select data-index="${idx}" data-field="vara">${optionsVaraHtml}</select>
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
          item.local = "Clínica Própria";
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
        salvarChaveNuvemSessao(chaveNuvem, true);
      }

      const urlGet = `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(sessaoUsuario.projectId)}/databases/(default)/documents/subsecoes/${encodeURIComponent(subId)}`;
      const respGet = await fetch(urlGet, { method: "GET", cache: "no-cache" });

      let escalaNuvemAtual = [];
      if (respGet.ok) {
        const doc = await respGet.json();
        const fields = doc.fields || {};
        if (fields.escalaPautasJson?.stringValue) {
          const dec = await decodificarOuDecifrarDadoNuvemMobile(
            fields.escalaPautasJson.stringValue,
            fields.ivEscala?.stringValue || fields.iv?.stringValue,
            fields.saltEscala?.stringValue || fields.salt?.stringValue,
            chaveNuvem
          );
          if (Array.isArray(dec)) {
            escalaNuvemAtual = dec;
          }
        }
      } else if (respGet.status !== 404) {
        throw new Error(`Falha ao consultar a nuvem (HTTP ${respGet.status}).`);
      }

      const mesclado = mesclarListasEscala(escalaNuvemAtual, pautasCanonic);
      resultadoMergeFinal = mesclado;

      const escalaStr = JSON.stringify(mesclado.listaFinal);
      const estimativaCifrado = Math.ceil(escalaStr.length * 1.34);
      const opcoesCripto = estimativaCifrado >= 400000
        ? { comprimirGzip: true }
        : { autoGzipAcimaBytes: 131072 };

      const resEscala = await cifrarTextoAESMobile(escalaStr, chaveNuvem, opcoesCripto);
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

      const payloadPatch = {
        fields: {
          subsecaoId: { stringValue: subId },
          encrypted: { booleanValue: true },
          escalaPautasJson: { stringValue: resEscala.data },
          ivEscala: { stringValue: resEscala.iv },
          saltEscala: { stringValue: resEscala.salt },
          timestamp: { integerValue: String(now) },
          atualizadoPor: { stringValue: `Maestro Mobile (${sessaoUsuario.usuarioCpf || "WhatsApp"})` }
        }
      };

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
    if (sessaoUsuario.role !== "Master" && sessaoUsuario.role !== "Editor") {
      alert("🔒 Seu usuário não possui permissão de Editor ou Master para enviar pautas à planilha.");
      return;
    }

    const selecionadas = pautasParaImportar.filter((p) => p._meta?.selecionada !== false);
    if (selecionadas.length === 0) {
      alert("⚠️ Selecione ao menos 1 pauta para enviar para a planilha.");
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
    const subId = sessaoUsuario.subsecaoId;
    const fila = carregarFilaOffline(subId);
    if (fila.length === 0) {
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
    atualizarKpisDoMes();
    window.filtrarPautas();
  }

  function atualizarLabelPeriodo() {
    document.getElementById("lblMesAtual").textContent = MESES_NOMES[mesAtivo];
    document.getElementById("lblAnoAtual").textContent = anoAtivo;
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
    atualizarInterfaceCompleta();
  };

  function obterPautasDoMesAtivo() {
    const mesIso = `${anoAtivo}-${String(mesAtivo + 1).padStart(2, "0")}`;
    return todasPautas.filter((p) => p.data && p.data.startsWith(mesIso));
  }

  function atualizarKpisDoMes() {
    const pautasMes = obterPautasDoMesAtivo();

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

      const v = p.vara ? `${p.vara}ª Vara` : "Vara Única";
      if (!varasMap[v]) varasMap[v] = { marcadas: 0, pendentes: 0, total: 0 };
      varasMap[v].total += vagas;
      if (p.situacao === "Marcado") varasMap[v].marcadas += vagas;
      else if (ehSituacaoPendente(p.situacao)) varasMap[v].pendentes += vagas;
    });

    const taxa = totalVagas > 0 ? Math.round((marcadas / totalVagas) * 100) : 0;

    document.getElementById("kpiTotalVagas").textContent = totalVagas;
    document.getElementById("kpiTotalPautas").textContent = `${pautasMes.length} pautas em ${MESES_NOMES[mesAtivo]}`;
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

    renderizarVarasKpi(varasMap);
  }

  function renderizarVarasKpi(varasMap) {
    const container = document.getElementById("listaVarasKpi");
    container.innerHTML = "";

    const keys = Object.keys(varasMap);
    document.getElementById("lblQtdVaras").textContent = `${keys.length} Varas Ativas`;

    if (keys.length === 0) {
      container.innerHTML = '<div class="text-sm text-muted" style="padding: 10px; text-align: center;">Nenhuma perícia agendada para este mês nesta subseção.</div>';
      return;
    }

    keys.sort().forEach((vara) => {
      const info = varasMap[vara];
      const div = document.createElement("div");
      div.className = "vara-row";
      div.innerHTML = `
        <span class="vara-title">${escapeHtml(vara)}</span>
        <div class="vara-counts">
          <span class="badge-count badge-count-green" title="Marcadas">${escapeHtml(info.marcadas)} marcadas</span>
          <span class="badge-count badge-count-yellow" title="Pendentes">${escapeHtml(info.pendentes)} pendentes</span>
          <strong title="Total de Vagas">(${escapeHtml(info.total)})</strong>
        </div>
      `;
      container.appendChild(div);
    });
  }

  // =========================================================================
  // 9. LISTAGEM & FILTROS DAS PAUTAS
  // =========================================================================
  window.setFiltroSituacao = function (filtro, elem) {
    filtroSituacaoAtivo = filtro;
    document.querySelectorAll(".filter-pills .pill").forEach((p) => p.classList.remove("active"));
    if (elem) elem.classList.add("active");
    window.filtrarPautas();
  };

  window.limparBusca = function () {
    const input = document.getElementById("filtroTexto");
    input.value = "";
    document.getElementById("btnLimparBusca").style.display = "none";
    window.filtrarPautas();
  };

  window.filtrarPautas = function () {
    const txtBusca = (document.getElementById("filtroTexto").value || "").toLowerCase().trim();
    const varaFiltro = document.getElementById("filtroVara").value;
    const catFiltro = document.getElementById("filtroCategoria").value;
    const btnLimpar = document.getElementById("btnLimparBusca");

    if (btnLimpar) btnLimpar.style.display = txtBusca ? "block" : "none";

    let countTotal = 0;
    let countMarc = 0;
    let countPend = 0;

    todasPautas.forEach((p) => {
      countTotal++;
      if (p.situacao === "Marcado") countMarc++;
      else if (ehSituacaoPendente(p.situacao)) countPend++;
    });

    document.getElementById("pillCountTodos").textContent = countTotal;
    document.getElementById("pillCountMarcadas").textContent = countMarc;
    document.getElementById("pillCountPendentes").textContent = countPend;

    pautasFiltradas = todasPautas.filter((p) => {
      if (filtroSituacaoAtivo === "marcado" && p.situacao !== "Marcado") return false;
      if (filtroSituacaoAtivo === "pendente" && !ehSituacaoPendente(p.situacao)) return false;
      if (varaFiltro && String(p.vara) !== String(varaFiltro)) return false;
      if (catFiltro && p.categoria !== catFiltro) return false;
      if (txtBusca) {
        const conteudo = `${p.peritoNome} ${p.especialidade} ${p.vara} ${p.data} ${p.local} ${p.endereco || ""} ${p.observacoes || ""}`.toLowerCase();
        if (!conteudo.includes(txtBusca)) return false;
      }
      return true;
    });

    pautasFiltradas.sort((a, b) => (a.data || "").localeCompare(b.data || ""));
    renderizarCardsPautas();
  };

  function renderizarCardsPautas() {
    const container = document.getElementById("listaPautasCards");
    const lblCount = document.getElementById("lblQtdPautasFiltradas");
    container.innerHTML = "";

    lblCount.textContent = `Exibindo ${pautasFiltradas.length} pautas`;

    if (pautasFiltradas.length === 0) {
      container.innerHTML = `
        <div class="section-card" style="text-align: center; padding: 30px;">
          <div style="font-size: 32px; margin-bottom: 8px;">🔍</div>
          <h5>Nenhuma pauta encontrada</h5>
          <p class="text-sm text-muted">Ajuste os filtros de pesquisa ou importe novas pautas na aba WhatsApp.</p>
        </div>
      `;
      return;
    }

    pautasFiltradas.forEach((p) => {
      const dataFmt = formatarDataBr(p.data);
      const isMarcado = p.situacao === "Marcado";
      const statusClass = isMarcado ? "status-marcado" : "status-pendente";
      const badgeClass = isMarcado ? "status-badge-marcado" : "status-badge-pendente";
      const vagasNum = p.vagas !== undefined ? p.vagas : p.quantidade;
      const horaTxt = p.horaInicio || p.hora || "08:00";
      const obsTxt = p.observacoes || p.observacao || "";

      const card = document.createElement("div");
      card.className = `pauta-card ${statusClass}`;
      card.innerHTML = `
        <div class="pauta-header">
          <div class="pauta-date-badge">
            <span>📅</span>
            <span>${escapeHtml(dataFmt)} • ${escapeHtml(horaTxt)}</span>
          </div>
          <span class="status-badge ${badgeClass}">${escapeHtml(p.situacao)}</span>
        </div>

        <div class="pauta-perito">${escapeHtml(p.peritoNome)}</div>
        <div class="pauta-esp">${escapeHtml(p.especialidade)}</div>

        <div class="pauta-details-grid">
          <div class="detail-item">
            <span>Vara:</span>
            <strong>${escapeHtml(p.vara)}ª Federal</strong>
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
  // 10. GERAÇÃO E EXPORTAÇÃO DE RELATÓRIOS (PDF, CSV E WHATSAPP)
  // =========================================================================
  window.gerarRelatorioPdf = function (tipo) {
    const subInfo = SUBSECOES_MAP[sessaoUsuario.subsecaoId] || { nome: sessaoUsuario.subsecaoNome };
    const lista = tipo === "mes" ? obterPautasDoMesAtivo() : todasPautas;
    const tituloPeriodo = tipo === "mes" ? `${MESES_NOMES[mesAtivo]} de ${anoAtivo}` : "Todas as Pautas Cadastradas";

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
        <td style="text-align: center;">${escapeHtml(p.vara)}ª VF</td>
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
          Subseção Judiciária de ${escapeHtml(subInfo.nome)} • Maestro PJe
        </div>
        <div style="font-size: 11px; color: #64748B; margin-top: 4px;">
          Período: <strong>${escapeHtml(tituloPeriodo)}</strong> • Emitido em: ${new Date().toLocaleDateString("pt-BR")} às ${new Date().toLocaleTimeString("pt-BR")}
        </div>
      </div>

      <div style="display: flex; justify-content: space-between; background: #F8FAFC; border: 1px solid #CBD5E1; padding: 12px; border-radius: 6px; margin-bottom: 16px; font-size: 12px;">
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
          ${linhasHtml}
        </tbody>
      </table>

      <div style="margin-top: 24px; text-align: right; font-size: 10px; color: #64748B;">
        Documento gerado pelo Maestro PJe Mobile • Usuário: ${escapeHtml(sessaoUsuario.usuarioCpf)} (Escopo: ${escapeHtml(subInfo.nome)})
      </div>
    `;

    previewArea.style.display = "block";
    previewArea.scrollIntoView({ behavior: "smooth" });
  };

  window.fecharPreviewRelatorio = function () {
    document.getElementById("areaPreviewRelatorio").style.display = "none";
  };

  window.exportarRelatorioCsv = function () {
    const subInfo = SUBSECOES_MAP[sessaoUsuario.subsecaoId] || { nome: sessaoUsuario.subsecaoNome };
    const lista = obterPautasDoMesAtivo();

    let csv = "\uFEFF";
    csv += "Data;Hora;Perito;Especialidade;Vara;Vagas;Situacao;Local;Endereco;Observacoes;Subsecao\n";

    lista.forEach((p) => {
      const linha = [
        sanitizarCelulaCSV(formatarDataBr(p.data)),
        sanitizarCelulaCSV(p.horaInicio || p.hora || "08:00"),
        sanitizarCelulaCSV(p.peritoNome || ""),
        sanitizarCelulaCSV(p.especialidade || ""),
        sanitizarCelulaCSV(`${p.vara}ª Vara Federal`),
        sanitizarCelulaCSV(p.vagas !== undefined ? p.vagas : (p.quantidade || 1)),
        sanitizarCelulaCSV(p.situacao || "Não marcado"),
        sanitizarCelulaCSV(p.local || ""),
        sanitizarCelulaCSV(p.endereco || ""),
        sanitizarCelulaCSV(p.observacoes || p.observacao || ""),
        sanitizarCelulaCSV(subInfo.nome)
      ].join(";");
      csv += linha + "\n";
    });

    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `Maestro_PJe_Pautas_${sessaoUsuario.subsecaoId}_${MESES_NOMES[mesAtivo]}_${anoAtivo}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  function gerarTextoResumoWhatsApp() {
    const subInfo = SUBSECOES_MAP[sessaoUsuario.subsecaoId] || { nome: sessaoUsuario.subsecaoNome };
    const lista = obterPautasDoMesAtivo();

    let totalVagas = 0;
    let marcadas = 0;
    let pendentes = 0;
    const varasMap = {};

    lista.forEach((p) => {
      const v = Number(p.vagas !== undefined ? p.vagas : p.quantidade) || 1;
      totalVagas += v;
      if (p.situacao === "Marcado") marcadas += v;
      else if (ehSituacaoPendente(p.situacao)) pendentes += v;

      const vNome = `${p.vara}ª VF`;
      if (!varasMap[vNome]) varasMap[vNome] = { m: 0, p: 0, tot: 0 };
      varasMap[vNome].tot += v;
      if (p.situacao === "Marcado") varasMap[vNome].m += v;
      else if (ehSituacaoPendente(p.situacao)) varasMap[vNome].p += v;
    });

    const taxa = totalVagas > 0 ? Math.round((marcadas / totalVagas) * 100) : 0;

    let txt = `⚖️ *MAESTRO PJE - RESUMO DE PAUTAS*\n`;
    txt += `📍 *Subseção:* ${subInfo.nome}\n`;
    txt += `📅 *Período:* ${MESES_NOMES[mesAtivo]}/${anoAtivo}\n\n`;
    txt += `📊 *NÚMEROS GERAIS:*\n`;
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
      alert("✅ Resumo copiado para a Área de Transferência!\n\nAgora você pode colar diretamente no WhatsApp ou e-mail.");
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
    window.gerarRelatorioPdf("mes");
  };

  // =========================================================================
  // 11. NAVEGAÇÃO DE ABAS
  // =========================================================================
  window.trocarAba = function (tabId) {
    document.querySelectorAll(".tab-content").forEach((c) => c.classList.remove("active"));
    document.querySelectorAll(".main-tabs .tab-btn").forEach((b) => b.classList.remove("active"));

    const tab = document.getElementById(tabId);
    const btn = document.querySelector(`.main-tabs .tab-btn[data-tab='${tabId}']`);

    if (tab) tab.classList.add("active");
    if (btn) btn.classList.add("active");
  };

  // Service Worker apenas em origem HTTP/HTTPS (PWA Android; evita aviso em chrome-extension://)
  if ("serviceWorker" in navigator && (window.location.protocol === "https:" || window.location.protocol === "http:")) {
    window.addEventListener("load", () => {
      navigator.serviceWorker.register("./sw.js")
        .then((reg) => console.log("[Maestro Mobile] Service Worker registrado:", reg.scope))
        .catch((err) => console.warn("[Maestro Mobile] Falha no Service Worker:", err));
    });
  }
})();