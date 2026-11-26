/**
 * Maestro PJe Mobile - Interpretador (Parser) de Pautas em Conversas do WhatsApp
 * Converte mensagens copiadas ou compartilhadas do WhatsApp (1 ou múltiplas pautas)
 * para o esquema canônico da planilha Escala & Calendário (escalaPautas).
 */
(function (root) {
  "use strict";

  const MESES_EXTENSO = {
    janeiro: 1, jan: 1,
    fevereiro: 2, fev: 2,
    marco: 3, mar: 3,
    abril: 4, abr: 4,
    maio: 5, mai: 5,
    junho: 6, jun: 6,
    julho: 7, jul: 7,
    agosto: 8, ago: 8,
    setembro: 9, set: 9,
    outubro: 10, out: 10,
    novembro: 11, nov: 11,
    dezembro: 12, dez: 12
  };

  const FERIADOS_PADRAO_JFCE = [
    { data: "2026-01-01", nome: "Confraternização Universal (Ano Novo)", recorrente: true },
    { data: "2026-02-16", nome: "Carnaval (Segunda-feira)", recorrente: false },
    { data: "2026-02-17", nome: "Carnaval (Terça-feira)", recorrente: false },
    { data: "2026-02-18", nome: "Quarta-feira de Cinzas", recorrente: false },
    { data: "2026-03-19", nome: "Dia de São José", recorrente: true },
    { data: "2026-03-25", nome: "Data Magna do Ceará", recorrente: true },
    { data: "2026-04-01", nome: "Semana Santa", recorrente: false },
    { data: "2026-04-02", nome: "Semana Santa", recorrente: false },
    { data: "2026-04-03", nome: "Paixão de Cristo", recorrente: false },
    { data: "2026-04-21", nome: "Tiradentes", recorrente: true },
    { data: "2026-05-01", nome: "Dia do Trabalho", recorrente: true },
    { data: "2026-06-04", nome: "Corpus Christi", recorrente: false },
    { data: "2026-07-05", nome: "Aniversário de Sobral", recorrente: true },
    { data: "2026-08-11", nome: "Dia do Magistrado (Lei 5010)", recorrente: true },
    { data: "2026-09-07", nome: "Independência do Brasil", recorrente: true },
    { data: "2026-10-12", nome: "Nossa Senhora Aparecida", recorrente: true },
    { data: "2026-10-28", nome: "Dia do Servidor Público", recorrente: true },
    { data: "2026-11-01", nome: "Dia de Todos os Santos", recorrente: true },
    { data: "2026-11-02", nome: "Finados", recorrente: true },
    { data: "2026-11-15", nome: "Proclamação da República", recorrente: true },
    { data: "2026-11-20", nome: "Consciência Negra", recorrente: true },
    { data: "2026-12-08", nome: "Dia da Justiça", recorrente: true },
    { data: "2026-12-20", nome: "Recesso Judiciário Forense", recorrente: true },
    { data: "2026-12-25", nome: "Natal", recorrente: true }
  ];

  const MAPA_NOMES_OFICIAIS = {
    "barbara": "Bárbara Duarte de Carvalho",
    "barbara duarte": "Bárbara Duarte de Carvalho",
    "barbara duarte carvalho": "Bárbara Duarte de Carvalho",
    "barbara duarte de carvalho": "Bárbara Duarte de Carvalho",
    "amanda": "Amanda Gadelha Mont Alverne",
    "amanda gadelha": "Amanda Gadelha Mont Alverne",
    "amanda gadelha mont alverne": "Amanda Gadelha Mont Alverne",
    "paulo andre": "Paulo André Moreira Aguiar",
    "paulo andre moreira aguiar": "Paulo André Moreira Aguiar",
    "rufino": "Francisco Rufino de Araújo Filho",
    "francisco rufino": "Francisco Rufino de Araújo Filho",
    "francisco rufino de araujo filho": "Francisco Rufino de Araújo Filho",
    "yure": "Yure Guimarães Azevedo",
    "yure guimaraes": "Yure Guimarães Azevedo",
    "yure guimaraes azevedo": "Yure Guimarães Azevedo",
    "ericson": "Ericson Cavalcante Teixeira",
    "ericson cavalcante": "Ericson Cavalcante Teixeira",
    "ericson cavalcante teixeira": "Ericson Cavalcante Teixeira",
    "filipe": "Filipe Melo Vasconcelos",
    "filipe melo": "Filipe Melo Vasconcelos",
    "filipe melo vasconcelos": "Filipe Melo Vasconcelos",
    "guido": "Pedro Guido Matias de Oliveira",
    "pedro guido": "Pedro Guido Matias de Oliveira",
    "pedro guido matias de oliveira": "Pedro Guido Matias de Oliveira",
    "pedro hardy": "Pedro Wisley Hardy",
    "pedro wisley": "Pedro Wisley Hardy",
    "pedro wisley hardy": "Pedro Wisley Hardy",
    "hardy": "Pedro Wisley Hardy",
    "alam bruce": "Alam Bruce Prado de Sousa",
    "alam bruce prado de sousa": "Alam Bruce Prado de Sousa",
    "alam bruce prado de souza": "Alam Bruce Prado de Sousa",
    "felipe": "Felipe Boaventura Apolinário",
    "felipe boaventura": "Felipe Boaventura Apolinário",
    "felipe boaventura apolinario": "Felipe Boaventura Apolinário",
    "ardiles": "Ardiles de Morais Bispo",
    "ardiles de morais bispo": "Ardiles de Morais Bispo",
    "carlos junior": "Antônio Carlos Lopes Júnior",
    "antonio carlos": "Antônio Carlos Lopes Júnior",
    "antonio carlos lopes junior": "Antônio Carlos Lopes Júnior",
    "aldemar": "José Aldemar Vasconcelos Cisne Júnior",
    "jose aldemar": "José Aldemar Vasconcelos Cisne Júnior",
    "jose aldemar vasconcelos cisne junior": "José Aldemar Vasconcelos Cisne Júnior",
    "flora": "Flora Nascimento da Paz",
    "flora nascimento da paz": "Flora Nascimento da Paz",
    "francine": "Francine Ribeiro Alves Leite",
    "francine ribeiro alves leite": "Francine Ribeiro Alves Leite",
    "erialdo": "José Erialdo da Silva Júnior",
    "jose erialdo": "José Erialdo da Silva Júnior",
    "jose erialdo da silva junior": "José Erialdo da Silva Júnior",
    "marcelo fernandes": "Marcelo Fernandes dos Santos",
    "marcelo fernandes dos santos": "Marcelo Fernandes dos Santos",
    "maria alice": "Maria Alice Rocha Maia",
    "maria alice rocha maia": "Maria Alice Rocha Maia",
    "maryllia": "Maryllia Linhares de Vasconcelos Frota",
    "maryllia linhares": "Maryllia Linhares de Vasconcelos Frota",
    "maryllia linhares de vasconcelos frota": "Maryllia Linhares de Vasconcelos Frota",
    "daniel": "Daniel",
    "daniela": "Daniela Pires",
    "daniela pires": "Daniela Pires",
    "jonas": "Jonas",
    "lucas": "Lucas",
    "niedja": "Niedja",
    "samea": "Samea"
  };

  const STOPWORDS_NOME = new Set([
    "de", "da", "do", "dos", "das", "e", "para", "com",
    "dr", "dra", "doutor", "doutora", "prof", "profa",
    "perito", "perita", "medico", "medica", "judicial", "eng"
  ]);

  const PRENOMES_AMBIGUOS = new Set([
    "jose", "maria", "joao", "francisco", "antonio", "ana",
    "pedro", "paulo", "carlos", "marcelo", "felipe", "filipe", "marcos", "luiz"
  ]);

  function removerAcentos(str) {
    return String(str || "")
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "");
  }

  function normLower(str) {
    return removerAcentos(str).toLowerCase().trim();
  }

  function ocupaSalasNoPredio(localStr) {
    if (!localStr) return true;
    const l = normLower(localStr);
    if (l.includes("telepericia")) {
      if (
        (l.includes("predio") || l.includes("justica") || l.includes("forum") || l.includes("sala jf") || l.includes("sede")) &&
        !l.includes("fora") &&
        !l.includes("remot") &&
        !l.includes("extern")
      ) {
        return true;
      }
      return false;
    }
    if (
      l.includes("clinica") ||
      l.includes("propria") ||
      l.includes("particular") ||
      l.includes("extern") ||
      l.includes("remot") ||
      l.includes("fora") ||
      l.includes("vila clinic") ||
      l.includes("noblan") ||
      l.includes("sao lucas") ||
      l.includes("premium") ||
      l.includes("consultorio") ||
      l.includes("hospital") ||
      l.includes("domiciliar") ||
      l.includes("virtual") ||
      l.includes("online")
    ) {
      return false;
    }
    if (l.includes("justica") || l.includes("predio") || l.includes("forum") || l.includes("sede") || l.includes("jf") || l.includes("vara") || l === "") {
      return true;
    }
    return false;
  }

  function ehLocalFora(localStr) {
    if (!localStr) return false;
    return !ocupaSalasNoPredio(localStr);
  }

  function calcularPascoaFallback(ano) {
    const y = parseInt(ano, 10);
    if (!Number.isFinite(y) || y < 1583) return null;
    const a = y % 19;
    const b = Math.floor(y / 100);
    const c = y % 100;
    const d = Math.floor(b / 4);
    const e = b % 4;
    const f = Math.floor((b + 8) / 25);
    const g = Math.floor((b - f + 1) / 3);
    const h = (19 * a + b - d - g + 15) % 30;
    const i = Math.floor(c / 4);
    const k = c % 4;
    const l = (32 + 2 * e + 2 * i - h - k) % 7;
    const m = Math.floor((a + 11 * h + 22 * l) / 451);
    const mes = Math.floor((h + l - 7 * m + 114) / 31);
    const dia = ((h + l - 7 * m + 114) % 31) + 1;
    return { ano: y, mes, dia };
  }

  function verificarEhFeriado(dataIso, listaFeriados = FERIADOS_PADRAO_JFCE, subsecaoId = "") {
    if (!dataIso) return null;
    if (typeof root !== "undefined" && root.MaestroDomainRules && typeof root.MaestroDomainRules.verificarEhFeriado === "function") {
      const custom = Array.isArray(listaFeriados) && listaFeriados !== FERIADOS_PADRAO_JFCE ? listaFeriados : [];
      return root.MaestroDomainRules.verificarEhFeriado(dataIso, { subsecaoId, feriadosCustom: custom });
    }
    const limpo = String(dataIso).trim().slice(0, 10);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(limpo)) return null;
    const ano = parseInt(limpo.slice(0, 4), 10);
    const mes = parseInt(limpo.slice(5, 7), 10);
    const dia = parseInt(limpo.slice(8, 10), 10);

    // Recesso Forense Integral (Art. 62, I, Lei 5.010/66: 20/12 a 06/01)
    if ((mes === 12 && dia >= 20) || (mes === 1 && dia <= 6)) {
      if (mes === 1 && dia === 1) return { data: limpo, nome: "Confraternização Universal (Ano Novo)", tipo: "Nacional" };
      if (mes === 12 && dia === 25) return { data: limpo, nome: "Natal", tipo: "Nacional" };
      return { data: limpo, nome: "Recesso Judiciário Forense (Lei 5.010/66)", tipo: "Recesso" };
    }

    // Feriados móveis dinâmicos pela Páscoa
    const pascoa = calcularPascoaFallback(ano);
    if (pascoa) {
      const moveisOffsets = [
        { offset: -48, nome: "Carnaval (Segunda-feira)" },
        { offset: -47, nome: "Carnaval (Terça-feira)" },
        { offset: -46, nome: "Quarta-feira de Cinzas" },
        { offset: -4, nome: "Semana Santa (Quarta-feira)" },
        { offset: -3, nome: "Semana Santa (Quinta-feira Santa)" },
        { offset: -2, nome: "Sexta-feira da Paixão" },
        { offset: 60, nome: "Corpus Christi" }
      ];
      for (const mv of moveisOffsets) {
        const dt = new Date(pascoa.ano, pascoa.mes - 1, pascoa.dia + mv.offset, 12, 0, 0);
        const mvIso = `${dt.getFullYear()}-${String(dt.getMonth() + 1).padStart(2, "0")}-${String(dt.getDate()).padStart(2, "0")}`;
        if (mvIso === limpo) return { data: mvIso, nome: mv.nome, tipo: "Forense" };
      }
    }

    const subNorm = removerAcentos(subsecaoId).toLowerCase().trim();
    const item = (listaFeriados || FERIADOS_PADRAO_JFCE).find((f) => {
      if (!f || !f.data) return false;
      // Escopo municipal: 07-05 (Aniversário de Sobral) só se subsecaoId vazio ou sobral
      if (f.data.slice(5, 10) === "07-05" && subNorm && subNorm !== "sobral") return false;
      if (f.data === limpo) return true;
      if (f.recorrente && f.data.length === 10) {
        return limpo.slice(5) === f.data.slice(5);
      }
      return false;
    });
    return item || null;
  }

  function calcularHorarioTermino(horaInicio, intervaloMin, quantidade) {
    if (!horaInicio) return "--:--";
    const partes = String(horaInicio).split(":");
    const h = parseInt(partes[0], 10) || 0;
    const m = parseInt(partes[1], 10) || 0;
    const duracaoMin = (parseInt(intervaloMin, 10) || 0) * (parseInt(quantidade, 10) || 0);
    const totalMin = h * 60 + m + duracaoMin;
    const endH = Math.floor(totalMin / 60) % 24;
    const endM = totalMin % 60;
    return `${String(endH).padStart(2, "0")}:${String(endM).padStart(2, "0")}`;
  }

  function somarMinutosHora(horaStr, deltaMin) {
    if (!horaStr || !String(horaStr).includes(":")) return "";
    const partes = String(horaStr).split(":");
    const h = parseInt(partes[0], 10);
    const m = parseInt(partes[1], 10);
    if (!Number.isFinite(h) || !Number.isFinite(m)) return "";
    const total = Math.max(0, Math.min(23 * 60 + 59, h * 60 + m + (parseInt(deltaMin, 10) || 0)));
    const outH = Math.floor(total / 60);
    const outM = total % 60;
    return `${String(outH).padStart(2, "0")}:${String(outM).padStart(2, "0")}`;
  }

  function calcularDataLimite8DiasUteis(dataStr, diasUteis = 8, listaFeriados = FERIADOS_PADRAO_JFCE, subsecaoId = "") {
    if (typeof root !== "undefined" && root.MaestroDomainRules && typeof root.MaestroDomainRules.calcularDataLimiteDiasUteis === "function") {
      const custom = Array.isArray(listaFeriados) && listaFeriados !== FERIADOS_PADRAO_JFCE ? listaFeriados : [];
      return root.MaestroDomainRules.calcularDataLimiteDiasUteis(dataStr, diasUteis, { subsecaoId, feriadosCustom: custom });
    }
    if (!dataStr || !/^\d{4}-\d{2}-\d{2}$/.test(dataStr)) return "";
    const [ano, mes, dia] = dataStr.split("-").map(Number);
    const d = new Date(ano, mes - 1, dia, 12, 0, 0);
    if (isNaN(d.getTime())) return "";
    let contagem = 0;
    let guard = 0;
    while (contagem < diasUteis && guard < 400) {
      guard++;
      d.setDate(d.getDate() - 1);
      const dw = d.getDay();
      const iso = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
      if (dw !== 0 && dw !== 6 && !verificarEhFeriado(iso, listaFeriados, subsecaoId)) {
        contagem++;
      }
    }
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
  }

  function calcularPrazoDias(dataLimiteStr) {
    if (!dataLimiteStr || !/^\d{4}-\d{2}-\d{2}$/.test(dataLimiteStr)) return null;
    const [ano, mes, dia] = dataLimiteStr.split("-").map(Number);
    const limite = new Date(ano, mes - 1, dia, 0, 0, 0);
    const hoje = new Date();
    hoje.setHours(0, 0, 0, 0);
    return Math.ceil((limite.getTime() - hoje.getTime()) / (1000 * 60 * 60 * 24));
  }

  function classificarCategoriaPericia(nomePerito, especialidade) {
    if (typeof root !== "undefined" && root.MaestroDomainRules && typeof root.MaestroDomainRules.analisarCategoriaPericia === "function") {
      const res = root.MaestroDomainRules.analisarCategoriaPericia(especialidade || "", nomePerito || "");
      return res.categoriaBI === "medica" ? "medica" : (res.id === "social" ? "social" : "outras");
    }
    const raw = normLower(`${nomePerito || ""} ${especialidade || ""}`);
    const semNegacoes = raw
      .replace(/(?:nao|n\.?)\s*(?:marca(?:r)?|atende|realiza|faz)\s*(?:processos?\s*(?:de\s*)?)?(?:bpc[\s\/]*)?loas/gi, " ")
      .replace(/(?:sem|exceto|menos)\s+(?:processos?\s*(?:de\s*)?)?(?:bpc[\s\/]*)?loas/gi, " ")
      .replace(/\bsem\s+assistencia\s+social\b/gi, " ");
    if (/\b(?:assistente\s+social|assistencia\s+social|pericia\s+social|servico\s+social|bpc)\b/i.test(semNegacoes) || /\bloas\b/i.test(semNegacoes) || /\bsocial\b/i.test(normLower(especialidade || ""))) {
      return "social";
    }
    if (raw.includes("engenharia") || raw.includes("contabil") || raw.includes("grafotec")) return "outras";
    return "medica";
  }

  function obterOcupacaoSalasTurno(dataIso, turno, pautasLista = [], ignorarId = null) {
    if (!dataIso) return { totalSalas: 0, peritos: [] };
    if (typeof root !== "undefined" && root.MaestroDomainRules && typeof root.MaestroDomainRules.obterOcupacaoSalasTurno === "function") {
      const filtrada = ignorarId ? (pautasLista || []).filter((p) => p && p.id !== ignorarId) : pautasLista;
      const r = root.MaestroDomainRules.obterOcupacaoSalasTurno(filtrada, dataIso, turno);
      return { totalSalas: r.salasUsadas, peritos: r.peritos };
    }
    const peritosMap = new Map();
    (pautasLista || []).forEach((p) => {
      if (!p || (ignorarId && p.id === ignorarId)) return;
      const statusNorm = normLower(`${p.status || ""} ${p.situacao || ""}`);
      if (p.cancelada === true || /cancelad|redesignad|suspens|desmarcad|excluid/i.test(statusNorm)) return;
      if (p.data !== dataIso) return;
      if (!ocupaSalasNoPredio(p.local)) return;
      const h = parseInt((p.horaInicio || p.hora || "08:00").split(":")[0], 10);
      const tPauta = h < 12 ? "manha" : (h < 18 ? "tarde" : "noite");
      if (tPauta !== turno) return;
      const chave = normLower(p.peritoNome || "");
      if (chave && !peritosMap.has(chave)) {
        peritosMap.set(chave, p.peritoNome);
      }
    });
    return { totalSalas: peritosMap.size, peritos: Array.from(peritosMap.values()) };
  }

  function criarRegistroPeritoLookup(bancoPeritos) {
    const lista = Array.isArray(bancoPeritos) ? bancoPeritos : [];
    return lista
      .filter((p) => p && (p.nome || p.apelido))
      .map((p) => {
        const nomeLimpo = String(p.nome || "").trim();
        const apelidoLimpo = String(p.apelido || "").trim();
        const nomeSemTitulo = normLower(nomeLimpo).replace(/^(?:dr|dra|eng)\.?\s+/i, "").trim();
        const tokens = nomeSemTitulo.split(/\s+/).filter((t) => t.length > 1 && !STOPWORDS_NOME.has(t));
        const aliases = new Set();

        if (nomeSemTitulo) aliases.add(nomeSemTitulo);
        if (apelidoLimpo) {
          aliases.add(normLower(apelidoLimpo).replace(/^(?:dr|dra|eng)\.?\s+/i, "").trim());
        }
        if (tokens.length >= 2) {
          aliases.add(`${tokens[0]} ${tokens[tokens.length - 1]}`);
          aliases.add(`${tokens[0]} ${tokens[1]}`);
        }
        if (tokens.length === 1 && !PRENOMES_AMBIGUOS.has(tokens[0])) {
          aliases.add(tokens[0]);
        } else if (tokens.length >= 2 && !PRENOMES_AMBIGUOS.has(tokens[0]) && tokens[0].length >= 5) {
          aliases.add(tokens[0]);
        }

        // Sobrenome distintivo único (quando tiver 6+ chars e não for muito genérico)
        const genericos = new Set(["silva", "santos", "souza", "sousa", "oliveira", "pereira", "costa", "rodrigues", "almeida", "nascimento", "lima", "araujo", "fernandes", "carvalho", "gomes", "martins", "rocha", "ribeiro", "alves", "monteiro", "mendes", "barros", "freitas", "barbosa", "moreira", "teixeira", "junior", "filho", "neto"]);
        if (tokens.length >= 2) {
          const ult = tokens[tokens.length - 1];
          if (ult.length >= 5 && !genericos.has(ult)) {
            aliases.add(ult);
          }
        }

        return {
          peritoObj: p,
          nomeOficial: nomeLimpo || apelidoLimpo,
          aliases: Array.from(aliases).filter((a) => a && a.length >= 3).sort((a, b) => b.length - a.length)
        };
      });
  }

  function escaparRegex(str) {
    return String(str || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  function normalizarNomePeritoOficial(nomeDigitado, bancoPeritos = []) {
    const bruto = String(nomeDigitado || "").trim();
    if (!bruto) return "";
    const semTitulo = normLower(bruto)
      .replace(/^(?:dr|dra|doutor|doutora|prof|profa|eng|perito|perita)\.?\s+/i, "")
      .replace(/[^a-z\s]/g, " ")
      .replace(/\s+/g, " ")
      .trim();
    const semStop = semTitulo.split(" ").filter((t) => t && !STOPWORDS_NOME.has(t)).join(" ");

    const regs = criarRegistroPeritoLookup(bancoPeritos);
    for (const r of regs) {
      if (r.aliases.includes(semTitulo) || (semStop && r.aliases.includes(semStop))) {
        return r.nomeOficial;
      }
    }
    if (MAPA_NOMES_OFICIAIS[semTitulo]) return MAPA_NOMES_OFICIAIS[semTitulo];
    if (semStop && MAPA_NOMES_OFICIAIS[semStop]) return MAPA_NOMES_OFICIAIS[semStop];
    return bruto.replace(/^(?:dr|dra)\.?\s+/i, "").trim();
  }

  function encontrarPeritoNoTexto(texto, bancoPeritos = []) {
    const cleanNorm = normLower(texto)
      .replace(/[^\w\s]/g, " ")
      .replace(/\s+/g, " ")
      .trim();
    if (!cleanNorm) return { nome: "", peritoObj: null };

    const regs = criarRegistroPeritoLookup(bancoPeritos);
    let melhorMatch = null;
    let melhorLen = 0;

    for (const r of regs) {
      for (const al of r.aliases) {
        const re = new RegExp(`(?:^|\\s)(?:dr\\s+|dra\\s+|eng\\s+)?${escaparRegex(al)}(?:$|\\s)`, "i");
        if (re.test(cleanNorm) && al.length > melhorLen) {
          melhorLen = al.length;
          melhorMatch = { nome: r.nomeOficial, peritoObj: r.peritoObj };
        }
      }
    }

    if (melhorMatch) return melhorMatch;

    // Fallback pelo dicionário oficial
    const keys = Object.keys(MAPA_NOMES_OFICIAIS).sort((a, b) => b.length - a.length);
    for (const k of keys) {
      if (k.length < 4) continue;
      const re = new RegExp(`(?:^|\\s)(?:dr\\s+|dra\\s+)?${escaparRegex(k)}(?:$|\\s)`, "i");
      if (re.test(cleanNorm)) {
        const oficial = MAPA_NOMES_OFICIAIS[k];
        const cadastro = regs.find((r) => normLower(r.nomeOficial) === normLower(oficial));
        return {
          nome: cadastro ? cadastro.nomeOficial : oficial,
          peritoObj: cadastro ? cadastro.peritoObj : null
        };
      }
    }

    // Padrão explícito "Dr./Dra. Sobrenome" mesmo não estando no banco ainda
    const mTitulo = String(texto || "").match(/\b(Dra?\.?\s+[A-ZÁÀÂÃÉÈÊÍÏÓÔÕÖÚÇÑ][a-zàáâãéèêíïóôõöúçñ]+(?:\s+(?:d[aeo]s?\s+)?[A-ZÁÀÂÃÉÈÊÍÏÓÔÕÖÚÇÑ][a-zàáâãéèêíïóôõöúçñ]+){0,3})/);
    if (mTitulo && mTitulo[1]) {
      const limpo = mTitulo[1].replace(/^(?:Dra?\.?\s+)/i, "").trim();
      if (!/^(?:justica|varas?|sobral|clinica|pauta|pericia)$/i.test(normLower(limpo))) {
        return { nome: limpo, peritoObj: null };
      }
    }

    return { nome: "", peritoObj: null };
  }

  function obterRegrasVaraPerito(peritoObj, vara) {
    if (!peritoObj) {
      return {
        especialidade: "",
        intervaloMin: 10,
        procsPorPauta: 20,
        endereco: "",
        localExternoPadrao: "",
        atendeFora: false,
        padraoPauta: null
      };
    }
    const vStr = String(vara || "").replace(/\D/g, "");
    const r = (vStr && peritoObj.regrasPorVara && peritoObj.regrasPorVara[vStr]) ? peritoObj.regrasPorVara[vStr] : null;
    const pp = (peritoObj.padraoPauta && typeof peritoObj.padraoPauta === "object") ? peritoObj.padraoPauta : null;
    return {
      especialidade: peritoObj.titulada || (r && r.atuacao) || peritoObj.atuacao || "",
      intervaloMin: parseInt((r && r.intervaloMin) || peritoObj.intervaloMin, 10) || 10,
      procsPorPauta: parseInt((r && r.procsPorPauta) || peritoObj.procsPorPauta, 10) || 20,
      endereco: String(peritoObj.endereco || peritoObj.enderecoClinica || "").trim(),
      localExternoPadrao: String(peritoObj.localExternoPadrao || "").trim(),
      atendeFora: Boolean(peritoObj.atendeFora),
      padraoPauta: pp
    };
  }

  function validarDataParts(ano, mes, dia) {
    if (ano < 2020 || ano > 2035 || mes < 1 || mes > 12 || dia < 1 || dia > 31) return null;
    const dt = new Date(ano, mes - 1, dia, 12, 0, 0);
    if (dt.getFullYear() !== ano || dt.getMonth() !== (mes - 1) || dt.getDate() !== dia) return null;
    return `${ano}-${String(mes).padStart(2, "0")}-${String(dia).padStart(2, "0")}`;
  }

  function inferirAnoSemAno(mes, dia, dataRef, contextoMesAno = null) {
    if (contextoMesAno && contextoMesAno.ano && (!contextoMesAno.mes || contextoMesAno.mes === mes)) {
      return contextoMesAno.ano;
    }
    const ref = dataRef instanceof Date && !isNaN(dataRef.getTime()) ? dataRef : new Date();
    const anoBase = ref.getFullYear();
    const dtMesmoAno = new Date(anoBase, mes - 1, dia, 12, 0, 0);
    const diffDias = (dtMesmoAno.getTime() - ref.getTime()) / (1000 * 60 * 60 * 24);
    if (diffDias < -30) {
      return anoBase + 1;
    }
    return anoBase;
  }

  function ehLinhaRuidoAdministrativo(texto) {
    const l = normLower(texto);
    if (!l) return true;
    // Avisos de feriado ("Em fevereiro teremos feriado nos dias 8 a 10")
    if (/\bferiados?\s+(?:nos?\s+|em\s+)?dias?\b/.test(l) || /\bteremos\s+feriado\b/.test(l)) {
      return true;
    }
    // Recesso ou marco inicial ("Devido ao recesso...", "Em janeiro a partir do dia 07.")
    if (
      /\bdevido\s+ao\s+recesso\b/.test(l) ||
      /\b(?:em\s+[a-z]+\s+|as\s+datas(?:\s+de\s+[a-z]+)?\s+(?:devem\s+ser\s+)?)?a\s+partir\s+d[eo]\s+dia\b/.test(l) ||
      /\ba\s+partir\s+de\s+qual\s+dia\b/.test(l)
    ) {
      return true;
    }
    // Confirmação interrogativa da secretaria ("Você quis dizer 24/02, uma quarta?")
    if (/\bvoce\s+quis\s+dizer\s+\d{1,2}[\/.]\d{1,2}\b/.test(l)) {
      return true;
    }
    // Linhas puramente de solicitação/organização sem lista real de datas
    const temListaDatas = /\d{1,2}\s*(?:,|;|e|\/)\s*\d{1,2}/.test(l);
    if (
      !temListaDatas &&
      /\b(?:quando\s+possivel\s+me\s+passe|me\s+passe\s+as?\s+datas?|estou\s+passando\s+para\s+(?:pegar|combinar)|gostaria\s+de\s+(?:ver\s+a\s+possibilidade|\d+\s+datas?)|aguardo\s+as?\s+datas?|vou\s+organizar|vou\s+definir\s+hoje|ja\s+inclui\s+essas\s+datas)\b/.test(l)
    ) {
      return true;
    }
    return false;
  }

  function detectarDataInvalidaFimDeSemana(texto, dataRef, contextoMesAno = null) {
    const l = normLower(texto);
    const m = l.match(/\bo\s+dia\s+(\d{1,2})[\/.](\d{1,2})(?:[\/.](\d{2,4}))?\s+(?:e|eh|cai(?:\s+em|\s+no)?)\s+(?:domingo|sabado)\b/);
    if (!m) return null;
    const d = parseInt(m[1], 10);
    const mes = parseInt(m[2], 10);
    let ano = m[3] ? (m[3].length === 2 ? 2000 + parseInt(m[3], 10) : parseInt(m[3], 10)) : inferirAnoSemAno(mes, d, dataRef, contextoMesAno);
    return validarDataParts(ano, mes, d);
  }

  function extrairMesAnoContextoLinha(linha, dataRef) {
    const lNorm = normLower(linha);
    const ref = dataRef instanceof Date ? dataRef : new Date();
    let melhorContexto = null;
    let maiorPos = -1;

    // Captura o último mês mencionado como referência de bloco (ex: "Em fevereiro...", "para fevereiro...")
    for (const [nomeMes, numMes] of Object.entries(MESES_EXTENSO)) {
      if (nomeMes.length < 3) continue;
      const re = new RegExp(`\\b${nomeMes}(?:\\s*(?:/|de)?\\s*(20\\d{2}))?\\b`, "gi");
      let m;
      while ((m = re.exec(lNorm)) !== null) {
        const antes = lNorm.slice(0, m.index || 0);
        if (!/\b\d{1,2}\s*(?:de)?\s*$/.test(antes) && m.index > maiorPos) {
          const ano = m[1] ? parseInt(m[1], 10) : inferirAnoSemAno(numMes, 15, ref);
          melhorContexto = { mes: numMes, ano };
          maiorPos = m.index;
        }
      }
    }
    if (melhorContexto) return melhorContexto;

    const mNum = lNorm.match(/\b(0?[1-9]|1[0-2])\s*\/\s*(20\d{2})\b/);
    if (mNum) {
      return { mes: parseInt(mNum[1], 10), ano: parseInt(mNum[2], 10) };
    }
    return null;
  }

  const DIAS_SEMANA_MAP = {
    domingo: 0, domingos: 0,
    segunda: 1, segundas: 1,
    terca: 2, tercas: 2,
    quarta: 3, quartas: 3,
    quinta: 4, quintas: 4,
    sexta: 5, sextas: 5,
    sabado: 6, sabados: 6
  };

  function extrairRecorrenciasSemanaisDaLinha(linha, dataRef, contextoMesAno = null, opcoes = {}) {
    const listaFeriados = Array.isArray(opcoes.listaFeriados) ? opcoes.listaFeriados : FERIADOS_PADRAO_JFCE;
    const subsecaoId = String(opcoes.subsecaoId || "");
    const datas = [];
    const ignoradasPorFeriado = [];
    let work = String(linha || "");

    const mesesKeys = Object.keys(MESES_EXTENSO).join("|");
    const mesesAccentPattern = `${mesesKeys}|março`;
    const diaSemToken = "(?:domingos?|segundas?|ter[cç]as?|quartas?|quintas?|sextas?|s[áa]bados?)(?:[\\s-]+feiras?)?";
    const diasSemLista = `${diaSemToken}(?:\\s*(?:,|\\be\\b|\\/)\\s*(?:as\\s+|os\\s+)?${diaSemToken})*`;
    const mesesLista = `(?:${mesesAccentPattern})(?:\\s*(?:,|\\be\\b|\\/)\\s*(?:de\\s+)?(?:${mesesAccentPattern}))*`;

    const expandirParaMes = (diasSemanaSet, mesNum, anoNum) => {
      if (!mesNum || !anoNum || diasSemanaSet.size === 0) return;
      const ultimoDia = new Date(anoNum, mesNum, 0).getDate();
      for (let dia = 1; dia <= ultimoDia; dia++) {
        const dt = new Date(anoNum, mesNum - 1, dia, 12, 0, 0);
        if (!diasSemanaSet.has(dt.getDay())) continue;
        const iso = validarDataParts(anoNum, mesNum, dia);
        if (!iso) continue;
        const feriado = verificarEhFeriado(iso, listaFeriados, subsecaoId);
        if (feriado) {
          ignoradasPorFeriado.push(`${String(dia).padStart(2, "0")}/${String(mesNum).padStart(2, "0")}/${anoNum} (${feriado.nome || "Feriado"})`);
          continue;
        }
        if (!datas.includes(iso)) datas.push(iso);
      }
    };

    const parsearDiasSemana = (trecho) => {
      const set = new Set();
      const limpo = normLower(trecho).replace(/[-–]feiras?/g, "").replace(/\bfeiras?\b/g, "");
      const tokens = limpo.match(/\b(?:domingos?|segundas?|tercas?|quartas?|quintas?|sextas?|sabados?)\b/g) || [];
      tokens.forEach((tk) => {
        if (DIAS_SEMANA_MAP[tk] !== undefined) set.add(DIAS_SEMANA_MAP[tk]);
      });
      return set;
    };

    // 1. Padrão com mês explícito ligado ao(s) dia(s) da semana:
    // Ex: "todas as segundas-feiras de dezembro", "toda segunda e quarta de janeiro e fevereiro"
    const reComMes = new RegExp(
      `\\b(?:(?:todas?|todos?)\\s+(?:as|os)\\s+|toda\\s+|todo\\s+|as\\s+|os\\s+)?(${diasSemLista})\\s+(?:d[eo]|em)\\s+(${mesesLista})(?:\\s+de\\s+(20\\d{2}))?\\b`,
      "gi"
    );
    work = work.replace(reComMes, (full, diasSemStr, mesesStr, anoStr) => {
      const diasSet = parsearDiasSemana(diasSemStr);
      if (diasSet.size === 0) return full;
      const mesTokens = normLower(mesesStr).match(new RegExp(`\\b(${mesesKeys})\\b`, "g")) || [];
      if (mesTokens.length === 0) return full;
      mesTokens.forEach((mNome) => {
        const mesNum = MESES_EXTENSO[mNome];
        if (!mesNum) return;
        const anoNum = anoStr ? parseInt(anoStr, 10) : inferirAnoSemAno(mesNum, 15, dataRef, contextoMesAno);
        expandirParaMes(diasSet, mesNum, anoNum);
      });
      return " __DATA__ ";
    });

    // 2. Fallback com quantificador explícito herdando contextoMesAno ("todas as segundas-feiras")
    if (datas.length === 0 && contextoMesAno && contextoMesAno.mes) {
      const reSemMes = new RegExp(
        `\\b(?:todas?\\s+(?:as\\s+)?|todos?\\s+(?:os\\s+)?)(${diasSemLista})\\b`,
        "gi"
      );
      work = work.replace(reSemMes, (full, diasSemStr) => {
        const diasSet = parsearDiasSemana(diasSemStr);
        if (diasSet.size === 0) return full;
        expandirParaMes(diasSet, contextoMesAno.mes, contextoMesAno.ano);
        return " __DATA__ ";
      });
    }

    return { datas, textoSemRecorrencias: work, ignoradasPorFeriado };
  }

  function extrairDatasDaLinha(linha, dataRef, contextoMesAno = null, opcoesDatas = {}) {
    const datas = [];
    const ignoradasPorFeriado = [];
    const mascarado = { texto: String(linha || "") };
    const adicionarData = (iso) => {
      if (iso && !datas.includes(iso)) datas.push(iso);
    };

    const rec = extrairRecorrenciasSemanaisDaLinha(linha, dataRef, contextoMesAno, opcoesDatas);
    rec.datas.forEach(adicionarData);
    rec.ignoradasPorFeriado.forEach((item) => {
      if (!ignoradasPorFeriado.includes(item)) ignoradasPorFeriado.push(item);
    });

    let work = rec.textoSemRecorrencias;

    // 1. ISO YYYY-MM-DD
    work = work.replace(/\b(20\d{2})-(\d{1,2})-(\d{1,2})\b/g, (full, a, m, d) => {
      const iso = validarDataParts(parseInt(a, 10), parseInt(m, 10), parseInt(d, 10));
      if (iso) {
        adicionarData(iso);
        return " __DATA__ ";
      }
      return full;
    });

    // 2. Lista de dias com mês por extenso depois: "12,19,26de janeiro" / "13, 14 e 15 de Janeiro de 2027"
    const mesesKeys = Object.keys(MESES_EXTENSO).join("|");
    const mesesAccentPattern = `${mesesKeys}|março`;
    const reListaMesExtenso = new RegExp(`\\b(?:dias?\\s+)?((?:\\d{1,2}\\s*(?:,|;|\\be\\b|\\/)\\s*)+\\d{1,2})\\s*de\\s+(${mesesAccentPattern})(?:\\s+de\\s+(20\\d{2}))?\\b`, "gi");
    work = work.replace(reListaMesExtenso, (full, diasStr, mesNome, anoStr) => {
      const mesNum = MESES_EXTENSO[normLower(mesNome)];
      if (!mesNum) return full;
      const diasTokens = diasStr.match(/\d{1,2}/g) || [];
      diasTokens.forEach((dTxt) => {
        const diaNum = parseInt(dTxt, 10);
        const anoNum = anoStr ? parseInt(anoStr, 10) : inferirAnoSemAno(mesNum, diaNum, dataRef, contextoMesAno);
        adicionarData(validarDataParts(anoNum, mesNum, diaNum));
      });
      return " __DATA__ ";
    });

    // 2B. Mês ANTES da lista (inclusive múltiplas ocorrências e parênteses):
    // Ex: "Fevereiro 2, 16, 23", "para Janeiro as datas 13,20 e 27 e para fevereiro as datas 3,17,24", "em janeiro(13,20,27)"
    const reMesAntesLista = new RegExp(
      `(^|[\\s,;(\\-–])(?:(?:em|para|de|m[êe]s\\s+de)\\s+)?(${mesesAccentPattern})(?:\\s+de\\s+(20\\d{2}))?\\s*(?::\\s*|\\(\\s*|(?:(?:para|em)\\s+)?(?:as\\s+)?datas?\\s+|dias?\\s+|\\s+)((?:\\d{1,2}\\s*(?:,|;|\\be\\b)\\s*)*\\d{1,2})(?:\\s*\\))?(?!\\s*(?:[ªºa°]|:?\\d|h\\b|min\\b|vagas?|per[ií]cias?|processos?|horas?|hora\\b|pautas?|anos?))`,
      "gi"
    );
    work = work.replace(reMesAntesLista, (full, prefixo, mesNome, anoStr, diasStr) => {
      const mesNum = MESES_EXTENSO[normLower(mesNome)];
      if (!mesNum) return full;
      const diasTokens = diasStr.match(/\d{1,2}/g) || [];
      if (diasTokens.length === 0) return full;
      let adicionouAlguma = false;
      diasTokens.forEach((dTxt) => {
        const diaNum = parseInt(dTxt, 10);
        const anoNum = anoStr ? parseInt(anoStr, 10) : inferirAnoSemAno(mesNum, diaNum, dataRef, contextoMesAno);
        const iso = validarDataParts(anoNum, mesNum, diaNum);
        if (iso) {
          adicionarData(iso);
          adicionouAlguma = true;
        }
      });
      return adicionouAlguma ? `${prefixo} __DATA__ ` : full;
    });

    // 3. Lista de dias com mês numérico: "dias 07, 14 e 21/12(/2026)?"
    work = work.replace(/\b(?:dias?\s+)?((?:\d{1,2}\s*(?:,|e)\s*)+\d{1,2})\s*\/\s*(\d{1,2})(?:\/(\d{2,4}))?\b/gi, (full, diasStr, mesStr, anoStr) => {
      const mesNum = parseInt(mesStr, 10);
      if (mesNum < 1 || mesNum > 12) return full;
      const anoExpl = anoStr ? (anoStr.length === 2 ? 2000 + parseInt(anoStr, 10) : parseInt(anoStr, 10)) : null;
      const diasTokens = diasStr.match(/\d{1,2}/g) || [];
      diasTokens.forEach((dTxt) => {
        const diaNum = parseInt(dTxt, 10);
        const anoNum = anoExpl || inferirAnoSemAno(mesNum, diaNum, dataRef, contextoMesAno);
        adicionarData(validarDataParts(anoNum, mesNum, diaNum));
      });
      return " __DATA__ ";
    });

    // 4. Data única por extenso: "09 de dezembro (de 2026)?" (aceita sem espaço antes do "de")
    const reDataExtenso = new RegExp(`\\b(\\d{1,2})\\s*de\\s+(${mesesAccentPattern})(?:\\s+de\\s+(20\\d{2}))?\\b`, "gi");
    work = work.replace(reDataExtenso, (full, diaStr, mesNome, anoStr) => {
      const mesNum = MESES_EXTENSO[normLower(mesNome)];
      const diaNum = parseInt(diaStr, 10);
      if (!mesNum || diaNum < 1 || diaNum > 31) return full;
      const anoNum = anoStr ? parseInt(anoStr, 10) : inferirAnoSemAno(mesNum, diaNum, dataRef, contextoMesAno);
      const iso = validarDataParts(anoNum, mesNum, diaNum);
      if (iso) {
        adicionarData(iso);
        return " __DATA__ ";
      }
      return full;
    });

    // 5. Data DD/MM/AAAA, DD/MM/AA ou DD.MM.AAAA
    work = work.replace(/\b(\d{1,2})[\/.](\d{1,2})[\/.](\d{2,4})\b/g, (full, dStr, mStr, aStr) => {
      const d = parseInt(dStr, 10);
      const m = parseInt(mStr, 10);
      let a = parseInt(aStr, 10);
      if (aStr.length === 2) a = 2000 + a;
      const iso = validarDataParts(a, m, d);
      if (iso) {
        adicionarData(iso);
        return " __DATA__ ";
      }
      return full;
    });

    // 6. Data DD/MM ou DD.MM sem ano (mas não mm/2026 ou valores monetários/versões)
    work = work.replace(/(^|[^\d.$])(\d{1,2})([\/.])(\d{1,2})(?=$|[^\d.])(?!\.\d|\d)/g, (full, prefixo, dStr, sep, mStr, offset, origStr) => {
      const d = parseInt(dStr, 10);
      const m = parseInt(mStr, 10);
      if (m < 1 || m > 12 || d < 1 || d > 31) return full;
      if (sep === ".") {
        const antes = origStr.slice(Math.max(0, offset - 8), offset + prefixo.length);
        if (/(?:r\$|versao|v\.?)\s*$/i.test(antes)) return full;
      }
      const anoNum = inferirAnoSemAno(m, d, dataRef, contextoMesAno);
      const iso = validarDataParts(anoNum, m, d);
      if (iso) {
        adicionarData(iso);
        return `${prefixo} __DATA__ `;
      }
      return full;
    });

    // 7. Listas prefixadas por dois-pontos ou local quando há contextoMesAno definido: "Externo: 15, 22, 23, 25, 26." / "Na JEF: 13 e 19."
    if (contextoMesAno && contextoMesAno.mes) {
      work = work.replace(
        /(^|[\s.;])((?:extern[oa]s?|na\s+jef|no\s+jef|jef|pr[eé]dio|fora|cl[ií]nica|justi[çc]a(?:\s+federal)?|datas?|dias?)\s*:)\s*((?:\d{1,2}\s*(?:,|;|\be\b)\s*)*\d{1,2})(?=$|[\s.,;!?)\-])(?!\s*(?:[ªºa°]|:|\d|h\b|min\b|vagas?|per[ií]cias?|processos?))/gi,
        (full, prefixo, rotulo, listaDias) => {
          const nums = listaDias.match(/\d{1,2}/g) || [];
          let addCount = 0;
          nums.forEach((n) => {
            const d = parseInt(n, 10);
            if (d >= 1 && d <= 31) {
              const iso = validarDataParts(contextoMesAno.ano, contextoMesAno.mes, d);
              if (iso) {
                adicionarData(iso);
                addCount++;
              }
            }
          });
          // Mantém o rótulo (ex: "Externo:", "Na JEF:") no textoSemDatas para o detector de local identificar!
          return addCount > 0 ? `${prefixo}${rotulo} __DATA__ ` : full;
        }
      );
    }

    // 8. Fallback: "dia 12" ou "dias 05, 12 e 19" quando há contextoMesAno definido
    if (datas.length === 0 && contextoMesAno && contextoMesAno.mes) {
      work = work.replace(/\bdias?\s+((?:\d{1,2}\s*(?:,|;|\be\b)?\s*)+)(?!\s*(?:[ªºa°]|:|\d|h\b|min\b|vagas?|per[ií]cias?|processos?))/gi, (full, listaDias) => {
        const nums = listaDias.match(/\d{1,2}/g) || [];
        nums.forEach((n) => {
          const d = parseInt(n, 10);
          if (d >= 1 && d <= 31) {
            adicionarData(validarDataParts(contextoMesAno.ano, contextoMesAno.mes, d));
          }
        });
        return nums.length > 0 ? " __DATA__ " : full;
      });
    }

    mascarado.texto = work;
    return { datas, textoSemDatas: mascarado.texto, ignoradasPorFeriado };
  }

  function extrairDiretivaHorarioCorrido(linha, dataRef, contextoMesAno = null) {
    const bruto = String(linha || "");
    const sentencas = bruto.split(/\.(?!\d)|[;\n]+/);
    const mantidas = [];
    const datasCorrido = [];
    let temCorridoSemData = false;
    let pausaRestanteMin = null;

    sentencas.forEach((sent) => {
      const trimmed = sent.trim();
      if (!trimmed) return;
      const sNorm = normLower(trimmed);

      if (/\bhorario\s+corrido\b/.test(sNorm)) {
        const res = extrairDatasDaLinha(trimmed, dataRef, contextoMesAno);
        if (res.datas.length > 0) {
          res.datas.forEach((d) => {
            if (!datasCorrido.includes(d)) datasCorrido.push(d);
          });
        } else {
          temCorridoSemData = true;
        }
        return;
      }

      const mAlmoco = sNorm.match(/\b(\d+)\s*h(?:oras?)?\s+de\s+almoco\b/);
      if (mAlmoco && (/\bpadrao\b/.test(sNorm) || /\brestante\b/.test(sNorm) || /\balmoco\b/.test(sNorm))) {
        pausaRestanteMin = (parseInt(mAlmoco[1], 10) || 1) * 60;
        return;
      }

      mantidas.push(trimmed);
    });

    return {
      textoSemClausulaCorrido: mantidas.join(". "),
      datasCorrido,
      temCorridoSemData,
      pausaRestanteMin
    };
  }

  function extrairAjustesVagasPorData(linha, dataRef, contextoMesAno = null) {
    const partes = String(linha || "").split(/\.\s*(?!\d)|;\s*|,\s*(?=mas\b|por[eé]m\b|j[aá]\s+n[ao])|\bmas\b/i);
    const ajustes = [];
    let ctxLocal = contextoMesAno;

    for (const parte of partes) {
      const trimmed = parte.trim();
      if (!trimmed) continue;
      const resDatas = extrairDatasDaLinha(trimmed, dataRef, ctxLocal);
      if (resDatas.datas.length === 0) continue;

      const lastIso = resDatas.datas[resDatas.datas.length - 1];
      ctxLocal = {
        mes: parseInt(lastIso.slice(5, 7), 10),
        ano: parseInt(lastIso.slice(0, 4), 10)
      };

      let qtd = extrairQuantidadeDaLinha(resDatas.textoSemDatas);
      if (qtd === null) {
        const lSem = normLower(resDatas.textoSemDatas);
        const mQ = lSem.match(/\b(?:d[aá]|faz(?:er)?|marc(?:a|ar)|at[eé]|somente|apenas)\s+(?:as?\s+|os?\s+)?(\d{1,3})\b(?!\s*(?:h\b|:|min\b|dias?\b|[ªºa°]|vara|vf))/i);
        if (mQ) {
          const val = parseInt(mQ[1], 10);
          if (val >= 1 && val <= 200) qtd = val;
        }
      }

      if (qtd !== null) {
        ajustes.push({ datas: resDatas.datas, quantidade: qtd, trecho: trimmed });
      }
    }

    return ajustes;
  }

  function extrairHorariosDaLinha(texto) {
    const horarios = [];
    const l = normLower(texto);

    const adicionarHora = (hhmm) => {
      if (hhmm && !horarios.includes(hhmm)) horarios.push(hhmm);
    };

    // Padrões explícitos: 08:00, 08:00h, 12:15, 08h30, 8h, às 9h, 13h00
    const reHora = /(?:^|[\s(,\-–])(?:a\s*partir\s*d[ao]s?|as\s+)?(\d{1,2})\s*(?::\s*(\d{2})(?:\s*(?:hrs?|hs?))?|h\s*(\d{2})?|hrs?|hs?)\b(?!\s*min)/gi;
    let m;
    while ((m = reHora.exec(l)) !== null) {
      const trechoCompleto = m[0];
      const temSeparadorHora = trechoCompleto.includes(":") || /\d\s*h/i.test(trechoCompleto);
      if (!temSeparadorHora) continue;
      const h = parseInt(m[1], 10);
      const min = m[2] ? parseInt(m[2], 10) : (m[3] ? parseInt(m[3], 10) : 0);
      if (h >= 6 && h <= 21 && min >= 0 && min <= 59) {
        adicionarHora(`${String(h).padStart(2, "0")}:${String(min).padStart(2, "0")}`);
      }
    }

    // Caso "às 8", "das 13" sem "h"
    const reAsHora = /\b(?:as|às|horario\s*[:=]?)\s*(\d{1,2})(?!\s*(?:de|\/|min|vagas?|pericias?|processos?|vf|vara))/gi;
    while ((m = reAsHora.exec(normLower(texto))) !== null) {
      const h = parseInt(m[1], 10);
      if (h >= 6 && h <= 20) {
        const jahTemNoTurno = horarios.some((hr) => {
          const hh = parseInt(hr.split(":")[0], 10);
          return hh === h;
        });
        if (!jahTemNoTurno) {
          adicionarHora(`${String(h).padStart(2, "0")}:00`);
        }
      }
    }

    // Turnos nominais quando não há horário naquele turno ainda
    if (/\bmanha\b/.test(l) && !horarios.some((hr) => parseInt(hr.split(":")[0], 10) < 12)) {
      adicionarHora("08:00");
    }
    if (/\btarde\b/.test(l) && !horarios.some((hr) => parseInt(hr.split(":")[0], 10) >= 12)) {
      adicionarHora("13:30");
    }

    return horarios;
  }

  function extrairVarasDaLinha(texto, subsecaoVaras = []) {
    const varas = [];
    const l = normLower(texto);
    const adicionarVara = (v) => {
      const clean = String(v || "").replace(/\D/g, "");
      if (!clean) return;
      const num = parseInt(clean, 10);
      if (num < 1 || num > 99) return;
      if (!varas.includes(clean)) varas.push(clean);
    };

    // Ex: "19ª e 31ª Varas", "19ª/31ª VF", "19ª Vara"
    const reMultiVara = /\b((?:\d{1,2}\s*[ªaº°]?\s*(?:,|e|\/)\s*)+\d{1,2}\s*[ªaº°]?)\s*(?:varas?(?:\s*federais?)?|vfs?|jef)\b/gi;
    let m;
    while ((m = reMultiVara.exec(l)) !== null) {
      (m[1].match(/\d{1,2}/g) || []).forEach(adicionarVara);
    }

    const reVaraDepois = /\b(\d{1,2})\s*[ªaº°]\s*(?:vara(?:\s*federal)?|vf|jef)?\b/gi;
    while ((m = reVaraDepois.exec(l)) !== null) {
      adicionarVara(m[1]);
    }

    const reVaraAntes = /\b(?:vara(?:\s*federal)?|vf|jef)\s*(?:n[º°]?\.?\s*)?(\d{1,2})\b/gi;
    while ((m = reVaraAntes.exec(l)) !== null) {
      adicionarVara(m[1]);
    }

    if (Array.isArray(subsecaoVaras) && subsecaoVaras.length > 0 && varas.length > 1) {
      const filtradas = varas.filter((v) => subsecaoVaras.includes(v));
      if (filtradas.length > 0) return filtradas;
    }

    return varas;
  }

  function extrairQuantidadeDaLinha(texto) {
    const l = normLower(texto);
    const m1 = l.match(/\b(\d{1,3})\s*(?:vagas?|pericias?|processos?|exames?|atendimentos?|pacientes?|periciandos?|senhas?|marcacoes?)\b/i);
    if (m1) {
      const q = parseInt(m1[1], 10);
      if (q > 0 && q <= 200) return q;
    }
    const m2 = l.match(/\b(?:qtd|quant\.?|quantidade|vagas|capacidade)\s*[:=\-]?\s*(\d{1,3})\b/i);
    if (m2) {
      const q = parseInt(m2[1], 10);
      if (q > 0 && q <= 200) return q;
    }
    return null;
  }

  function extrairIntervaloDaLinha(texto) {
    const l = normLower(texto);
    const m1 = l.match(/\bintervalo\s*(?:de)?\s*[:=\-]?\s*(\d{1,3})\s*(?:min(?:utos?)?)?\b/i);
    if (m1) {
      const v = parseInt(m1[1], 10);
      if (v >= 1 && v <= 120) return v;
    }
    const m2 = l.match(/\ba\s*cada\s*(\d{1,3})\s*min(?:utos?)?\b/i);
    if (m2) {
      const v = parseInt(m2[1], 10);
      if (v >= 1 && v <= 120) return v;
    }
    const m3 = l.match(/\bde\s*(\d{1,2})\s*em\s*\d{1,2}\s*min(?:utos?)?\b/i);
    if (m3) {
      const v = parseInt(m3[1], 10);
      if (v >= 1 && v <= 120) return v;
    }
    const m4 = l.match(/\b(\d{1,2})\s*min(?:utos?)?\b/i);
    if (m4) {
      const v = parseInt(m4[1], 10);
      if (v >= 3 && v <= 90) return v;
    }
    return null;
  }

  function extrairLocalEEndereco(texto, peritoRegras = null) {
    const bruto = String(texto || "");
    const l = normLower(bruto);
    let local = "";
    let endereco = "";

    // 1. Identificação do local padronizado (compatível com #pautaFormLocal do dashboard.html)
    if (l.includes("telepericia")) {
      if (l.includes("predio") || l.includes("justica") || l.includes("forum") || l.includes("sala jf")) {
        local = "Teleperícia (No Prédio)";
      } else {
        local = "Teleperícia (Remota / Externa)";
      }
    } else if (l.includes("clinica particular")) {
      local = "Clínica particular";
    } else if (
      l.includes("clinica propria") ||
      l.includes("na clinica") ||
      l.includes("vila clinic") ||
      l.includes("noblan") ||
      l.includes("sao lucas") ||
      l.includes("premium") ||
      l.includes("clinica ")
    ) {
      local = (l.includes("noblan") && !peritoRegras?.localExternoPadrao)
        ? "Clínica Noblan"
        : (peritoRegras?.localExternoPadrao || "Clínica Própria");
    } else if (
      /\bextern[oa]s?\b/.test(l) ||
      /\bfora\b/.test(l) ||
      l.includes("consultorio") ||
      l.includes("hospital") ||
      l.includes("domiciliar") ||
      l.includes("fora do predio") ||
      l.includes("fora do forum")
    ) {
      if (peritoRegras && peritoRegras.localExternoPadrao) {
        local = peritoRegras.localExternoPadrao;
      } else if (/\bextern[oa]s?\b/.test(l) || /\bfora\b/.test(l)) {
        local = "Clínica Própria";
      } else {
        local = "Fora / Consultório / Hospital";
      }
    } else if (
      /\b(?:na|no)\s+jef\b/.test(l) ||
      /\bdo\s+predio\b/.test(l) ||
      l.includes("justica federal") ||
      l.includes("no predio") ||
      l.includes("predio da justica") ||
      l.includes("forum") ||
      l.includes("sede")
    ) {
      local = "Justiça Federal";
    }

    // 2. Extração de endereço quando presente no texto
    const limparEnderecoExtraido = (rawEnd) => {
      return String(rawEnd || "")
        .replace(/^[:=\-–\s]+/, "")
        .replace(/\s*[-–|]\s*(?:\d{1,2}\s*[ªaº°]?\s*(?:vara|vf|jef)|\d+\s*vagas?|\d{1,2}:\d{2}|\d{1,2}h\d{0,2}|marcad[ao]|nao marcad[ao]|em marcacao).*$/i, "")
        .replace(/[)\];]+$/, "")
        .trim();
    };

    const mEndRotulo = bruto.match(/(?:endere[çc]o(?:\s+da\s+per[íi]cia)?|local\s+da\s+per[íi]cia)\s*[:=\-–]\s*([^\n]+)/i);
    if (mEndRotulo && mEndRotulo[1]) {
      endereco = limparEnderecoExtraido(mEndRotulo[1]);
    } else {
      const mLogradouro = bruto.match(/\b((?:Rua|R\.|Av\.?|Avenida|Travessa|Tv\.?|Pra[çc]a|Alameda)\s+[^;\n()]+)/i);
      if (mLogradouro && mLogradouro[1]) {
        endereco = limparEnderecoExtraido(mLogradouro[1]);
      } else {
        const mClinicaNome = bruto.match(/\b((?:Vila\s+Clinic|Noblan(?:\s+Med\s+Hub)?|S[ãa]o\s+Lucas\s+Medical\s+Center)[^;\n()]*)/i);
        if (mClinicaNome && mClinicaNome[1]) {
          endereco = limparEnderecoExtraido(mClinicaNome[1]);
        }
      }
    }

    // Se encontrou endereço explícito mas o local ficou vazio, marca como externa
    if (!local && endereco) {
      local = (peritoRegras && peritoRegras.localExternoPadrao) ? peritoRegras.localExternoPadrao : "Clínica Própria";
    }

    // Herança do cadastro do perito se não informado no texto
    if (!local) {
      if (peritoRegras && peritoRegras.atendeFora) {
        local = peritoRegras.localExternoPadrao || "Clínica Própria";
      } else {
        local = "Justiça Federal";
      }
    }

    if (ehLocalFora(local) && !endereco && peritoRegras && peritoRegras.endereco) {
      endereco = peritoRegras.endereco;
    }

    return {
      local,
      endereco: ehLocalFora(local) ? endereco : ""
    };
  }

  function extrairSituacao(texto, situacaoPadrao = "Não marcado") {
    const l = normLower(texto);
    if (/\b(?:nao\s+marcad[ao]|pendente|em\s+aberto|sem\s+marcar)\b/.test(l)) return "Não marcado";
    if (/\b(?:em\s+marcacao|em\s+andamento|liberada?)\b/.test(l)) return "Em marcação";
    if (/\b(?:ja\s+marcad[ao]|confirmad[ao]|marcad[ao])\b/.test(l)) return "Marcado";
    return situacaoPadrao || "Não marcado";
  }

  function limparFormatoWhatsapp(textoBruto) {
    return String(textoBruto || "")
      .replace(/[\u200e\u200f\u202a-\u202e\ufeff]/g, "")
      .replace(/\r\n/g, "\n")
      .replace(/\r/g, "\n")
      .replace(/[*_`~]/g, "");
  }

  function analisarLinhaWhatsappHeader(linha) {
    // [24/11 09:40] Remetente: corpo
    // [24/11/2026, 09:40:12] Remetente: corpo
    let m = linha.match(/^\[\s*\d{1,2}\/\d{1,2}(?:\/\d{2,4})?(?:,|\s)+\d{1,2}:\d{2}(?::\d{2})?\s*\]\s*([^:]{1,80}):\s*(.*)$/);
    if (m) {
      return { ehCabecalhoMsg: true, remetente: m[1].trim(), corpo: m[2].trim() };
    }
    // 24/11/2026 09:40 - Remetente: corpo  OU  24/11/2026, 09:40 - Remetente: corpo
    m = linha.match(/^\d{1,2}\/\d{1,2}(?:\/\d{2,4})?(?:,|\s)+\d{1,2}:\d{2}(?::\d{2})?\s*[-–]\s*([^:]{1,80}):\s*(.*)$/);
    if (m) {
      return { ehCabecalhoMsg: true, remetente: m[1].trim(), corpo: m[2].trim() };
    }
    return { ehCabecalhoMsg: false, remetente: "", corpo: linha.trim() };
  }

  function prepararPautaCanonica(dados = {}, bancoPeritos = [], listaFeriados = FERIADOS_PADRAO_JFCE) {
    const nomeOficial = normalizarNomePeritoOficial(dados.peritoNome || dados.perito || "", bancoPeritos);
    const peritoMatch = encontrarPeritoNoTexto(nomeOficial, bancoPeritos);
    const peritoObj = peritoMatch.peritoObj || null;
    const regras = obterRegrasVaraPerito(peritoObj, dados.vara);

    const especialidade = String(dados.especialidade || regras.especialidade || "Clínica Médica / Geral").trim();
    const vara = String(dados.vara || "19").replace(/\D/g, "") || String(dados.vara || "19").trim();
    const local = String(dados.local || "Justiça Federal").trim() || "Justiça Federal";
    const ehFora = ehLocalFora(local);
    const endereco = ehFora ? String(dados.endereco || regras.endereco || "").trim() : "";
    const quantidade = Math.max(1, parseInt(dados.quantidade !== undefined ? dados.quantidade : (dados.vagas || regras.procsPorPauta), 10) || 20);
    const intervaloMin = Math.max(1, parseInt(dados.intervaloMin !== undefined ? dados.intervaloMin : (dados.duracao || regras.intervaloMin), 10) || 10);
    const horaInicio = String(dados.horaInicio || dados.hora || "08:00").trim();
    const data = /^\d{4}-\d{2}-\d{2}$/.test(String(dados.data || "")) ? String(dados.data) : "";
    const horaTermino = calcularHorarioTermino(horaInicio, intervaloMin, quantidade);
    const dataLimite = data ? calcularDataLimite8DiasUteis(data, 8, listaFeriados) : "";
    const prazoDias = dataLimite ? calcularPrazoDias(dataLimite) : null;
    const situacao = String(dados.situacao || "Não marcado").trim() || "Não marcado";
    const observacoes = String(dados.observacoes || dados.observacao || "").trim();
    const id = dados.id || `pauta_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    const nowTs = dados.updatedAt || Date.now();

    return {
      id,
      peritoNome: nomeOficial || String(dados.peritoNome || "").trim(),
      especialidade,
      data,
      vara,
      local,
      endereco,
      quantidade,
      horaInicio,
      intervaloMin,
      horaTermino,
      dataLimite,
      prazoDias,
      situacao,
      observacoes,
      origem: dados.origem || "mobile_whatsapp",
      updatedAt: nowTs,
      // Aliases mantidos para renderização de relatórios no App Mobile
      vagas: quantidade,
      hora: horaInicio,
      duracao: intervaloMin,
      observacao: observacoes,
      categoria: classificarCategoriaPericia(nomeOficial, especialidade)
    };
  }

  function calcularPendenciasPauta(pauta) {
    const pendencias = [];
    if (!pauta.peritoNome || pauta.peritoNome.length < 2) pendencias.push("Perito não identificado");
    if (!pauta.data || !/^\d{4}-\d{2}-\d{2}$/.test(pauta.data)) pendencias.push("Data ausente ou inválida");
    if (!pauta.vara) pendencias.push("Vara não informada");
    if (ehLocalFora(pauta.local) && !String(pauta.endereco || "").trim()) {
      pendencias.push("Endereço externo obrigatório");
    }
    return pendencias;
  }

  /**
   * Aplica a regra de horário corrido (0 min de almoço) nos cards de uma data específica.
   */
  function aplicarHorarioCorridoNasPautas(listaPautas, datasCorrido, peritoNomeAlvo, listaFeriados = FERIADOS_PADRAO_JFCE) {
    if (!Array.isArray(listaPautas) || !Array.isArray(datasCorrido) || datasCorrido.length === 0) return false;
    const alvoNorm = normLower(peritoNomeAlvo || "");
    let alterou = false;

    datasCorrido.forEach((dataIso) => {
      const indices = [];
      listaPautas.forEach((p, idx) => {
        if (!p || p.data !== dataIso) return;
        if (alvoNorm && normLower(p.peritoNome || "") !== alvoNorm) return;
        indices.push(idx);
      });
      if (indices.length === 0) return;

      indices.sort((a, b) => String(listaPautas[a].horaInicio || "").localeCompare(String(listaPautas[b].horaInicio || "")));
      const obsCorrido = "Horário corrido (sem intervalo de almoço)";

      if (indices.length >= 2) {
        const idxManha = indices[0];
        const idxTarde = indices[1];
        const manha = listaPautas[idxManha];
        const tarde = listaPautas[idxTarde];
        const terminoManha = calcularHorarioTermino(manha.horaInicio, manha.intervaloMin, manha.quantidade);
        if (terminoManha && terminoManha !== "--:--") {
          tarde.horaInicio = terminoManha;
          tarde.hora = terminoManha;
          tarde.horaTermino = calcularHorarioTermino(terminoManha, tarde.intervaloMin, tarde.quantidade);
        }
        const obsAtual = String(tarde.observacoes || "").trim();
        if (!normLower(obsAtual).includes("horario corrido")) {
          tarde.observacoes = obsAtual ? `${obsAtual} • ${obsCorrido}` : obsCorrido;
          tarde.observacao = tarde.observacoes;
        }
        alterou = true;
      } else {
        const unica = listaPautas[indices[0]];
        const obsAtual = String(unica.observacoes || "").trim();
        if (!normLower(obsAtual).includes("horario corrido")) {
          unica.observacoes = obsAtual ? `${obsAtual} • ${obsCorrido}` : obsCorrido;
          unica.observacao = unica.observacoes;
        }
        alterou = true;
      }
    });

    return alterou;
  }

  /**
   * Insere ou mescla pauta no array de extração evitando cards duplicados no mesmo lote/conversa.
   */
  function inserirOuMesclarPautaExtraida(pautasExtraidas, canonica, opcoesMerge = {}) {
    const chaveNova = `${canonica.data || ""}|${normLower(canonica.peritoNome || "")}|${canonica.horaInicio || ""}`;
    if (canonica.data && canonica.peritoNome) {
      const idxExist = pautasExtraidas.findIndex((p) => {
        if (!p || !p.data || !p.peritoNome) return false;
        const ch = `${p.data}|${normLower(p.peritoNome)}|${p.horaInicio || ""}`;
        return ch === chaveNova;
      });
      if (idxExist !== -1) {
        const exist = pautasExtraidas[idxExist];
        if (opcoesMerge.localExplicito && canonica.local) {
          exist.local = canonica.local;
          exist.endereco = canonica.endereco || "";
        }
        if (opcoesMerge.qtdExplicita && canonica.quantidade) {
          exist.quantidade = canonica.quantidade;
          exist.vagas = canonica.quantidade;
          exist.horaTermino = calcularHorarioTermino(exist.horaInicio, exist.intervaloMin, exist.quantidade);
        }
        if (canonica.observacoes && !normLower(exist.observacoes || "").includes(normLower(canonica.observacoes))) {
          exist.observacoes = exist.observacoes ? `${exist.observacoes} • ${canonica.observacoes}` : canonica.observacoes;
          exist.observacao = exist.observacoes;
        }
        if (opcoesMerge.trechoOrigem && exist._meta) {
          exist._meta.trechoOrigem = exist._meta.trechoOrigem
            ? `${exist._meta.trechoOrigem} | ${opcoesMerge.trechoOrigem}`
            : opcoesMerge.trechoOrigem;
        }
        return false;
      }
    }
    pautasExtraidas.push(canonica);
    return true;
  }

  /**
   * Parser principal de conversas do WhatsApp (1 ou N pautas).
   * @param {string} textoBruto
   * @param {object} opcoes
   */
  function parsearConversaWhatsApp(textoBruto, opcoes = {}) {
    const textoLimpo = limparFormatoWhatsapp(textoBruto);
    const bancoPeritos = Array.isArray(opcoes.bancoPeritos) ? opcoes.bancoPeritos : [];
    const subsecaoVaras = Array.isArray(opcoes.subsecaoVaras) ? opcoes.subsecaoVaras : [];
    const varaPadrao = String(opcoes.varaPadrao || subsecaoVaras[0] || "19").replace(/\D/g, "") || "19";
    const situacaoPadrao = String(opcoes.situacaoPadrao || "Não marcado");
    const modoTurnos = String(opcoes.modoTurnos || "padrao_perito").trim();
    const listaFeriados = Array.isArray(opcoes.listaFeriados) ? opcoes.listaFeriados : FERIADOS_PADRAO_JFCE;
    const subsecaoId = String(opcoes.subsecaoId || "");
    const dataRef = opcoes.dataReferencia instanceof Date ? opcoes.dataReferencia : new Date();
    const peritoPadraoRaw = String(opcoes.peritoPadrao || "").trim();
    const peritoPadraoResolvido = peritoPadraoRaw
      ? encontrarPeritoNoTexto(peritoPadraoRaw, bancoPeritos)
      : { nome: "", peritoObj: null };
    if (peritoPadraoRaw && !peritoPadraoResolvido.nome) {
      peritoPadraoResolvido.nome = normalizarNomePeritoOficial(peritoPadraoRaw, bancoPeritos);
    }

    if (!textoLimpo.trim()) {
      return { pautas: [], avisos: ["Nenhum texto informado para interpretar."] };
    }

    const linhasBrutas = textoLimpo.split("\n");
    const itensSegmentados = [];

    for (const rawLine of linhasBrutas) {
      const trimmed = rawLine.trim();
      if (!trimmed) {
        itensSegmentados.push({ tipo: "VAZIA" });
        continue;
      }
      const parsedHdr = analisarLinhaWhatsappHeader(trimmed);
      if (parsedHdr.ehCabecalhoMsg) {
        itensSegmentados.push({
          tipo: "LINHA",
          ehNovaMsg: true,
          remetente: parsedHdr.remetente,
          texto: parsedHdr.corpo
        });
      } else {
        itensSegmentados.push({
          tipo: "LINHA",
          ehNovaMsg: false,
          remetente: "",
          texto: trimmed
        });
      }
    }

    const pautasExtraidas = [];
    const alertas = [];

    let contexto = {
      peritoNome: peritoPadraoResolvido.nome || "",
      peritoObj: peritoPadraoResolvido.peritoObj || null,
      remetentePeritoNome: "",
      remetentePeritoObj: null,
      vara: "",
      local: "",
      endereco: "",
      quantidade: null,
      intervaloMin: null,
      situacao: "",
      mesAno: null,
      cabecalhoPendente: null
    };

    const fecharCabecalhoPendenteSeNecessario = () => {
      const pend = contexto.cabecalhoPendente;
      if (pend && !pend.usadoPorFilho && (pend.peritoNome || pend.quantidade || pend.horarios.length > 0)) {
        const horariosUsar = pend.horarios.length > 0 ? pend.horarios : ["08:00"];
        const varasUsar = pend.varas.length > 0 ? pend.varas : [pend.vara || varaPadrao];
        horariosUsar.forEach((hr, hIdx) => {
          const varaItem = varasUsar[Math.min(hIdx, varasUsar.length - 1)] || varaPadrao;
          const canonica = prepararPautaCanonica({
            peritoNome: pend.peritoNome,
            data: "",
            vara: varaItem,
            local: pend.local,
            endereco: pend.endereco,
            quantidade: pend.quantidade,
            intervaloMin: pend.intervaloMin,
            horaInicio: hr,
            situacao: pend.situacao || situacaoPadrao,
            observacoes: pend.observacoes || ""
          }, bancoPeritos);
          const pendencias = calcularPendenciasPauta(canonica);
          canonica._meta = {
            pendencias,
            confianca: "baixa",
            trechoOrigem: pend.trechoOrigem,
            selecionada: true
          };
          pautasExtraidas.push(canonica);
        });
      }
      contexto.cabecalhoPendente = null;
    };

    for (const seg of itensSegmentados) {
      if (seg.tipo === "VAZIA") {
        fecharCabecalhoPendenteSeNecessario();
        contexto.mesAno = null;
        continue;
      }

      if (seg.ehNovaMsg) {
        fecharCabecalhoPendenteSeNecessario();
        contexto.peritoNome = peritoPadraoResolvido.nome || "";
        contexto.peritoObj = peritoPadraoResolvido.peritoObj || null;
        contexto.vara = "";
        contexto.local = "";
        contexto.endereco = "";
        contexto.quantidade = null;
        contexto.intervaloMin = null;
        contexto.situacao = "";
        contexto.mesAno = null;

        const senderMatch = encontrarPeritoNoTexto(seg.remetente, bancoPeritos);
        contexto.remetentePeritoNome = senderMatch.nome || "";
        contexto.remetentePeritoObj = senderMatch.peritoObj || null;
      }

      const linha = seg.texto;
      if (!linha) continue;

      // 0A. Correção explícita de dia que cai em fim de semana ("O dia 20/02 é domingo")
      const dataFdsRemover = detectarDataInvalidaFimDeSemana(linha, dataRef, contexto.mesAno);
      if (dataFdsRemover) {
        for (let i = pautasExtraidas.length - 1; i >= 0; i--) {
          if (pautasExtraidas[i] && pautasExtraidas[i].data === dataFdsRemover) {
            pautasExtraidas.splice(i, 1);
          }
        }
        const partesIso = dataFdsRemover.split("-");
        alertas.push(`📅 Data ${partesIso[2]}/${partesIso[1]}/${partesIso[0]} ignorada por ter sido indicada como domingo/sábado.`);
        continue;
      }

      // 0B. Filtro anti-ruído (avisos de recesso, feriados, perguntas de secretaria)
      if (ehLinhaRuidoAdministrativo(linha)) {
        continue;
      }

      // 0C. Extração de cláusula "horário corrido" (pode vir sozinha ou após lista na mesma linha)
      const dirCorrido = extrairDiretivaHorarioCorrido(linha, dataRef, contexto.mesAno);
      const linhaEfetiva = dirCorrido.textoSemClausulaCorrido;

      // Verifica se linha define mês/ano de contexto (ex: "Em janeiro chefa, podemos fazer assim:", "Pauta Dezembro/2026")
      const mesAnoLinha = extrairMesAnoContextoLinha(linhaEfetiva || linha, dataRef);
      if (mesAnoLinha) {
        contexto.mesAno = mesAnoLinha;
      }

      // Identifica perito na linha (ou mantém contexto/remetente/peritoPadrao)
      const peritoPre = encontrarPeritoNoTexto(linhaEfetiva || linha, bancoPeritos);
      const peritoEfetivoNomeTmp = peritoPre.nome || contexto.peritoNome || contexto.remetentePeritoNome || peritoPadraoResolvido.nome || "";

      // 0D. Ajustes por data em pautas já extraídas ("No dia 13/01 só posso marcar 25 perícias..., mas no dia 20 e 27 dá as 46")
      if (linhaEfetiva && pautasExtraidas.length > 0 && peritoEfetivoNomeTmp) {
        const ajustes = extrairAjustesVagasPorData(linhaEfetiva, dataRef, contexto.mesAno);
        if (ajustes.length > 0) {
          const pNormAlvo = normLower(peritoEfetivoNomeTmp);
          const todasDatasExistem = ajustes.every((aj) =>
            aj.datas.every((dt) => pautasExtraidas.some((p) => p && p.data === dt && normLower(p.peritoNome || "") === pNormAlvo))
          );
          if (todasDatasExistem) {
            ajustes.forEach((aj) => {
              aj.datas.forEach((dt) => {
                const indicesDt = [];
                pautasExtraidas.forEach((p, idxP) => {
                  if (p && p.data === dt && normLower(p.peritoNome || "") === pNormAlvo) {
                    indicesDt.push(idxP);
                  }
                });
                if (indicesDt.length === 1) {
                  const pTarget = pautasExtraidas[indicesDt[0]];
                  const qtdAntiga = pTarget.quantidade;
                  pTarget.quantidade = aj.quantidade;
                  pTarget.vagas = aj.quantidade;
                  pTarget.horaTermino = calcularHorarioTermino(pTarget.horaInicio, pTarget.intervaloMin, aj.quantidade);
                  if (qtdAntiga && aj.quantidade < qtdAntiga) {
                    const nota = `Ajustado para ${aj.quantidade} vagas (limite diário)`;
                    if (!normLower(pTarget.observacoes || "").includes("limite diario")) {
                      pTarget.observacoes = pTarget.observacoes ? `${pTarget.observacoes} • ${nota}` : nota;
                      pTarget.observacao = pTarget.observacoes;
                    }
                  }
                } else if (indicesDt.length >= 2) {
                  let restante = aj.quantidade;
                  indicesDt.sort((a, b) => String(pautasExtraidas[a].horaInicio || "").localeCompare(String(pautasExtraidas[b].horaInicio || "")));
                  for (let k = indicesDt.length - 1; k >= 0; k--) {
                    const pTarget = pautasExtraidas[indicesDt[k]];
                    if (k === indicesDt.length - 1 && restante <= (pautasExtraidas[indicesDt[0]].quantidade || 20)) {
                      // Cabe tudo no 1º turno; mantém ajuste proporcional ou no 1º turno
                      pautasExtraidas.splice(indicesDt[k], 1);
                    } else if (restante > 0) {
                      const novaQ = Math.min(pTarget.quantidade || restante, restante);
                      pTarget.quantidade = novaQ;
                      pTarget.vagas = novaQ;
                      pTarget.horaTermino = calcularHorarioTermino(pTarget.horaInicio, pTarget.intervaloMin, novaQ);
                      restante -= novaQ;
                    }
                  }
                }
              });
            });
            continue;
          }
        }
      }

      // Identifica datas na linha (após remover cláusulas de horário corrido)
      const { datas, textoSemDatas, ignoradasPorFeriado = [] } = extrairDatasDaLinha(linhaEfetiva, dataRef, contexto.mesAno, {
        listaFeriados,
        subsecaoId
      });
      if (ignoradasPorFeriado.length > 0) {
        alertas.push(`🗓️ Recesso/Feriado ignorado na recorrência semanal: ${ignoradasPorFeriado.join(", ")}.`);
      }
      if (datas.length > 0) {
        const lastIso = datas[datas.length - 1];
        contexto.mesAno = {
          mes: parseInt(lastIso.slice(5, 7), 10),
          ano: parseInt(lastIso.slice(0, 4), 10)
        };
      }

      // Identifica perito no trecho restante
      const peritoLinha = encontrarPeritoNoTexto(textoSemDatas, bancoPeritos);
      if (peritoLinha.nome) {
        if (contexto.cabecalhoPendente && normLower(contexto.cabecalhoPendente.peritoNome) !== normLower(peritoLinha.nome)) {
          fecharCabecalhoPendenteSeNecessario();
        }
        contexto.peritoNome = peritoLinha.nome;
        contexto.peritoObj = peritoLinha.peritoObj;
      }

      const peritoEfetivoNome = peritoLinha.nome || contexto.peritoNome || contexto.remetentePeritoNome || peritoPadraoResolvido.nome || "";
      const peritoEfetivoObj = peritoLinha.peritoObj || contexto.peritoObj || contexto.remetentePeritoObj || peritoPadraoResolvido.peritoObj || null;

      // Se a linha era só diretiva de horário corrido (ex: "Ai ia pedir para, apenas no dia 19, marcar horário corrido."), aplica nos cards já gerados!
      if (datas.length === 0 && dirCorrido.datasCorrido.length > 0) {
        aplicarHorarioCorridoNasPautas(pautasExtraidas, dirCorrido.datasCorrido, peritoEfetivoNome);
        continue;
      }

      // Varas na linha
      const varasLinha = extrairVarasDaLinha(textoSemDatas, subsecaoVaras);
      const varaEfetivaPrimaria = varasLinha[0] || contexto.vara || varaPadrao;
      const regrasPerito = obterRegrasVaraPerito(peritoEfetivoObj, varaEfetivaPrimaria);

      // Quantidade e intervalo
      const qtdLinha = extrairQuantidadeDaLinha(textoSemDatas);
      const intLinha = extrairIntervaloDaLinha(textoSemDatas);

      // Horários explícitos
      const horariosLinha = extrairHorariosDaLinha(textoSemDatas);

      // Local e endereço
      const temPalavraLocal = /\b(justica|predio|forum|clinica|propria|particular|telepericia|consultorio|hospital|vila clinic|noblan|sao lucas|rua|av\.?|avenida|endere[çc]o|remota?|extern[oa]s?|na\s+jef|no\s+jef|fora)\b/i.test(normLower(textoSemDatas));
      let localInfo = { local: "", endereco: "" };
      if (temPalavraLocal) {
        localInfo = extrairLocalEEndereco(textoSemDatas, regrasPerito);
      } else if (contexto.local) {
        localInfo = { local: contexto.local, endereco: contexto.endereco };
      } else {
        localInfo = extrairLocalEEndereco("", regrasPerito);
      }

      // Situação
      const temPalavraSituacao = /\b(nao marcad|em marcacao|marcad|confirmad|pendente)\b/i.test(normLower(textoSemDatas));
      const situacaoEfetiva = temPalavraSituacao
        ? extrairSituacao(textoSemDatas, situacaoPadrao)
        : (contexto.situacao || situacaoPadrao);

      // Se a linha NÃO tem datas: atualiza contexto para as próximas linhas ou guarda como pauta-cabeçalho
      if (datas.length === 0) {
        if (varasLinha.length > 0) contexto.vara = varasLinha[0];
        if (qtdLinha !== null) contexto.quantidade = qtdLinha;
        if (intLinha !== null) contexto.intervaloMin = intLinha;
        if (temPalavraLocal && localInfo.local) {
          contexto.local = localInfo.local;
          contexto.endereco = ehLocalFora(localInfo.local) ? localInfo.endereco : "";
        }
        if (temPalavraSituacao) contexto.situacao = situacaoEfetiva;

        // Só cria cabecalhoPendente se realmente houve menção explícita a perito/qtd/horário/endereço NA LINHA (ignora peritoPadrao herdado sozinho)
        if (peritoLinha.nome || qtdLinha !== null || horariosLinha.length > 0 || (temPalavraLocal && localInfo.endereco)) {
          contexto.cabecalhoPendente = {
            usadoPorFilho: false,
            peritoNome: peritoEfetivoNome,
            peritoObj: peritoEfetivoObj,
            varas: varasLinha,
            vara: varaEfetivaPrimaria,
            local: localInfo.local,
            endereco: localInfo.endereco,
            quantidade: qtdLinha !== null ? qtdLinha : (contexto.quantidade !== null ? contexto.quantidade : regrasPerito.procsPorPauta),
            intervaloMin: intLinha !== null ? intLinha : (contexto.intervaloMin !== null ? contexto.intervaloMin : regrasPerito.intervaloMin),
            horarios: horariosLinha,
            situacao: situacaoEfetiva,
            observacoes: "",
            trechoOrigem: linha
          };
        }
        continue;
      }

      // A linha possui 1 ou mais datas!
      if (contexto.cabecalhoPendente) {
        contexto.cabecalhoPendente.usadoPorFilho = true;
      }

      const intEfetivo = intLinha !== null
        ? intLinha
        : (contexto.intervaloMin !== null ? contexto.intervaloMin : regrasPerito.intervaloMin);

      const varasParaGerar = varasLinha.length > 0
        ? varasLinha
        : [contexto.vara || varaPadrao];

      const horariosExplicitos = horariosLinha.length > 0
        ? horariosLinha
        : ((contexto.cabecalhoPendente && contexto.cabecalhoPendente.horarios.length > 0)
            ? contexto.cabecalhoPendente.horarios
            : []);

      const pp = regrasPerito.padraoPauta;
      const efetivoModo = (modoTurnos && modoTurnos !== "padrao_perito")
        ? modoTurnos
        : ((pp && pp.turnosPadrao) ? pp.turnosPadrao : "manha");

      const criarListaBlocosParaData = (dataIso) => {
        // Quando a mensagem especificou horários explícitos (ex: "às 08h30" ou "às 08h e 13h")
        if (horariosExplicitos.length > 0) {
          const qtdExpl = qtdLinha !== null
            ? qtdLinha
            : (contexto.quantidade !== null ? contexto.quantidade : regrasPerito.procsPorPauta);
          return horariosExplicitos.map((hr, hIdx) => ({
            horaInicio: hr,
            quantidade: qtdExpl,
            vara: varasParaGerar.length === horariosExplicitos.length ? varasParaGerar[hIdx] : varasParaGerar[0],
            observacoes: dirCorrido.temCorridoSemData || dirCorrido.datasCorrido.includes(dataIso)
              ? "Horário corrido (sem intervalo de almoço)"
              : ""
          }));
        }

        // Caso contrário, expande conforme padrão do perito / modoTurnos selecionado
        const horaManha = (pp && pp.horaInicioManha) ? pp.horaInicioManha : "08:00";
        const vagasManha = qtdLinha !== null
          ? qtdLinha
          : (contexto.quantidade !== null ? contexto.quantidade : ((pp && pp.vagasManha) ? pp.vagasManha : regrasPerito.procsPorPauta));
        const varaManha = varasLinha[0] || contexto.vara || (pp && pp.varaManha) || varaPadrao;

        const horaTermManha = calcularHorarioTermino(horaManha, intEfetivo, vagasManha);
        const ehCorridoData = dirCorrido.temCorridoSemData || dirCorrido.datasCorrido.includes(dataIso);
        const pausaAlmoco = (pp && pp.pausaAlmocoMin !== undefined && pp.pausaAlmocoMin !== null)
          ? parseInt(pp.pausaAlmocoMin, 10)
          : (dirCorrido.pausaRestanteMin !== null ? dirCorrido.pausaRestanteMin : 60);

        const horaTardeNormal = (pp && pp.horaInicioTarde)
          ? pp.horaInicioTarde
          : (somarMinutosHora(horaTermManha, Number.isFinite(pausaAlmoco) ? pausaAlmoco : 60) || "13:00");
        const horaTarde = ehCorridoData && horaTermManha && horaTermManha !== "--:--"
          ? horaTermManha
          : horaTardeNormal;
        const vagasTarde = qtdLinha !== null
          ? qtdLinha
          : (contexto.quantidade !== null ? contexto.quantidade : ((pp && pp.vagasTarde) ? pp.vagasTarde : vagasManha));
        const varaTarde = varasLinha.length > 1
          ? varasLinha[1]
          : (varasLinha[0] || contexto.vara || (pp && pp.varaTarde) || varaPadrao);

        if (efetivoModo === "manha_tarde") {
          return [
            { horaInicio: horaManha, quantidade: vagasManha, vara: varaManha, observacoes: "" },
            {
              horaInicio: horaTarde,
              quantidade: vagasTarde,
              vara: varaTarde,
              observacoes: ehCorridoData ? "Horário corrido (sem intervalo de almoço)" : ""
            }
          ];
        }
        if (efetivoModo === "tarde") {
          return [
            {
              horaInicio: horaTarde,
              quantidade: vagasTarde,
              vara: varaTarde,
              observacoes: ehCorridoData ? "Horário corrido (sem intervalo de almoço)" : ""
            }
          ];
        }
        return [
          {
            horaInicio: horaManha,
            quantidade: vagasManha,
            vara: varaManha,
            observacoes: ehCorridoData ? "Horário corrido (sem intervalo de almoço)" : ""
          }
        ];
      };

      // Cruzamento: cada data x blocos/turnos resolvidos
      datas.forEach((dataIso) => {
        const blocos = criarListaBlocosParaData(dataIso);
        blocos.forEach((bloco) => {
          const regrasBloco = obterRegrasVaraPerito(peritoEfetivoObj, bloco.vara);
          const canonica = prepararPautaCanonica({
            peritoNome: peritoEfetivoNome,
            especialidade: regrasBloco.especialidade || regrasPerito.especialidade,
            data: dataIso,
            vara: bloco.vara,
            local: localInfo.local,
            endereco: localInfo.endereco,
            quantidade: bloco.quantidade,
            intervaloMin: intEfetivo,
            horaInicio: bloco.horaInicio,
            situacao: situacaoEfetiva,
            observacoes: bloco.observacoes || ""
          }, bancoPeritos, listaFeriados);

          const pendencias = calcularPendenciasPauta(canonica);
          const confianca = pendencias.length > 0
            ? "baixa"
            : ((peritoEfetivoObj && (qtdLinha !== null || pp) && (horariosExplicitos.length > 0 || pp)) ? "alta" : "media");

          canonica._meta = {
            pendencias,
            confianca,
            trechoOrigem: linha,
            selecionada: true
          };

          inserirOuMesclarPautaExtraida(pautasExtraidas, canonica, {
            localExplicito: temPalavraLocal,
            qtdExplicita: qtdLinha !== null,
            trechoOrigem: linha
          });
        });
      });

      // Aplica diretiva "horário corrido" caso tenha citado outra data na mesma linha
      if (dirCorrido.datasCorrido.length > 0) {
        aplicarHorarioCorridoNasPautas(pautasExtraidas, dirCorrido.datasCorrido, peritoEfetivoNome);
      }

      // Se a linha citou múltiplas varas sem múltiplos horários
      if (varasParaGerar.length > 1 && horariosExplicitos.length === 1) {
        alertas.push(`Linha citou mais de uma Vara (${varasParaGerar.map((v) => v + "ª").join(" e ")}) para um único horário; verifique se deseja dividir.`);
      }
    }

    fecharCabecalhoPendenteSeNecessario();

    if (pautasExtraidas.length === 0) {
      alertas.push("Não foi possível identificar pautas estruturadas no texto. Você pode adicionar uma pauta manualmente ou ajustar o texto.");
    }

    return {
      pautas: pautasExtraidas,
      avisos: Array.from(new Set(alertas))
    };
  }

  root.MaestroWhatsAppParser = {
    MAPA_NOMES_OFICIAIS,
    FERIADOS_PADRAO_JFCE,
    removerAcentos,
    ocupaSalasNoPredio,
    ehLocalFora,
    verificarEhFeriado,
    calcularHorarioTermino,
    somarMinutosHora,
    calcularDataLimite8DiasUteis,
    calcularPrazoDias,
    classificarCategoriaPericia,
    obterOcupacaoSalasTurno,
    normalizarNomePeritoOficial,
    encontrarPeritoNoTexto,
    obterRegrasVaraPerito,
    prepararPautaCanonica,
    calcularPendenciasPauta,
    parsearConversaWhatsApp
  };
})(typeof window !== "undefined" ? window : globalThis);
