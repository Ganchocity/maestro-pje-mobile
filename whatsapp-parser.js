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
        (l.includes("predio") || l.includes("justica") || l.includes("no predio") || l.includes("sala jf") || l.includes("forum") || l.includes("sede")) &&
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

  function verificarEhFeriado(dataIso, listaFeriados = FERIADOS_PADRAO_JFCE) {
    if (!dataIso) return null;
    const item = (listaFeriados || FERIADOS_PADRAO_JFCE).find((f) => {
      if (!f || !f.data) return false;
      if (f.data === dataIso) return true;
      if (f.recorrente && dataIso.length === 10 && f.data.length === 10) {
        return dataIso.slice(5) === f.data.slice(5);
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

  function calcularDataLimite8DiasUteis(dataStr, diasUteis = 8, listaFeriados = FERIADOS_PADRAO_JFCE) {
    if (!dataStr || !/^\d{4}-\d{2}-\d{2}$/.test(dataStr)) return "";
    const [ano, mes, dia] = dataStr.split("-").map(Number);
    const d = new Date(ano, mes - 1, dia, 12, 0, 0);
    if (isNaN(d.getTime())) return "";
    let contagem = 0;
    while (contagem < diasUteis) {
      d.setDate(d.getDate() - 1);
      const dw = d.getDay();
      const iso = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
      if (dw !== 0 && dw !== 6 && !verificarEhFeriado(iso, listaFeriados)) {
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
    const txt = normLower(`${nomePerito || ""} ${especialidade || ""}`);
    if (txt.includes("social") || txt.includes("assist") || txt.includes("loas")) return "social";
    if (txt.includes("engenharia") || txt.includes("contabil") || txt.includes("grafotec")) return "outras";
    return "medica";
  }

  function obterOcupacaoSalasTurno(dataIso, turno, pautasLista = [], ignorarId = null) {
    if (!dataIso) return { totalSalas: 0, peritos: [] };
    const peritosMap = new Map();
    (pautasLista || []).forEach((p) => {
      if (!p || (ignorarId && p.id === ignorarId)) return;
      if (p.data !== dataIso) return;
      if (!ocupaSalasNoPredio(p.local)) return;
      const h = parseInt((p.horaInicio || p.hora || "08:00").split(":")[0], 10);
      const tPauta = h < 12 ? "manha" : "tarde";
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
      return { especialidade: "", intervaloMin: 10, procsPorPauta: 20, endereco: "", atendeFora: false };
    }
    const vStr = String(vara || "").replace(/\D/g, "");
    const r = (vStr && peritoObj.regrasPorVara && peritoObj.regrasPorVara[vStr]) ? peritoObj.regrasPorVara[vStr] : null;
    return {
      especialidade: peritoObj.titulada || (r && r.atuacao) || peritoObj.atuacao || "",
      intervaloMin: parseInt((r && r.intervaloMin) || peritoObj.intervaloMin, 10) || 10,
      procsPorPauta: parseInt((r && r.procsPorPauta) || peritoObj.procsPorPauta, 10) || 20,
      endereco: String(peritoObj.endereco || peritoObj.enderecoClinica || "").trim(),
      atendeFora: Boolean(peritoObj.atendeFora || peritoObj.endereco || peritoObj.enderecoClinica)
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

  function extrairMesAnoContextoLinha(linha, dataRef) {
    const lNorm = normLower(linha);
    const ref = dataRef instanceof Date ? dataRef : new Date();
    // Ex: "dezembro/2026", "dezembro de 2026", "pauta dezembro"
    for (const [nomeMes, numMes] of Object.entries(MESES_EXTENSO)) {
      if (nomeMes.length < 3) continue;
      const re = new RegExp(`\\b${nomeMes}(?:\\s*(?:/|de)?\\s*(20\\d{2}))?\\b`, "i");
      const m = lNorm.match(re);
      if (m) {
        // Garante que não é um dia explícito "09 de dezembro"
        const antes = lNorm.slice(0, m.index || 0);
        if (!/\b\d{1,2}\s*(?:de)?\s*$/.test(antes)) {
          const ano = m[1] ? parseInt(m[1], 10) : inferirAnoSemAno(numMes, 15, ref);
          return { mes: numMes, ano };
        }
      }
    }
    const mNum = lNorm.match(/\b(0?[1-9]|1[0-2])\s*\/\s*(20\d{2})\b/);
    if (mNum) {
      return { mes: parseInt(mNum[1], 10), ano: parseInt(mNum[2], 10) };
    }
    return null;
  }

  function extrairDatasDaLinha(linha, dataRef, contextoMesAno = null) {
    const datas = [];
    const mascarado = { texto: String(linha || "") };
    const adicionarData = (iso) => {
      if (iso && !datas.includes(iso)) datas.push(iso);
    };

    let work = String(linha || "");

    // 1. ISO YYYY-MM-DD
    work = work.replace(/\b(20\d{2})-(\d{1,2})-(\d{1,2})\b/g, (full, a, m, d) => {
      const iso = validarDataParts(parseInt(a, 10), parseInt(m, 10), parseInt(d, 10));
      if (iso) {
        adicionarData(iso);
        return " __DATA__ ";
      }
      return full;
    });

    // 2. Lista de dias com mês por extenso: "dias 07, 14 e 21 de dezembro (de 2026)?"
    const mesesKeys = Object.keys(MESES_EXTENSO).join("|");
    const reListaMesExtenso = new RegExp(`\\b(?:dias?\\s+)?((?:\\d{1,2}\\s*(?:,|;|e|\\/)\\s*)+\\d{1,2})\\s+de\\s+(${mesesKeys})(?:\\s+de\\s+(20\\d{2}))?\\b`, "gi");
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

    // 4. Data única por extenso: "09 de dezembro (de 2026)?"
    const reDataExtenso = new RegExp(`\\b(\\d{1,2})\\s+de\\s+(${mesesKeys})(?:\\s+de\\s+(20\\d{2}))?\\b`, "gi");
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

    // 6. Data DD/MM sem ano (mas não mm/2026)
    work = work.replace(/\b(\d{1,2})\/(\d{1,2})\b/g, (full, dStr, mStr) => {
      const d = parseInt(dStr, 10);
      const m = parseInt(mStr, 10);
      if (m < 1 || m > 12 || d < 1 || d > 31) return full;
      const anoNum = inferirAnoSemAno(m, d, dataRef, contextoMesAno);
      const iso = validarDataParts(anoNum, m, d);
      if (iso) {
        adicionarData(iso);
        return " __DATA__ ";
      }
      return full;
    });

    // 7. "dia 12" ou "dias 05, 12 e 19" quando há contextoMesAno definido
    if (datas.length === 0 && contextoMesAno && contextoMesAno.mes) {
      work = work.replace(/\bdias?\s+((?:\d{1,2}\s*(?:,|;|e)?\s*)+)/gi, (full, listaDias) => {
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
    return { datas, textoSemDatas: mascarado.texto };
  }

  function extrairHorariosDaLinha(texto) {
    const horarios = [];
    const l = normLower(texto);

    const adicionarHora = (hhmm) => {
      if (hhmm && !horarios.includes(hhmm)) horarios.push(hhmm);
    };

    // Padrões explícitos: 08:00, 12:15, 08h30, 8h, às 9h, 13h00
    const reHora = /(?:^|[\s(,\-–])(?:a\s*partir\s*d[ao]s?|as\s+)?(\d{1,2})\s*(?:(?::|h)\s*(\d{2})?|hrs?|hs?)\b(?!\s*min)/gi;
    let m;
    while ((m = reHora.exec(l)) !== null) {
      const trechoCompleto = m[0];
      const temSeparadorHora = trechoCompleto.includes(":") || /\d\s*h/i.test(trechoCompleto);
      if (!temSeparadorHora) continue;
      const h = parseInt(m[1], 10);
      const min = m[2] ? parseInt(m[2], 10) : 0;
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
      local = "Clínica Própria";
    } else if (l.includes("consultorio") || l.includes("hospital") || l.includes("domiciliar") || l.includes("fora do predio") || l.includes("fora do forum") || l.includes("externa")) {
      local = "Fora / Consultório / Hospital";
    } else if (l.includes("justica federal") || l.includes("no predio") || l.includes("predio da justica") || l.includes("forum") || l.includes("sede")) {
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
      local = "Clínica Própria";
    }

    // Herança do cadastro do perito se não informado no texto
    if (!local) {
      if (peritoRegras && peritoRegras.atendeFora) {
        local = "Clínica Própria";
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
    const dataRef = opcoes.dataReferencia instanceof Date ? opcoes.dataReferencia : new Date();

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
      peritoNome: "",
      peritoObj: null,
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
        contexto.peritoNome = "";
        contexto.peritoObj = null;
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

      // Verifica se linha define mês/ano de contexto (ex: "Pauta Dezembro/2026")
      const mesAnoLinha = extrairMesAnoContextoLinha(linha, dataRef);
      if (mesAnoLinha) {
        contexto.mesAno = mesAnoLinha;
      }

      // Identifica datas na linha
      const { datas, textoSemDatas } = extrairDatasDaLinha(linha, dataRef, contexto.mesAno);

      // Identifica perito na linha
      const peritoLinha = encontrarPeritoNoTexto(textoSemDatas, bancoPeritos);
      if (peritoLinha.nome) {
        // Se mudou o perito, fecha eventual pauta-cabeçalho anterior sem datas
        if (contexto.cabecalhoPendente && normLower(contexto.cabecalhoPendente.peritoNome) !== normLower(peritoLinha.nome)) {
          fecharCabecalhoPendenteSeNecessario();
        }
        contexto.peritoNome = peritoLinha.nome;
        contexto.peritoObj = peritoLinha.peritoObj;
      }

      const peritoEfetivoNome = peritoLinha.nome || contexto.peritoNome || contexto.remetentePeritoNome || "";
      const peritoEfetivoObj = peritoLinha.peritoObj || contexto.peritoObj || contexto.remetentePeritoObj || null;

      // Varas na linha
      const varasLinha = extrairVarasDaLinha(textoSemDatas, subsecaoVaras);
      const varaEfetivaPrimaria = varasLinha[0] || contexto.vara || varaPadrao;
      const regrasPerito = obterRegrasVaraPerito(peritoEfetivoObj, varaEfetivaPrimaria);

      // Quantidade e intervalo
      const qtdLinha = extrairQuantidadeDaLinha(textoSemDatas);
      const intLinha = extrairIntervaloDaLinha(textoSemDatas);

      // Horários
      const horariosLinha = extrairHorariosDaLinha(textoSemDatas);

      // Local e endereço
      const temPalavraLocal = /\b(justica|predio|forum|clinica|propria|particular|telepericia|consultorio|hospital|vila clinic|noblan|sao lucas|rua|av\.?|avenida|endere[çc]o|remota?|externa)\b/i.test(normLower(textoSemDatas));
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
          contexto.endereco = localInfo.endereco;
        }
        if (temPalavraSituacao) contexto.situacao = situacaoEfetiva;

        // Se a linha parecia descrever uma pauta completa exceto a data, guarda caso nenhuma linha com data venha depois
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
            observacoes: linha.length <= 140 && temPalavraLocal && !localInfo.endereco ? "" : "",
            trechoOrigem: linha
          };
        }
        continue;
      }

      // A linha possui 1 ou mais datas!
      if (contexto.cabecalhoPendente) {
        contexto.cabecalhoPendente.usadoPorFilho = true;
      }

      const qtdEfetiva = qtdLinha !== null
        ? qtdLinha
        : (contexto.quantidade !== null ? contexto.quantidade : regrasPerito.procsPorPauta);
      const intEfetivo = intLinha !== null
        ? intLinha
        : (contexto.intervaloMin !== null ? contexto.intervaloMin : regrasPerito.intervaloMin);

      const horariosParaGerar = horariosLinha.length > 0
        ? horariosLinha
        : ((contexto.cabecalhoPendente && contexto.cabecalhoPendente.horarios.length > 0)
            ? contexto.cabecalhoPendente.horarios
            : ["08:00"]);

      const varasParaGerar = varasLinha.length > 0
        ? varasLinha
        : [contexto.vara || varaPadrao];

      // Cruzamento: cada data x cada horário informado na linha
      datas.forEach((dataIso) => {
        horariosParaGerar.forEach((horaStr, hIdx) => {
          // Se há 2 horários (ex: 08h e 13h) e 2 varas (ex: 19ª e 31ª), casa na ordem; senão usa a vara correspondente ou primeira
          const varaEscolhida = varasParaGerar.length === horariosParaGerar.length
            ? varasParaGerar[hIdx]
            : varasParaGerar[0];

          const canonica = prepararPautaCanonica({
            peritoNome: peritoEfetivoNome,
            especialidade: regrasPerito.especialidade,
            data: dataIso,
            vara: varaEscolhida,
            local: localInfo.local,
            endereco: localInfo.endereco,
            quantidade: qtdEfetiva,
            intervaloMin: intEfetivo,
            horaInicio: horaStr,
            situacao: situacaoEfetiva,
            observacoes: ""
          }, bancoPeritos);

          const pendencias = calcularPendenciasPauta(canonica);
          const confianca = pendencias.length > 0
            ? "baixa"
            : ((peritoEfetivoObj && qtdLinha !== null && horariosLinha.length > 0) ? "alta" : "media");

          canonica._meta = {
            pendencias,
            confianca,
            trechoOrigem: linha,
            selecionada: true
          };

          pautasExtraidas.push(canonica);
        });
      });

      // Se a linha citou múltiplas varas sem múltiplos horários (ex: "dia 10/12, 19ª e 31ª Varas, 08h"), apenas avisa caso o usuário queira duplicar manualmente
      if (varasParaGerar.length > 1 && horariosParaGerar.length === 1) {
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