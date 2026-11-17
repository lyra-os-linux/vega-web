//! Idioma do painel (vega-web#25): o escolhido no login, guardado na sessão.
//! Fica na biblioteca para os textos do diagnóstico e do Pedir ajuda.

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Lang {
    #[default]
    Pt,
    En,
    Es,
}

impl Lang {
    pub fn parse(value: Option<&str>) -> Self {
        match value.map(str::trim) {
            Some("en" | "en-US") => Self::En,
            Some("es" | "es-ES") => Self::Es,
            _ => Self::Pt,
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            Self::Pt => "pt-BR",
            Self::En => "en-US",
            Self::Es => "es-ES",
        }
    }

    pub fn text<'a>(self, pt: &'a str, en: &'a str, es: &'a str) -> &'a str {
        match self {
            Self::Pt => pt,
            Self::En => en,
            Self::Es => es,
        }
    }
}
