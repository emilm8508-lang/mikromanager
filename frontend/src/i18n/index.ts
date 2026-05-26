import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
import LanguageDetector from 'i18next-browser-languagedetector'

import pl from './locales/pl.json'
import en from './locales/en.json'

export const SUPPORTED_LANGS = [
  { code: 'pl', name: 'Polski', flag: '🇵🇱' },
  { code: 'en', name: 'English', flag: '🇬🇧' },
] as const

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources: {
      pl: { translation: pl },
      en: { translation: en },
    },
    fallbackLng: 'pl',
    supportedLngs: ['pl', 'en'],
    interpolation: { escapeValue: false },
    detection: {
      order: ['localStorage', 'navigator'],
      lookupLocalStorage: 'mikromanager_lang',
      caches: ['localStorage'],
    },
  })

export default i18n
