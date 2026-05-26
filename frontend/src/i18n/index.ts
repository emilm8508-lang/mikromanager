import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
import LanguageDetector from 'i18next-browser-languagedetector'

import pl from './locales/pl.json'
import en from './locales/en.json'
import es from './locales/es.json'
import de from './locales/de.json'
import fr from './locales/fr.json'
import ru from './locales/ru.json'
import uk from './locales/uk.json'

export const SUPPORTED_LANGS = [
  { code: 'pl', name: 'Polski', flag: '🇵🇱' },
  { code: 'en', name: 'English', flag: '🇬🇧' },
  { code: 'de', name: 'Deutsch', flag: '🇩🇪' },
  { code: 'es', name: 'Español', flag: '🇪🇸' },
  { code: 'fr', name: 'Français', flag: '🇫🇷' },
  { code: 'ru', name: 'Русский', flag: '🇷🇺' },
  { code: 'uk', name: 'Українська', flag: '🇺🇦' },
] as const

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources: {
      pl: { translation: pl },
      en: { translation: en },
      es: { translation: es },
      de: { translation: de },
      fr: { translation: fr },
      ru: { translation: ru },
      uk: { translation: uk },
    },
    fallbackLng: 'pl',
    supportedLngs: ['pl', 'en', 'de', 'es', 'fr', 'ru', 'uk'],
    interpolation: { escapeValue: false },
    detection: {
      order: ['localStorage', 'navigator'],
      lookupLocalStorage: 'mikromanager_lang',
      caches: ['localStorage'],
    },
  })

export default i18n
