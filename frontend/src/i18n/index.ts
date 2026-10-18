import { createI18n } from 'vue-i18n'
import en from './en'
import ru from './ru'

export type Locale = 'en' | 'ru'
export const locales: Locale[] = ['en', 'ru']
export const dateLocales: Record<Locale, string> = { en: 'en-GB', ru: 'ru-RU' }

const STORAGE_KEY = 'admin_locale'

function detectLocale(): Locale {
  try {
    const saved = localStorage.getItem(STORAGE_KEY)
    if (saved === 'en' || saved === 'ru') return saved
  } catch { /* ignore */ }
  return navigator.language?.toLowerCase().startsWith('ru') ? 'ru' : 'en'
}

function ruPlural(choice: number, choicesLength: number): number {
  if (choice === 0) return 0
  const teen = choice > 10 && choice < 20
  const endsWithOne = choice % 10 === 1
  if (choicesLength < 4) return !teen && endsWithOne ? 1 : 2
  if (!teen && endsWithOne) return 1
  if (!teen && choice % 10 >= 2 && choice % 10 <= 4) return 2
  return 3
}

export const i18n = createI18n({
  legacy: false,
  locale: detectLocale(),
  fallbackLocale: 'en',
  messages: { en, ru },
  pluralRules: { ru: ruPlural },
})

export function setLocale(locale: Locale) {
  i18n.global.locale.value = locale
  try {
    localStorage.setItem(STORAGE_KEY, locale)
  } catch { /* ignore */ }
}
