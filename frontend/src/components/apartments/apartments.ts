import type { ApartmentSource, ApartmentStatus } from '../../api/types'

export const STATUS_OPTIONS: { value: ApartmentStatus; cls: string }[] = [
  { value: 'new', cls: 'text-gray-300 bg-white/5' },
  { value: 'scheduled', cls: 'text-sky-300 bg-sky-500/10' },
  { value: 'visited', cls: 'text-violet-300 bg-violet-500/10' },
  { value: 'shortlist', cls: 'text-emerald-300 bg-emerald-500/10' },
  { value: 'rejected', cls: 'text-red-300 bg-red-500/10' },
]

export const SOURCE_CLS: Record<ApartmentSource, string> = {
  cian: 'bg-blue-500/15 text-blue-300',
  yandex: 'bg-yellow-500/15 text-yellow-300',
  avito: 'bg-emerald-500/15 text-emerald-300',
  domclick: 'bg-teal-500/15 text-teal-300',
  other: 'bg-white/5 text-gray-400',
}

export function statusMeta(status: ApartmentStatus) {
  return STATUS_OPTIONS.find((s) => s.value === status) ?? STATUS_OPTIONS[0]!
}

export function sourceKey(source: string): ApartmentSource {
  return (source as ApartmentSource) in SOURCE_CLS ? (source as ApartmentSource) : 'other'
}

export function sourceClass(source: string) {
  return SOURCE_CLS[sourceKey(source)]
}

export function detectSource(raw: string): ApartmentSource {
  let value = raw.trim()
  if (!value) return 'other'
  if (!/^https?:\/\//i.test(value)) value = 'https://' + value
  let host = ''
  let path = ''
  try {
    const u = new URL(value)
    host = u.hostname.toLowerCase().replace(/^www\./, '')
    path = u.pathname.toLowerCase()
  } catch {
    return 'other'
  }
  const hostIs = (d: string) => host === d || host.endsWith('.' + d)
  if (hostIs('cian.ru')) return 'cian'
  if (hostIs('realty.yandex.ru') || hostIs('realty.ya.ru')) return 'yandex'
  if ((hostIs('yandex.ru') || hostIs('ya.ru')) && path.includes('realty')) return 'yandex'
  if (hostIs('avito.ru')) return 'avito'
  if (hostIs('domclick.ru')) return 'domclick'
  return 'other'
}

const rub = new Intl.NumberFormat('ru-RU')

export function formatPrice(price: number) {
  if (!price) return ''
  return rub.format(price) + ' ₽'
}

export function scoreClass(score: number) {
  if (score >= 4) return 'text-emerald-400'
  if (score >= 3) return 'text-amber-400'
  if (score > 0) return 'text-red-400'
  return 'text-gray-600'
}

export function formatScore(score: number) {
  return score > 0 ? score.toFixed(1) : '—'
}

export function displayName(u?: { username: string; first_name?: string } | null) {
  return u?.first_name || u?.username || ''
}
