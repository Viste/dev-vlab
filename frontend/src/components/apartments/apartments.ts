import type { ApartmentSource, ApartmentStatus } from '../../api/types'

export const STATUS_OPTIONS: { value: ApartmentStatus; label: string; cls: string }[] = [
  { value: 'new', label: 'New', cls: 'text-gray-300 bg-white/5' },
  { value: 'scheduled', label: 'Viewing scheduled', cls: 'text-sky-300 bg-sky-500/10' },
  { value: 'visited', label: 'Visited', cls: 'text-violet-300 bg-violet-500/10' },
  { value: 'shortlist', label: 'Shortlist', cls: 'text-emerald-300 bg-emerald-500/10' },
  { value: 'rejected', label: 'Rejected', cls: 'text-red-300 bg-red-500/10' },
]

export const SOURCE_META: Record<ApartmentSource, { label: string; cls: string }> = {
  cian: { label: 'Cian', cls: 'bg-blue-500/15 text-blue-300' },
  yandex: { label: 'Yandex', cls: 'bg-yellow-500/15 text-yellow-300' },
  avito: { label: 'Avito', cls: 'bg-emerald-500/15 text-emerald-300' },
  domclick: { label: 'Domclick', cls: 'bg-teal-500/15 text-teal-300' },
  other: { label: 'Link', cls: 'bg-white/5 text-gray-400' },
}

export function statusMeta(status: ApartmentStatus) {
  return STATUS_OPTIONS.find((s) => s.value === status) ?? STATUS_OPTIONS[0]!
}

export function sourceMeta(source: string) {
  return SOURCE_META[(source as ApartmentSource) in SOURCE_META ? (source as ApartmentSource) : 'other']
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

export function formatRooms(rooms: number) {
  if (rooms === 0) return 'Studio'
  return `${rooms}-room`
}

export function formatArea(area: number) {
  if (!area) return ''
  return `${area} m²`
}

export function formatFloor(floor: number, total: number) {
  if (!floor && !total) return ''
  if (!total) return `${floor} fl.`
  if (!floor) return `${total} floors`
  return `${floor}/${total} fl.`
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
  if (!u) return 'unknown'
  return u.first_name || u.username
}
