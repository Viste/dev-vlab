<script setup lang="ts">
import { computed, ref } from 'vue'
import type { Apartment, ApartmentCriterion, ApartmentStatus } from '../../api/types'
import StarRating from './StarRating.vue'
import {
  STATUS_OPTIONS, statusMeta, sourceMeta, formatPrice, formatRooms, formatArea, formatFloor,
  scoreClass, formatScore, displayName,
} from './apartments'

const props = defineProps<{
  apartment: Apartment
  criteria: ApartmentCriterion[]
  currentUserId: number
}>()

const emit = defineEmits<{
  (e: 'edit', apartment: Apartment): void
  (e: 'delete', id: number): void
  (e: 'status', id: number, status: ApartmentStatus): void
  (e: 'rate', id: number, payload: { scores: Record<string, number>; comment: string }): void
  (e: 'unrate', id: number): void
}>()

const rating = ref(false)
const saving = ref(false)
const draftScores = ref<Record<string, number>>({})
const draftComment = ref('')
const expanded = ref<Record<number, boolean>>({})

const myRating = computed(() => props.apartment.ratings?.find((r) => r.user_id === props.currentUserId))
const meta = computed(() => statusMeta(props.apartment.status))
const source = computed(() => sourceMeta(props.apartment.source))

const facts = computed(() => {
  const a = props.apartment
  return [formatPrice(a.price), a.rooms || a.area ? formatRooms(a.rooms) : '', formatArea(a.area), formatFloor(a.floor, a.total_floors)].filter(Boolean)
})

const draftScore = computed(() => {
  let sum = 0
  let wsum = 0
  for (const c of props.criteria) {
    const v = draftScores.value[c.key] ?? 0
    if (v <= 0) continue
    const w = c.weight > 0 ? c.weight : 1
    sum += v * w
    wsum += w
  }
  return wsum ? Math.round((sum / wsum) * 100) / 100 : 0
})

function openRating() {
  const existing = myRating.value
  const scores: Record<string, number> = {}
  for (const c of props.criteria) scores[c.key] = existing?.scores?.[c.key] ?? 0
  draftScores.value = scores
  draftComment.value = existing?.comment ?? ''
  rating.value = true
}

async function saveRating() {
  saving.value = true
  try {
    emit('rate', props.apartment.id, { scores: { ...draftScores.value }, comment: draftComment.value })
    rating.value = false
  } finally {
    saving.value = false
  }
}

function removeRating() {
  if (!confirm('Remove your rating?')) return
  emit('unrate', props.apartment.id)
  rating.value = false
}

function labelFor(key: string) {
  return props.criteria.find((c) => c.key === key)?.label ?? key
}

function ratedEntries(scores: Record<string, number>) {
  return props.criteria.filter((c) => (scores?.[c.key] ?? 0) > 0).map((c) => ({ key: c.key, label: c.label, value: scores[c.key]! }))
}

function formatDate(s: string) {
  return new Date(s).toLocaleDateString('ru-RU', { day: '2-digit', month: 'short' })
}
</script>

<template>
  <div class="bg-[#12121f] border border-gray-800/40 rounded-2xl p-5 hover:border-gray-700/50 transition">
    <div class="flex items-start gap-4">
      <div class="flex-1 min-w-0">
        <div class="flex items-center gap-2 flex-wrap">
          <span class="text-[10px] uppercase tracking-wider font-semibold px-2 py-0.5 rounded-md" :class="source.cls">{{ source.label }}</span>
          <a :href="apartment.url" target="_blank" rel="noopener noreferrer"
            class="font-semibold text-gray-100 hover:text-white truncate max-w-full inline-flex items-center gap-1.5 group">
            <span class="truncate">{{ apartment.title }}</span>
            <svg class="w-3.5 h-3.5 shrink-0 text-gray-600 group-hover:text-red-400 transition" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
            </svg>
          </a>
        </div>
        <p v-if="apartment.address" class="text-sm text-gray-500 mt-1 truncate">{{ apartment.address }}</p>
        <div v-if="facts.length" class="flex items-center gap-x-3 gap-y-1 flex-wrap mt-2 text-sm">
          <span v-for="(f, i) in facts" :key="i" :class="i === 0 && apartment.price ? 'text-gray-100 font-semibold' : 'text-gray-400'">{{ f }}</span>
        </div>
      </div>

      <div class="text-right shrink-0">
        <div class="text-3xl font-bold leading-none" :class="scoreClass(apartment.score)">{{ formatScore(apartment.score) }}</div>
        <div class="text-[10px] uppercase tracking-wider text-gray-600 mt-1">{{ apartment.ratings?.length || 0 }} {{ apartment.ratings?.length === 1 ? 'rating' : 'ratings' }}</div>
      </div>
    </div>

    <div class="flex items-center gap-3 flex-wrap mt-4">
      <div class="relative">
        <select :value="apartment.status" @change="emit('status', apartment.id, ($event.target as HTMLSelectElement).value as ApartmentStatus)"
          class="appearance-none text-xs font-medium pl-3 pr-7 py-1.5 rounded-lg cursor-pointer focus:outline-none border border-transparent hover:border-gray-700/50 transition"
          :class="meta.cls">
          <option v-for="s in STATUS_OPTIONS" :key="s.value" :value="s.value" class="bg-[#12121f] text-gray-200">{{ s.label }}</option>
        </select>
        <svg class="w-3 h-3 absolute right-2 top-1/2 -translate-y-1/2 pointer-events-none opacity-60" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </div>
      <span class="text-xs text-gray-600">added by {{ displayName(apartment.creator) }} · {{ formatDate(apartment.created_at) }}</span>
      <div class="flex-1"></div>
      <button @click="rating ? (rating = false) : openRating()" class="btn-sm" :class="myRating && 'text-amber-300'">
        {{ rating ? 'Close' : myRating ? 'Edit my rating' : 'Rate' }}
      </button>
      <button @click="emit('edit', apartment)" class="btn-sm">Edit</button>
      <button @click="emit('delete', apartment.id)" class="btn-sm-danger">Delete</button>
    </div>

    <p v-if="apartment.notes" class="text-sm text-gray-400 mt-3 whitespace-pre-line border-l-2 border-gray-800 pl-3">{{ apartment.notes }}</p>

    <div v-if="rating" class="mt-4 bg-white/[0.03] border border-gray-800/50 rounded-xl p-4">
      <div class="flex items-center justify-between mb-3">
        <h3 class="text-sm font-semibold">Your rating</h3>
        <span class="text-sm font-bold" :class="scoreClass(draftScore)">{{ formatScore(draftScore) }}</span>
      </div>
      <div v-if="!criteria.length" class="text-sm text-gray-500">No active criteria. Add some in the Criteria panel.</div>
      <div v-else class="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2.5">
        <div v-for="c in criteria" :key="c.key" class="flex items-center justify-between gap-3">
          <span class="text-sm text-gray-300 truncate">
            {{ c.label }}
            <span v-if="c.weight !== 1" class="text-[10px] text-gray-600 ml-1">×{{ c.weight }}</span>
          </span>
          <StarRating v-model="draftScores[c.key]" />
        </div>
      </div>
      <textarea v-model="draftComment" rows="2" placeholder="Comment (optional)" class="input mt-4 resize-y"></textarea>
      <div class="flex items-center gap-2 mt-3">
        <button @click="saveRating" class="btn" :disabled="saving">Save rating</button>
        <button @click="rating = false" class="btn-secondary">Cancel</button>
        <div class="flex-1"></div>
        <button v-if="myRating" @click="removeRating" class="btn-sm-danger">Remove my rating</button>
      </div>
    </div>

    <div v-if="apartment.ratings?.length" class="mt-4 space-y-2">
      <div v-for="r in apartment.ratings" :key="r.id" class="rounded-xl bg-white/[0.02] border border-gray-800/40 px-4 py-3">
        <div class="flex items-center gap-3">
          <div class="w-7 h-7 rounded-full bg-gray-800 flex items-center justify-center text-[11px] font-bold shrink-0"
            :class="r.user_id === currentUserId ? 'text-red-400' : 'text-sky-400'">
            {{ (displayName(r.user)[0] || '?').toUpperCase() }}
          </div>
          <div class="min-w-0 flex-1">
            <div class="flex items-center gap-2">
              <span class="text-sm font-medium">{{ displayName(r.user) }}</span>
              <span v-if="r.user_id === currentUserId" class="text-[10px] text-gray-600">you</span>
              <span class="text-xs text-gray-600">· {{ formatDate(r.updated_at) }}</span>
            </div>
            <p v-if="r.comment" class="text-sm text-gray-400 mt-0.5 whitespace-pre-line">{{ r.comment }}</p>
          </div>
          <button @click="expanded[r.id] = !expanded[r.id]" class="text-lg font-bold shrink-0 hover:opacity-80 transition" :class="scoreClass(r.score)" title="Show breakdown">
            {{ formatScore(r.score) }}
          </button>
        </div>
        <div v-if="expanded[r.id]" class="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1 mt-3 pl-10">
          <div v-for="e in ratedEntries(r.scores)" :key="e.key" class="flex items-center justify-between gap-3 text-xs">
            <span class="text-gray-400 truncate">{{ labelFor(e.key) }}</span>
            <StarRating :model-value="e.value" readonly size="sm" />
          </div>
          <div v-if="!ratedEntries(r.scores).length" class="text-xs text-gray-600">No criteria scored</div>
        </div>
      </div>
    </div>
  </div>
</template>
