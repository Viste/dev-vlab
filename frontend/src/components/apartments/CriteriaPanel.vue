<script setup lang="ts">
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import api from '../../api/client'
import type { ApartmentCriterion } from '../../api/types'
import type { Locale } from '../../i18n'
import { criterionLabel } from './apartments'

const props = defineProps<{ criteria: ApartmentCriterion[] }>()
const emit = defineEmits<{ (e: 'changed'): void }>()

const { t, locale } = useI18n()

const newLabelEn = ref('')
const newLabelRu = ref('')
const newWeight = ref(1)
const error = ref('')
const busy = ref(false)

async function run(fn: () => Promise<unknown>) {
  error.value = ''
  busy.value = true
  try {
    await fn()
  } catch (e: any) {
    error.value = e.response?.data?.error || t('common.requestFailed')
  } finally {
    busy.value = false
    emit('changed')
  }
}

function add() {
  const label_en = newLabelEn.value.trim()
  const label_ru = newLabelRu.value.trim()
  if (!label_en && !label_ru) return
  run(async () => {
    await api.post('/admin/apartment-criteria', {
      label_en,
      label_ru,
      weight: newWeight.value || 1,
      sort_order: (props.criteria.at(-1)?.sort_order ?? 0) + 1,
    })
    newLabelEn.value = ''
    newLabelRu.value = ''
    newWeight.value = 1
  })
}

function update(c: ApartmentCriterion, patch: Partial<ApartmentCriterion>) {
  run(() => api.put(`/admin/apartment-criteria/${c.id}`, patch))
}

function remove(c: ApartmentCriterion) {
  if (!confirm(t('criteria.confirmDelete', { label: criterionLabel(c, locale.value as Locale) }))) return
  run(() => api.delete(`/admin/apartment-criteria/${c.id}`))
}

function move(c: ApartmentCriterion, dir: -1 | 1) {
  const idx = props.criteria.findIndex((x) => x.id === c.id)
  const other = props.criteria[idx + dir]
  if (!other) return
  run(async () => {
    const a = c.sort_order, b = other.sort_order
    const [sa, sb] = a === b ? [idx + dir + 1, idx + 1] : [b, a]
    await api.put(`/admin/apartment-criteria/${c.id}`, { sort_order: sa })
    await api.put(`/admin/apartment-criteria/${other.id}`, { sort_order: sb })
  })
}

function onLabelBlur(c: ApartmentCriterion, field: 'label_en' | 'label_ru', e: Event) {
  const v = (e.target as HTMLInputElement).value.trim()
  if (v !== c[field]) update(c, { [field]: v })
}

function onWeightChange(c: ApartmentCriterion, e: Event) {
  const v = parseFloat((e.target as HTMLInputElement).value)
  if (!isNaN(v) && v > 0 && v !== c.weight) update(c, { weight: v })
}
</script>

<template>
  <div class="bg-[#12121f] border border-gray-800/40 rounded-2xl p-5">
    <div class="flex items-center justify-between mb-1">
      <h2 class="font-semibold">{{ $t('criteria.title') }}</h2>
      <span class="text-xs text-gray-600">{{ $t('criteria.activeCount', { n: criteria.filter((c) => c.is_active).length }) }}</span>
    </div>
    <p class="text-xs text-gray-500 mb-4">{{ $t('criteria.hint') }}</p>

    <div class="space-y-1.5">
      <div v-for="(c, i) in criteria" :key="c.id"
        class="flex items-center gap-2 rounded-xl px-2 py-1.5 transition" :class="c.is_active ? 'bg-white/[0.02]' : 'opacity-50'">
        <div class="flex flex-col">
          <button @click="move(c, -1)" :disabled="i === 0 || busy" class="text-gray-600 hover:text-gray-300 disabled:opacity-30 leading-none text-[10px]">▲</button>
          <button @click="move(c, 1)" :disabled="i === criteria.length - 1 || busy" class="text-gray-600 hover:text-gray-300 disabled:opacity-30 leading-none text-[10px]">▼</button>
        </div>
        <div class="flex-1 grid grid-cols-1 sm:grid-cols-2 gap-1.5">
          <div class="relative">
            <span class="absolute left-2.5 top-1/2 -translate-y-1/2 text-[10px] font-semibold text-gray-600 pointer-events-none">EN</span>
            <input :value="c.label_en" @blur="onLabelBlur(c, 'label_en', $event)" @keydown.enter="($event.target as HTMLInputElement).blur()"
              class="input !py-1.5 !pl-9" :disabled="busy" />
          </div>
          <div class="relative">
            <span class="absolute left-2.5 top-1/2 -translate-y-1/2 text-[10px] font-semibold text-gray-600 pointer-events-none">RU</span>
            <input :value="c.label_ru" @blur="onLabelBlur(c, 'label_ru', $event)" @keydown.enter="($event.target as HTMLInputElement).blur()"
              class="input !py-1.5 !pl-9" :disabled="busy" />
          </div>
        </div>
        <label class="flex items-center gap-1 text-xs text-gray-500 shrink-0">
          ×
          <input type="number" :value="c.weight" @change="onWeightChange(c, $event)" step="0.5" min="0.5" max="10"
            class="input w-16 !py-1.5 !px-2 text-center" :disabled="busy" />
        </label>
        <label class="flex items-center gap-1.5 text-xs text-gray-500 shrink-0 cursor-pointer select-none">
          <input type="checkbox" :checked="c.is_active" @change="update(c, { is_active: ($event.target as HTMLInputElement).checked })" class="accent-red-600" :disabled="busy" />
          {{ $t('criteria.active') }}
        </label>
        <button @click="remove(c)" class="btn-sm-danger shrink-0" :disabled="busy">✕</button>
      </div>
      <div v-if="!criteria.length" class="text-sm text-gray-500 px-2 py-3">{{ $t('criteria.empty') }}</div>
    </div>

    <form @submit.prevent="add" class="flex items-center gap-2 mt-4 pt-4 border-t border-gray-800/40">
      <input v-model="newLabelEn" :placeholder="$t('criteria.nameEn')" class="input flex-1" :disabled="busy" />
      <input v-model="newLabelRu" :placeholder="$t('criteria.nameRu')" class="input flex-1" :disabled="busy" />
      <label class="flex items-center gap-1 text-xs text-gray-500 shrink-0">
        ×
        <input v-model.number="newWeight" type="number" step="0.5" min="0.5" max="10" class="input w-16 !px-2 text-center" :disabled="busy" />
      </label>
      <button type="submit" class="btn shrink-0" :disabled="busy || !(newLabelEn.trim() || newLabelRu.trim())">{{ $t('common.add') }}</button>
    </form>
    <p v-if="error" class="text-sm text-red-500 mt-2">{{ error }}</p>
  </div>
</template>
