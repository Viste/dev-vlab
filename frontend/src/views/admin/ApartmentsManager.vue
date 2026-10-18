<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import api from '../../api/client'
import { useAuthStore } from '../../stores/auth'
import type { Apartment, ApartmentCriterion, ApartmentStatus } from '../../api/types'
import ApartmentCard from '../../components/apartments/ApartmentCard.vue'
import CriteriaPanel from '../../components/apartments/CriteriaPanel.vue'
import { STATUS_OPTIONS, detectSource, sourceMeta } from '../../components/apartments/apartments'

const auth = useAuthStore()

const items = ref<Apartment[]>([])
const criteria = ref<ApartmentCriterion[]>([])
const loading = ref(true)
const error = ref('')

const showForm = ref(false)
const showCriteria = ref(false)
const editingId = ref<number | null>(null)
const saving = ref(false)

type SortKey = 'newest' | 'score' | 'price_asc' | 'price_desc'
const filterStatus = ref<ApartmentStatus | ''>('')
const sortKey = ref<SortKey>('newest')
const sortOptions: { value: SortKey; label: string }[] = [
  { value: 'newest', label: 'Newest' },
  { value: 'score', label: 'Top rated' },
  { value: 'price_asc', label: 'Price ↑' },
  { value: 'price_desc', label: 'Price ↓' },
]

const emptyForm = () => ({
  url: '', title: '', address: '', price: 0, rooms: 1, area: 0, floor: 0, total_floors: 0,
  status: 'new' as ApartmentStatus, notes: '',
})
const form = ref(emptyForm())

const activeCriteria = computed(() => criteria.value.filter((c) => c.is_active))
const previewSource = computed(() => sourceMeta(detectSource(form.value.url)))

const counts = computed(() => {
  const c: Record<string, number> = { '': items.value.length }
  for (const s of STATUS_OPTIONS) c[s.value] = 0
  for (const a of items.value) c[a.status] = (c[a.status] ?? 0) + 1
  return c
})

const visible = computed(() => {
  let list = filterStatus.value ? items.value.filter((a) => a.status === filterStatus.value) : [...items.value]
  switch (sortKey.value) {
    case 'score':
      list.sort((a, b) => b.score - a.score || +new Date(b.created_at) - +new Date(a.created_at))
      break
    case 'price_asc':
      list.sort((a, b) => (a.price || Infinity) - (b.price || Infinity))
      break
    case 'price_desc':
      list.sort((a, b) => b.price - a.price)
      break
    default:
      list.sort((a, b) => +new Date(b.created_at) - +new Date(a.created_at))
  }
  return list
})

async function load() {
  error.value = ''
  try {
    const [a, c] = await Promise.all([
      api.get<Apartment[]>('/admin/apartments'),
      api.get<ApartmentCriterion[]>('/admin/apartment-criteria'),
    ])
    items.value = a.data
    criteria.value = c.data
  } catch (e: any) {
    error.value = e.response?.data?.error || 'Failed to load'
  } finally {
    loading.value = false
  }
}

function replaceItem(updated: Apartment) {
  const idx = items.value.findIndex((x) => x.id === updated.id)
  if (idx >= 0) items.value[idx] = updated
  else items.value.unshift(updated)
}

function openNew() {
  editingId.value = null
  form.value = emptyForm()
  showForm.value = true
  window.scrollTo({ top: 0, behavior: 'smooth' })
}

function openEdit(a: Apartment) {
  editingId.value = a.id
  form.value = {
    url: a.url, title: a.title === a.url ? '' : a.title, address: a.address || '', price: a.price, rooms: a.rooms,
    area: a.area, floor: a.floor, total_floors: a.total_floors, status: a.status, notes: a.notes || '',
  }
  showForm.value = true
  window.scrollTo({ top: 0, behavior: 'smooth' })
}

async function save() {
  error.value = ''
  if (!form.value.url.trim()) {
    error.value = 'Link is required'
    return
  }
  saving.value = true
  try {
    const payload = { ...form.value, price: Number(form.value.price) || 0, area: Number(form.value.area) || 0 }
    const { data } = editingId.value
      ? await api.put<Apartment>(`/admin/apartments/${editingId.value}`, payload)
      : await api.post<Apartment>('/admin/apartments', payload)
    replaceItem(data)
    showForm.value = false
  } catch (e: any) {
    error.value = e.response?.data?.error || 'Failed to save'
  } finally {
    saving.value = false
  }
}

async function remove(id: number) {
  if (!confirm('Delete this apartment and all its ratings?')) return
  await api.delete(`/admin/apartments/${id}`)
  items.value = items.value.filter((x) => x.id !== id)
}

async function setStatus(id: number, status: ApartmentStatus) {
  const { data } = await api.put<Apartment>(`/admin/apartments/${id}`, { status })
  replaceItem(data)
}

async function rate(id: number, payload: { scores: Record<string, number>; comment: string }) {
  try {
    const { data } = await api.put<Apartment>(`/admin/apartments/${id}/rating`, payload)
    replaceItem(data)
  } catch (e: any) {
    error.value = e.response?.data?.error || 'Failed to save rating'
  }
}

async function unrate(id: number) {
  const { data } = await api.delete<Apartment>(`/admin/apartments/${id}/rating`)
  replaceItem(data)
}

async function onCriteriaChanged() {
  await load()
}

onMounted(load)
</script>

<template>
  <div>
    <div class="flex items-center justify-between mb-6 gap-4 flex-wrap">
      <div>
        <h1 class="text-xl font-bold">Apartments</h1>
        <p class="text-gray-500 text-sm mt-0.5">Paste links from Cian, Yandex Realty or anywhere else, then rate them together.</p>
      </div>
      <div class="flex items-center gap-2">
        <button @click="showCriteria = !showCriteria" class="btn-secondary" :class="showCriteria && '!bg-white/10 !text-white'">Criteria</button>
        <button @click="openNew" class="btn">Add apartment</button>
      </div>
    </div>

    <div v-if="showCriteria" class="mb-6">
      <CriteriaPanel :criteria="criteria" @changed="onCriteriaChanged" />
    </div>

    <form v-if="showForm" @submit.prevent="save" class="bg-[#12121f] border border-gray-800/40 rounded-2xl p-5 mb-6 space-y-3">
      <div class="flex items-center justify-between">
        <h2 class="font-semibold">{{ editingId ? 'Edit apartment' : 'New apartment' }}</h2>
        <span class="text-[10px] uppercase tracking-wider font-semibold px-2 py-0.5 rounded-md" :class="previewSource.cls">{{ previewSource.label }}</span>
      </div>
      <input v-model="form.url" placeholder="Link (cian.ru, realty.yandex.ru, ...)" class="input" required autofocus />
      <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
        <input v-model="form.title" placeholder="Title, e.g. 2-room near Sokol" class="input" />
        <input v-model="form.address" placeholder="Address" class="input" />
      </div>
      <div class="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div>
          <label class="label">Price, ₽</label>
          <input v-model.number="form.price" type="number" min="0" step="1000" class="input" />
        </div>
        <div>
          <label class="label">Rooms (0 = studio)</label>
          <input v-model.number="form.rooms" type="number" min="0" max="20" class="input" />
        </div>
        <div>
          <label class="label">Area, m²</label>
          <input v-model.number="form.area" type="number" min="0" step="0.1" class="input" />
        </div>
        <div>
          <label class="label">Floor</label>
          <input v-model.number="form.floor" type="number" min="0" class="input" />
        </div>
        <div>
          <label class="label">Total floors</label>
          <input v-model.number="form.total_floors" type="number" min="0" class="input" />
        </div>
      </div>
      <div class="grid grid-cols-1 md:grid-cols-[12rem_1fr] gap-3">
        <div>
          <label class="label">Status</label>
          <select v-model="form.status" class="input">
            <option v-for="s in STATUS_OPTIONS" :key="s.value" :value="s.value" class="bg-[#12121f]">{{ s.label }}</option>
          </select>
        </div>
        <div>
          <label class="label">Notes</label>
          <textarea v-model="form.notes" rows="2" placeholder="Anything worth remembering: agent contact, viewing time, pros and cons..." class="input resize-y"></textarea>
        </div>
      </div>
      <div class="flex gap-2 pt-1">
        <button type="submit" class="btn" :disabled="saving">{{ saving ? 'Saving...' : 'Save' }}</button>
        <button type="button" @click="showForm = false" class="btn-secondary">Cancel</button>
      </div>
    </form>

    <p v-if="error" class="text-sm text-red-500 mb-4">{{ error }}</p>

    <div class="flex items-center gap-2 flex-wrap mb-4">
      <button @click="filterStatus = ''" class="tab-link" :class="filterStatus === '' && 'tab-active'">All <span class="text-gray-600 ml-1">{{ counts[''] }}</span></button>
      <button v-for="s in STATUS_OPTIONS" :key="s.value" @click="filterStatus = s.value" class="tab-link" :class="filterStatus === s.value && 'tab-active'">
        {{ s.label }} <span class="text-gray-600 ml-1">{{ counts[s.value] }}</span>
      </button>
      <div class="flex-1"></div>
      <div class="flex items-center gap-1">
        <span class="text-xs text-gray-600 mr-1">Sort</span>
        <button v-for="o in sortOptions" :key="o.value" @click="sortKey = o.value" class="tab-link-sm" :class="sortKey === o.value && 'tab-active'">{{ o.label }}</button>
      </div>
    </div>

    <div v-if="loading" class="text-sm text-gray-500 py-10 text-center">Loading...</div>
    <div v-else-if="!visible.length" class="bg-[#12121f] border border-dashed border-gray-800/60 rounded-2xl p-10 text-center">
      <p class="text-gray-400 text-sm">{{ items.length ? 'Nothing with this status yet.' : 'No apartments yet. Add the first link.' }}</p>
      <button v-if="!items.length" @click="openNew" class="btn mt-4">Add apartment</button>
    </div>
    <div v-else class="space-y-3">
      <ApartmentCard v-for="a in visible" :key="a.id" :apartment="a" :criteria="activeCriteria" :current-user-id="auth.user?.id ?? 0"
        @edit="openEdit" @delete="remove" @status="setStatus" @rate="rate" @unrate="unrate" />
    </div>
  </div>
</template>
