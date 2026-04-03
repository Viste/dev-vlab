<script setup lang="ts">
import { ref, onMounted } from 'vue'
import api from '../../api/client'
import type { MusicRelease } from '../../api/types'

const items = ref<MusicRelease[]>([])
const showForm = ref(false)
const editingId = ref<number | null>(null)
const form = ref({ title: '', artist: '', cover_url: '', release_url: '', embed_url: '', sort_order: 0 })

async function load() {
  const { data } = await api.get<MusicRelease[]>('/music/releases')
  items.value = data
}

function openNew() {
  editingId.value = null
  form.value = { title: '', artist: '', cover_url: '', release_url: '', embed_url: '', sort_order: 0 }
  showForm.value = true
}

function openEdit(item: MusicRelease) {
  editingId.value = item.id
  form.value = { title: item.title, artist: item.artist || '', cover_url: item.cover_url || '', release_url: item.release_url || '', embed_url: item.embed_url || '', sort_order: item.sort_order }
  showForm.value = true
}

async function save() {
  if (editingId.value) {
    await api.put(`/admin/music/releases/${editingId.value}`, form.value)
  } else {
    await api.post('/admin/music/releases', form.value)
  }
  showForm.value = false
  await load()
}

async function remove(id: number) {
  if (!confirm('Delete?')) return
  await api.delete(`/admin/music/releases/${id}`)
  await load()
}

onMounted(load)
</script>

<template>
  <div>
    <div class="flex items-center justify-between mb-6">
      <h1 class="text-xl font-bold">Releases</h1>
      <button @click="openNew" class="btn">Add Release</button>
    </div>

    <div v-if="showForm" class="bg-[#12121f] border border-gray-800/40 rounded-2xl p-5 mb-6 space-y-3">
      <input v-model="form.title" placeholder="Title" class="input" />
      <input v-model="form.artist" placeholder="Artist" class="input" />
      <input v-model="form.cover_url" placeholder="Cover URL" class="input" />
      <input v-model="form.release_url" placeholder="Release URL" class="input" />
      <input v-model="form.embed_url" placeholder="SoundCloud Embed URL" class="input" />
      <input v-model.number="form.sort_order" type="number" placeholder="Sort Order" class="input w-32" />
      <div class="flex gap-2">
        <button @click="save" class="btn">Save</button>
        <button @click="showForm = false" class="btn-secondary">Cancel</button>
      </div>
    </div>

    <div class="space-y-2">
      <div v-for="item in items" :key="item.id" class="flex items-center justify-between bg-[#12121f] border border-gray-800/40 rounded-2xl p-4">
        <span>{{ item.title }} <span class="text-gray-500 text-sm">{{ item.artist }}</span></span>
        <div class="flex gap-2">
          <button @click="openEdit(item)" class="btn-sm">Edit</button>
          <button @click="remove(item.id)" class="btn-sm-danger">Delete</button>
        </div>
      </div>
    </div>
  </div>
</template>
