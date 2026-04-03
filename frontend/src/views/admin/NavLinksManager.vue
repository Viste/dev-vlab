<script setup lang="ts">
import { ref, onMounted } from 'vue'
import api from '../../api/client'
import type { NavigationLink } from '../../api/types'

const items = ref<NavigationLink[]>([])
const showForm = ref(false)
const editingId = ref<number | null>(null)
const form = ref({ title: '', url: '', icon: '', sort_order: 0, is_active: true })

async function load() {
  const { data } = await api.get<NavigationLink[]>('/admin/nav-links')
  items.value = data
}

function openNew() {
  editingId.value = null
  form.value = { title: '', url: '', icon: '', sort_order: 0, is_active: true }
  showForm.value = true
}

function openEdit(item: NavigationLink) {
  editingId.value = item.id
  form.value = { title: item.title, url: item.url, icon: item.icon || '', sort_order: item.sort_order, is_active: item.is_active }
  showForm.value = true
}

async function save() {
  if (editingId.value) {
    await api.put(`/admin/nav-links/${editingId.value}`, form.value)
  } else {
    await api.post('/admin/nav-links', form.value)
  }
  showForm.value = false
  await load()
}

async function remove(id: number) {
  if (!confirm('Delete?')) return
  await api.delete(`/admin/nav-links/${id}`)
  await load()
}

onMounted(load)
</script>

<template>
  <div>
    <div class="flex items-center justify-between mb-6">
      <h1 class="text-2xl font-bold">Navigation Links</h1>
      <button @click="openNew" class="btn">Add Link</button>
    </div>

    <div v-if="showForm" class="border border-gray-800 rounded-lg p-4 mb-6 space-y-3">
      <input v-model="form.title" placeholder="Title" class="input" />
      <input v-model="form.url" placeholder="URL" class="input" />
      <input v-model="form.icon" placeholder="Icon (optional)" class="input" />
      <input v-model.number="form.sort_order" type="number" placeholder="Sort Order" class="input w-32" />
      <div class="flex items-center gap-2">
        <input type="checkbox" v-model="form.is_active" id="link-active" />
        <label for="link-active" class="text-sm">Active</label>
      </div>
      <div class="flex gap-2">
        <button @click="save" class="btn">Save</button>
        <button @click="showForm = false" class="btn-secondary">Cancel</button>
      </div>
    </div>

    <div class="space-y-2">
      <div v-for="item in items" :key="item.id" class="flex items-center justify-between border border-gray-800 rounded p-3">
        <div>
          <span>{{ item.title }}</span>
          <span class="text-gray-500 text-sm ml-2">{{ item.url }}</span>
          <span v-if="!item.is_active" class="ml-2 text-xs text-yellow-500">inactive</span>
        </div>
        <div class="flex gap-2">
          <button @click="openEdit(item)" class="btn-sm">Edit</button>
          <button @click="remove(item.id)" class="btn-sm-danger">Delete</button>
        </div>
      </div>
    </div>
  </div>
</template>
