<script setup lang="ts">
import { ref, onMounted } from 'vue'
import api from '../../api/client'
import type { Project } from '../../api/types'

const items = ref<Project[]>([])
const showForm = ref(false)
const editingId = ref<number | null>(null)
const form = ref({ title: '', description: '', image_url: '', project_url: '', sort_order: 0 })

async function load() {
  const { data } = await api.get<Project[]>('/projects')
  items.value = data
}

function openNew() {
  editingId.value = null
  form.value = { title: '', description: '', image_url: '', project_url: '', sort_order: 0 }
  showForm.value = true
}

function openEdit(item: Project) {
  editingId.value = item.id
  form.value = { title: item.title, description: item.description || '', image_url: item.image_url || '', project_url: item.project_url || '', sort_order: item.sort_order }
  showForm.value = true
}

async function save() {
  if (editingId.value) {
    await api.put(`/admin/projects/${editingId.value}`, form.value)
  } else {
    await api.post('/admin/projects', form.value)
  }
  showForm.value = false
  await load()
}

async function remove(id: number) {
  if (!confirm('Delete?')) return
  await api.delete(`/admin/projects/${id}`)
  await load()
}

onMounted(load)
</script>

<template>
  <div>
    <div class="flex items-center justify-between mb-6">
      <h1 class="text-xl font-bold">Projects</h1>
      <button @click="openNew" class="btn">Add Project</button>
    </div>

    <div v-if="showForm" class="bg-[#12121f] border border-gray-800/40 rounded-2xl p-5 mb-6 space-y-3">
      <input v-model="form.title" placeholder="Title" class="input" />
      <input v-model="form.description" placeholder="Description" class="input" />
      <input v-model="form.image_url" placeholder="Image URL" class="input" />
      <input v-model="form.project_url" placeholder="Project URL" class="input" />
      <input v-model.number="form.sort_order" type="number" placeholder="Sort Order" class="input w-32" />
      <div class="flex gap-2">
        <button @click="save" class="btn">Save</button>
        <button @click="showForm = false" class="btn-secondary">Cancel</button>
      </div>
    </div>

    <div class="space-y-2">
      <div v-for="item in items" :key="item.id" class="flex items-center justify-between bg-[#12121f] border border-gray-800/40 rounded-2xl p-4">
        <span>{{ item.title }}</span>
        <div class="flex gap-2">
          <button @click="openEdit(item)" class="btn-sm">Edit</button>
          <button @click="remove(item.id)" class="btn-sm-danger">Delete</button>
        </div>
      </div>
    </div>
  </div>
</template>
