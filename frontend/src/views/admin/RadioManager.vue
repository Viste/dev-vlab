<script setup lang="ts">
import { ref, onMounted } from 'vue'
import api from '../../api/client'
import type { RadioStream } from '../../api/types'

const radio = ref<RadioStream | null>(null)
const form = ref({ title: '', stream_url: '', is_active: true })
const editing = ref(false)

async function load() {
  try {
    const { data } = await api.get<RadioStream>('/music/radio')
    radio.value = data
  } catch {
    radio.value = null
  }
}

function startEdit() {
  if (radio.value) {
    form.value = { title: radio.value.title, stream_url: radio.value.stream_url, is_active: radio.value.is_active }
  }
  editing.value = true
}

async function save() {
  if (radio.value) {
    await api.put(`/admin/music/radio/${radio.value.id}`, form.value)
  } else {
    await api.post('/admin/music/radio', form.value)
  }
  editing.value = false
  await load()
}

onMounted(load)
</script>

<template>
  <div>
    <h1 class="text-2xl font-bold mb-6">Radio Stream</h1>

    <div v-if="!editing">
      <div v-if="radio" class="border border-gray-800 rounded-lg p-4 space-y-2">
        <p><span class="text-gray-500">Title:</span> {{ radio.title }}</p>
        <p><span class="text-gray-500">URL:</span> {{ radio.stream_url }}</p>
        <p><span class="text-gray-500">Active:</span> {{ radio.is_active ? 'Yes' : 'No' }}</p>
        <button @click="startEdit" class="btn mt-3">Edit</button>
      </div>
      <div v-else>
        <p class="text-gray-500 mb-4">No radio stream configured.</p>
        <button @click="editing = true" class="btn">Create Radio Stream</button>
      </div>
    </div>

    <form v-else @submit.prevent="save" class="space-y-4 max-w-lg">
      <div>
        <label class="label">Title</label>
        <input v-model="form.title" class="input" required />
      </div>
      <div>
        <label class="label">Stream URL</label>
        <input v-model="form.stream_url" class="input" required />
      </div>
      <div class="flex items-center gap-2">
        <input type="checkbox" v-model="form.is_active" id="active" />
        <label for="active" class="text-sm">Active</label>
      </div>
      <div class="flex gap-3">
        <button type="submit" class="btn">Save</button>
        <button type="button" @click="editing = false" class="btn-secondary">Cancel</button>
      </div>
    </form>
  </div>
</template>
