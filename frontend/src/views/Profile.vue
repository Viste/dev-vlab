<script setup lang="ts">
import { ref } from 'vue'
import { useAuthStore } from '../stores/auth'
import api from '../api/client'

const auth = useAuthStore()
const editing = ref(false)
const form = ref({
  first_name: auth.user?.first_name || '',
  last_name: auth.user?.last_name || '',
  email: auth.user?.email || '',
})
const saving = ref(false)

async function save() {
  saving.value = true
  try {
    await api.put('/user/profile', form.value)
    await auth.fetchUser()
    editing.value = false
  } finally {
    saving.value = false
  }
}
</script>

<template>
  <div class="max-w-lg mx-auto px-4 py-12">
    <h1 class="text-3xl font-bold mb-8">Profile</h1>

    <div v-if="auth.user" class="space-y-6">
      <div class="flex items-center gap-4">
        <img
          v-if="auth.user.profile_picture"
          :src="auth.user.profile_picture"
          class="w-16 h-16 rounded-full object-cover"
        />
        <div class="w-16 h-16 rounded-full bg-gray-800 flex items-center justify-center text-xl font-bold" v-else>
          {{ auth.user.username[0].toUpperCase() }}
        </div>
        <div>
          <div class="font-semibold">{{ auth.user.username }}</div>
          <div class="text-sm text-gray-400">{{ auth.user.provider || 'local' }}</div>
        </div>
      </div>

      <template v-if="!editing">
        <div class="grid gap-3 text-sm">
          <div><span class="text-gray-500">Name:</span> {{ auth.user.first_name }} {{ auth.user.last_name }}</div>
          <div><span class="text-gray-500">Email:</span> {{ auth.user.email || '—' }}</div>
          <div><span class="text-gray-500">Joined:</span> {{ new Date(auth.user.created_at).toLocaleDateString() }}</div>
        </div>
        <button @click="editing = true" class="btn">Edit Profile</button>
      </template>

      <form v-else @submit.prevent="save" class="space-y-4">
        <div>
          <label class="text-sm text-gray-400">First Name</label>
          <input v-model="form.first_name" class="input" />
        </div>
        <div>
          <label class="text-sm text-gray-400">Last Name</label>
          <input v-model="form.last_name" class="input" />
        </div>
        <div>
          <label class="text-sm text-gray-400">Email</label>
          <input v-model="form.email" type="email" class="input" />
        </div>
        <div class="flex gap-3">
          <button type="submit" class="btn" :disabled="saving">Save</button>
          <button type="button" @click="editing = false" class="btn-secondary">Cancel</button>
        </div>
      </form>
    </div>
  </div>
</template>
