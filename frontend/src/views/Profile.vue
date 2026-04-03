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
  <div class="max-w-2xl mx-auto px-4 py-10">
    <div class="bento-card p-8 mb-4">
      <p class="text-sm text-purple-400 font-mono mb-2">profile</p>
      <div v-if="auth.user" class="flex items-center gap-4">
        <img v-if="auth.user.profile_picture" :src="auth.user.profile_picture"
          class="w-16 h-16 rounded-2xl object-cover" />
        <div v-else class="w-16 h-16 rounded-2xl bg-gray-800 flex items-center justify-center text-xl font-bold text-purple-400">
          {{ auth.user.username[0].toUpperCase() }}
        </div>
        <div>
          <h1 class="text-2xl font-bold">{{ auth.user.username }}</h1>
          <span class="text-xs text-gray-500 bg-gray-800/80 px-2 py-0.5 rounded-full">{{ auth.user.provider || 'local' }}</span>
        </div>
      </div>
    </div>

    <div v-if="auth.user" class="bento-card p-6">
      <template v-if="!editing">
        <div class="grid gap-4 text-sm">
          <div class="flex justify-between py-2 border-b border-gray-800/50">
            <span class="text-gray-500">Name</span>
            <span>{{ auth.user.first_name }} {{ auth.user.last_name }}</span>
          </div>
          <div class="flex justify-between py-2 border-b border-gray-800/50">
            <span class="text-gray-500">Email</span>
            <span>{{ auth.user.email || '---' }}</span>
          </div>
          <div class="flex justify-between py-2">
            <span class="text-gray-500">Joined</span>
            <span>{{ new Date(auth.user.created_at).toLocaleDateString() }}</span>
          </div>
        </div>
        <button @click="editing = true" class="btn mt-6">Edit Profile</button>
      </template>

      <form v-else @submit.prevent="save" class="space-y-4">
        <div>
          <label class="label">First Name</label>
          <input v-model="form.first_name" class="input" />
        </div>
        <div>
          <label class="label">Last Name</label>
          <input v-model="form.last_name" class="input" />
        </div>
        <div>
          <label class="label">Email</label>
          <input v-model="form.email" type="email" class="input" />
        </div>
        <div class="flex gap-3">
          <button type="submit" class="btn" :disabled="saving">{{ saving ? 'Saving...' : 'Save' }}</button>
          <button type="button" @click="editing = false" class="btn-secondary">Cancel</button>
        </div>
      </form>
    </div>
  </div>
</template>
