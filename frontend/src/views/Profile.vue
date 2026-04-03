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
const newPassword = ref('')
const passwordMsg = ref('')
const changingPassword = ref(false)

async function changePassword() {
  if (!newPassword.value || newPassword.value.length < 6) {
    passwordMsg.value = 'Min 6 characters'
    return
  }
  changingPassword.value = true
  try {
    await api.put('/user/password', { new_password: newPassword.value })
    passwordMsg.value = 'Password updated!'
    newPassword.value = ''
  } catch {
    passwordMsg.value = 'Failed to update'
  } finally {
    changingPassword.value = false
  }
}

async function uploadAvatar(e: Event) {
  const file = (e.target as HTMLInputElement).files?.[0]
  if (!file) return
  const fd = new FormData()
  fd.append('avatar', file)
  try {
    await api.post('/user/avatar', fd)
    await auth.fetchUser()
  } catch { /* ignore */ }
}

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
      <p class="text-sm text-red-700 font-mono mb-2">profile</p>
      <div v-if="auth.user" class="flex items-center gap-4">
        <div class="relative group cursor-pointer" @click="($refs.avatarInput as HTMLInputElement).click()">
          <img v-if="auth.user.profile_picture" :src="auth.user.profile_picture"
            class="w-16 h-16 rounded-2xl object-cover" />
          <div v-else class="w-16 h-16 rounded-2xl bg-gray-800 flex items-center justify-center text-xl font-bold text-red-700">
            {{ auth.user.username[0].toUpperCase() }}
          </div>
          <div class="absolute inset-0 rounded-2xl bg-black/50 opacity-0 group-hover:opacity-100 transition flex items-center justify-center">
            <span class="text-xs text-white">Change</span>
          </div>
          <input ref="avatarInput" type="file" accept="image/*" class="hidden" @change="uploadAvatar" />
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
        <div class="flex gap-3 mt-6">
          <button @click="editing = true" class="btn">Edit Profile</button>
        </div>
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

    <div class="bento-card p-6 mt-4">
      <h2 class="text-sm font-semibold mb-3">Change Password</h2>
      <div class="flex gap-3 items-end">
        <input v-model="newPassword" type="password" placeholder="New password" class="input flex-1" />
        <button @click="changePassword" class="btn shrink-0" :disabled="changingPassword">Update</button>
      </div>
      <p v-if="passwordMsg" class="text-sm mt-2" :class="passwordMsg.includes('updated') ? 'text-green-400' : 'text-red-600'">{{ passwordMsg }}</p>
    </div>
  </div>
</template>
