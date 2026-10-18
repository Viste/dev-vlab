<script setup lang="ts">
import { onMounted, ref } from 'vue'
import api from '../../api/client'
import { useAuthStore } from '../../stores/auth'
import type { AdminUser } from '../../api/types'

const auth = useAuthStore()

const users = ref<AdminUser[]>([])
const loading = ref(true)
const error = ref('')
const showForm = ref(false)
const saving = ref(false)
const createdNote = ref('')

const emptyForm = () => ({ username: '', password: '', first_name: '', last_name: '', email: '', is_admin: true })
const form = ref(emptyForm())

const resetFor = ref<number | null>(null)
const resetPassword = ref('')

async function load() {
  error.value = ''
  try {
    const { data } = await api.get<AdminUser[]>('/admin/users')
    users.value = data
  } catch (e: any) {
    error.value = e.response?.data?.error || 'Failed to load users'
  } finally {
    loading.value = false
  }
}

function generatePassword() {
  const alphabet = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'
  const bytes = new Uint8Array(14)
  crypto.getRandomValues(bytes)
  form.value.password = Array.from(bytes, (b) => alphabet[b % alphabet.length]).join('')
}

async function create() {
  error.value = ''
  createdNote.value = ''
  saving.value = true
  try {
    const { data } = await api.post<AdminUser>('/admin/users', form.value)
    createdNote.value = `Created "${data.username}" with password: ${form.value.password}`
    form.value = emptyForm()
    showForm.value = false
    await load()
  } catch (e: any) {
    error.value = e.response?.data?.error || 'Failed to create user'
  } finally {
    saving.value = false
  }
}

async function patch(u: AdminUser, body: Record<string, unknown>) {
  error.value = ''
  try {
    const { data } = await api.put<AdminUser>(`/admin/users/${u.id}`, body)
    const idx = users.value.findIndex((x) => x.id === u.id)
    if (idx >= 0) users.value[idx] = data
    if (u.id === auth.user?.id) await auth.fetchUser()
  } catch (e: any) {
    error.value = e.response?.data?.error || 'Failed to update user'
  }
}

async function applyReset(u: AdminUser) {
  if (resetPassword.value.length < 6) {
    error.value = 'Password must be at least 6 characters'
    return
  }
  await patch(u, { password: resetPassword.value })
  if (!error.value) {
    createdNote.value = `Password for "${u.username}" set to: ${resetPassword.value}`
    resetFor.value = null
    resetPassword.value = ''
  }
}

async function remove(u: AdminUser) {
  if (!confirm(`Delete user "${u.username}"?`)) return
  error.value = ''
  try {
    await api.delete(`/admin/users/${u.id}`)
    users.value = users.value.filter((x) => x.id !== u.id)
  } catch (e: any) {
    error.value = e.response?.data?.error || 'Failed to delete user'
  }
}

function formatDate(s: string) {
  return new Date(s).toLocaleDateString('ru-RU')
}

onMounted(load)
</script>

<template>
  <div>
    <div class="flex items-center justify-between mb-6 gap-4 flex-wrap">
      <div>
        <h1 class="text-xl font-bold">Users</h1>
        <p class="text-gray-500 text-sm mt-0.5">Local accounts and social logins. Admins can access this panel.</p>
      </div>
      <button @click="showForm = !showForm" class="btn">{{ showForm ? 'Close' : 'New user' }}</button>
    </div>

    <form v-if="showForm" @submit.prevent="create" class="bg-[#12121f] border border-gray-800/40 rounded-2xl p-5 mb-6 space-y-3">
      <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
        <div>
          <label class="label">Username</label>
          <input v-model="form.username" class="input" required autocomplete="off" placeholder="latin letters, digits, . _ -" />
        </div>
        <div>
          <label class="label">Password</label>
          <div class="flex gap-2">
            <input v-model="form.password" class="input font-mono" required minlength="6" autocomplete="new-password" />
            <button type="button" @click="generatePassword" class="btn-secondary shrink-0">Generate</button>
          </div>
        </div>
        <div>
          <label class="label">First name</label>
          <input v-model="form.first_name" class="input" />
        </div>
        <div>
          <label class="label">Last name</label>
          <input v-model="form.last_name" class="input" />
        </div>
        <div>
          <label class="label">Email</label>
          <input v-model="form.email" type="email" class="input" />
        </div>
        <label class="flex items-center gap-2 text-sm text-gray-300 self-end pb-2.5 cursor-pointer select-none">
          <input v-model="form.is_admin" type="checkbox" class="accent-red-600" />
          Admin (can open this panel)
        </label>
      </div>
      <div class="flex gap-2 pt-1">
        <button type="submit" class="btn" :disabled="saving">{{ saving ? 'Creating...' : 'Create user' }}</button>
        <button type="button" @click="showForm = false" class="btn-secondary">Cancel</button>
      </div>
    </form>

    <p v-if="createdNote" class="text-sm text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 rounded-xl px-4 py-3 mb-4 font-mono break-all">{{ createdNote }}</p>
    <p v-if="error" class="text-sm text-red-500 mb-4">{{ error }}</p>

    <div v-if="loading" class="text-sm text-gray-500 py-10 text-center">Loading...</div>
    <div v-else class="space-y-2">
      <div v-for="u in users" :key="u.id" class="bg-[#12121f] border border-gray-800/40 rounded-2xl p-4">
        <div class="flex items-center gap-4">
          <img v-if="u.profile_picture" :src="u.profile_picture" class="w-10 h-10 rounded-xl object-cover shrink-0" />
          <div v-else class="w-10 h-10 rounded-xl bg-gray-800 flex items-center justify-center text-sm font-bold text-red-400 shrink-0">
            {{ u.username[0]?.toUpperCase() }}
          </div>
          <div class="min-w-0 flex-1">
            <div class="flex items-center gap-2 flex-wrap">
              <span class="font-medium">{{ u.username }}</span>
              <span v-if="u.id === auth.user?.id" class="text-[10px] text-gray-600">you</span>
              <span class="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-white/5 text-gray-500">{{ u.provider || 'local' }}</span>
              <span v-if="u.is_admin" class="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-red-500/10 text-red-400">admin</span>
              <span v-if="u.is_banned" class="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-yellow-500/10 text-yellow-400">banned</span>
            </div>
            <div class="text-xs text-gray-500 mt-0.5 truncate">
              {{ [u.first_name, u.last_name].filter(Boolean).join(' ') || '—' }}
              <span v-if="u.email"> · {{ u.email }}</span>
              · joined {{ formatDate(u.created_at) }}
            </div>
          </div>
          <div class="flex gap-2 shrink-0 flex-wrap justify-end">
            <button @click="patch(u, { is_admin: !u.is_admin })" class="btn-sm" :disabled="u.id === auth.user?.id">{{ u.is_admin ? 'Revoke admin' : 'Make admin' }}</button>
            <button @click="resetFor = resetFor === u.id ? null : u.id; resetPassword = ''" class="btn-sm">Password</button>
            <button @click="patch(u, { is_banned: !u.is_banned })" class="btn-sm" :disabled="u.id === auth.user?.id">{{ u.is_banned ? 'Unban' : 'Ban' }}</button>
            <button @click="remove(u)" class="btn-sm-danger" :disabled="u.id === auth.user?.id">Delete</button>
          </div>
        </div>
        <form v-if="resetFor === u.id" @submit.prevent="applyReset(u)" class="flex items-center gap-2 mt-3 pt-3 border-t border-gray-800/40">
          <input v-model="resetPassword" class="input font-mono flex-1" placeholder="New password (min 6 chars)" autocomplete="new-password" />
          <button type="submit" class="btn shrink-0">Set password</button>
          <button type="button" @click="resetFor = null" class="btn-secondary shrink-0">Cancel</button>
        </form>
      </div>
    </div>
  </div>
</template>
